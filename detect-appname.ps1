<#
.SYNOPSIS
    Detection script for verifying the installation, version, and scope (machine or user) of desktop applications.

.DESCRIPTION
    This script is designed to detect the presence of a specified desktop application on a system. It checks for the application
    in predefined machine-level paths, per-user paths, and the Windows registry. The script also validates the installed version
    against an expected version and provides detailed logging for diagnostics.

    The script is intended for use in Intune, where it can be used as a detection script to 
    trigger a remediation script. By modifying the parameters, this script can be reused for detecting
    various desktop applications.

.PARAMETERS
    -AppDisplayName
        The display name of the application.
    
    -ExpectedVersion
        The version of the application that is expected to be installed.

    -MachinePaths
        An array of paths to check for the application at the machine level.
        Default:  "${env:ProgramW6432}\$AppDisplayName\$AppDisplayName.exe",
                  "${env:ProgramFiles(x86)}\$AppDisplayName\$AppDisplayName.exe"

    -PerUserRelativePath
        An array of relative paths to check for the application in user profiles.
        Default:  "AppData\Local\Programs\$AppDisplayName\$AppDisplayName.exe"

    -RegistrySearchByDisplayName
        Boolean flag to enable or disable registry-based detection using the DisplayName.
        Default: $true

    -RegistryDisplayNameMatch
        The pattern to match against the DisplayName in the registry.
        Default: $AppDisplayName

    -RegistryAliases
        An array of custom aliases for the application to account for branding variations.
        Default: ""

    -RegistryRoots
        An array of registry roots to scan for uninstall entries.
        Default: Uses internal defaults if not specified.

    -LogFile
        The path to the log file. If not specified, a default log file is created in "C:\Logs".
        Default:  "C:\Logs\Detect-$AppDisplayName.log"

    -CsvOutputFile
        The path to the CSV file for summary output. If not specified, no CSV is generated.
        Default: ""

    -VerboseMode
        Boolean flag to enable verbose logging for Intune-friendly environments.
        Default: $false

.NOTES
    - This script supports log rotation to prevent excessive log file growth.
    - It can optionally log to the Windows Event Log if configured.
    - The script is designed to handle retries for operations such as file detection and logging.
    - By modifying the parameters, this script can be adapted for detecting other desktop applications.
#>

[CmdletBinding(SupportsShouldProcess=$false)]
param (
    # --- App-specific parameters (set these per application) ---
    [string]$AppDisplayName                 = "",
    [string]$ExpectedVersion                = "",

    # --- Install paths (optional) ---
    [string[]]$MachinePaths                 = @(
        ""
    ),
    [string[]]$PerUserRelativePath          = @(
        ""
    ),
    
    # --- Registry search by DisplayName (optional) ---
    [bool]$RegistrySearchByDisplayName      = $true,                                         # Scan Uninstall keys for DisplayName matches
    [string]$RegistryDisplayNameMatch       = $AppDisplayName,                               # DisplayName pattern to match (wildcards supported)
    [string[]]$RegistryAliases              = @(                                             # Custom alias list for branding variations
        ""
    ),
    [string[]]$RegistryRoots                = @(                                             # Fallback to $DefaultRegistryRoots inside function
        ""
    ),
    [bool]$RegistryStrictAnchor             = $false,                                        # ONLY match entries anchored to exe dir
    [bool]$RegistryRegex                    = $false,                                        # Use regex matching for aliases

    # --- Common controls ---
    [string]$LogFile                        = "",                                            # If empty, derive "C:\Logs\Detect-$AppDisplayName.log"
    [int]$MaxRetries                        = 1,                                             # Retry attempts
    [int]$RetryDelay                        = 5,                                             # Seconds between retries
    [bool]$TriggerRemediationForMissingApp  = $false,                                        # Trigger remediation when nothing is found
    [int]$MaxLogRetries                     = 5,                                             # Log write retries
    [int]$LogRetryDelay                     = 2,                                             # Seconds between log write retries
    [int]$LogMaxSizeMB                      = 5,                                             # Rotate log when file exceeds this cap
    [int]$LogMaxFiles                       = 5,                                             # Number of rotated files to keep

    # --- Optional: additionally log to Windows Event Log ---
    [bool]$WriteEventLog                    = $false,
    [string]$EventLogSource                 = "Intune-DetectScript",

    # --- Optional: CSV summary output ---
    [string]$CsvOutputFile                  = "",                                            # Path to CSV; if empty, skip

    # --- Intune friendly verbose flag ---
    [bool]$VerboseMode                      = $false                                         # Intune-friendly boolean
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# If caller didn't supply MachinePaths, PerUserRelativePath, derive them from AppDisplayName
if (-not $PSBoundParameters.ContainsKey('MachinePaths') -or -not $MachinePaths -or $MachinePaths.Count -eq 0) {
    $MachinePaths = @(
        "${env:ProgramW6432}\$AppDisplayName\$AppDisplayName.exe",
        "${env:ProgramFiles(x86)}\$AppDisplayName\$AppDisplayName.exe"
    )
}
if (-not $PSBoundParameters.ContainsKey('PerUserRelativePath') -or -not $PerUserRelativePath -or $PerUserRelativePath.Count -eq 0) {
    $PerUserRelativePath = @(
        "AppData\Local\Programs\$AppDisplayName\$AppDisplayName.exe"
    )
}

# --- Defaults: single source of truth for uninstall roots ---
$DefaultRegistryRoots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKU:\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Components\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders',
    'HKLM:\SOFTWARE\Classes\Installer\Products\*',
    'HKLM:\SOFTWARE\Classes\Installer\Features\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Products\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders',
    'HKCU:\SOFTWARE\Classes\Installer\Products\*',
    'HKCU:\SOFTWARE\Classes\Installer\Features\*'
)

# ---------- Helpers to build a safe, per-app log file ----------
function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean   = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    # Trim trailing dots/spaces that Windows disallows
    $clean   = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# If caller didn't supply -LogFile, derive a robust default from AppDisplayName
if (-not $PSBoundParameters.ContainsKey('LogFile') -or [string]::IsNullOrWhiteSpace($LogFile)) {
    $safeName = Get-SafeFileName -Name $AppDisplayName
    $LogFile  = "C:\Logs\Detect-$safeName.log"
}

# ---------- Diagnostics ----------
$CorrelationId = [guid]::NewGuid().ToString()
$RunContext = @{
    UserName      = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    IsElevated    = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ProcessId     = $PID
    PowerShellVer = $PSVersionTable.PSVersion.ToString()
}

# ---------- Log rotation ----------
function Rotate-Log {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $fi = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $fi) { return }
        $sizeMB = [math]::Round($fi.Length / 1MB, 2)
        if ($sizeMB -lt $LogMaxSizeMB) { return }

        # Ensure directory exists
        $dir = Split-Path -Path $Path
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }

        # Shift older rotations up
        for ($i = ($LogMaxFiles - 1); $i -ge 1; $i--) {
            $src = "$Path.$i"
            $dst = "$Path." + ($i + 1)
            if (Test-Path -LiteralPath $src) {
                Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue
            }
        }

        # Move current to .1
        Move-Item -LiteralPath $Path -Destination "$Path.1" -Force -ErrorAction SilentlyContinue

        # Create fresh log file
        New-Item -Path $Path -ItemType File -Force | Out-Null
    } catch {
        Write-Verbose "Rotate-Log failed for '$Path': $_"
    }
}

# ---------- Logging ----------
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )

    $prefix = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')) [$Level] [$CorrelationId]"
    $line = "$prefix - $Message"

    # Console output: DO NOT WRITE TO PIPELINE
    switch ($Level) {
        'DEBUG' { Write-Verbose $line }                 # only shows with -Verbose
        'ERROR' { Write-Error   $line }                 # error stream (not pipeline output)
        'WARN'  { Write-Host    $line -ForegroundColor Yellow }
        default { Write-Host    $line }                 # INFO
    }

    # File logging with rotation and retries
    if ($LogFile) {
        $logDirectory = Split-Path -Path $LogFile
        if (-not (Test-Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }

        Rotate-Log -Path $LogFile

        for ($i = 1; $i -le $MaxLogRetries; $i++) {
            try {
                Add-Content -Path $LogFile -Value $line
                break
            } catch [System.IO.IOException] {
                if ($i -eq $MaxLogRetries) {
                    Write-Verbose "Failed to write to log file after $MaxLogRetries attempts $LogFile"
                    throw
                }
                Start-Sleep -Seconds $LogRetryDelay
            }
        }
    }

    # Optional: Event Log
    if ($WriteEventLog) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                [System.Diagnostics.EventLog]::CreateEventSource($EventLogSource, "Application")
            }
            $entryType = switch ($Level) {
                'ERROR' { [System.Diagnostics.EventLogEntryType]::Error }
                'WARN'  { [System.Diagnostics.EventLogEntryType]::Warning }
                default { [System.Diagnostics.EventLogEntryType]::Information }
            }
            [System.Diagnostics.EventLog]::WriteEntry($EventLogSource, $Message, $entryType)
        } catch {
            Write-Verbose "EventLog write failed: $_"
        }
    }
}

function Write-SectionStart {
    param([string]$Name)
    Write-Log "=== Begin: $Name ===" 'DEBUG'
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Write-SectionEnd {
    param(
        [string]$Name,
        [System.Diagnostics.Stopwatch]$Sw
    )
    if ($Sw) { $Sw.Stop() }
    $ms = if ($Sw) { $Sw.ElapsedMilliseconds } else { 0 }
    Write-Log "=== End: $Name (elapsed ${ms}ms) ===" 'DEBUG'
}

# ---------- Utilities ----------
function New-DirectoryIfMissing { param([string]$DirectoryPath)
    if (-not (Test-Path $DirectoryPath)) {
        New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
    }
}

function Invoke-OperationRetry {
    param ([int]$MaxRetries,[int]$RetryDelay,[scriptblock]$Operation)
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-Log "Attempt $i of $MaxRetries" 'INFO'
            & $Operation
            return $true
        } catch {
            Write-Log "Attempt $i failed $_" 'WARN'
            if ($i -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelay } else { return $false }
        }
    }
}

function Format-Version {
    param([string]$v)
    $v = ($v -replace ',', '.').Trim()
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    param([string]$InstalledVersion,[string]$ExpectedVersion)
    try { (Format-Version $InstalledVersion) -ge (Format-Version $ExpectedVersion) }
    catch { throw "Version comparison failed $_" }
}

function Get-FileVersionInfoSafe {
    param([string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    ($version -replace ',', '.').Trim()
}

function Get-PerUserAppPaths {
    param(
        [string]$RelativePath,
        [string[]]$Exclusions = @('Public','Default','Default User','All Users','WDAGUtilityAccount')
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { return @() }

    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    # If caller passed an absolute (rooted) path, don't join to each profile.
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        if (Test-Path -LiteralPath $RelativePath) { return @($RelativePath) } else { return @() }
    }

    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $Exclusions -notcontains $_.Name } |
        ForEach-Object { Join-Path $_.FullName $RelativePath } |
        Where-Object { Test-Path -LiteralPath $_ }
}

function Normalize-VersionString {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    if ($s -match '(\d+(?:\.\d+){0,})') { return $matches[1] }
    return $null
}

function Normalize-String {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    ($s.ToLowerInvariant() -replace '\s+', ' ').Trim()
}

function Escape-Regex {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    [Regex]::Escape($s)
}

function Test-AliasMatch {
    param(
        [string]$Haystack,
        [string]$Alias,
        [bool]$UseRegex
    )
    if ([string]::IsNullOrWhiteSpace($Haystack) -or [string]::IsNullOrWhiteSpace($Alias)) { return $false }
    if ($UseRegex) {
        $pattern = Escape-Regex -s $Alias
        return ($Haystack -match "(?i).*$pattern.*")   # case-insensitive contains
    } else {
        return ($Haystack -like "*$Alias*")
    }
}

# ----- Search Uninstall registry by DisplayName + exe path anchoring + custom aliases -----
function Search-RegistryForApp {
    param(
        [string[]]$Aliases,
        [string]$DisplayNamePattern = "",
        [string]$ExecutablePathHint = $null,
        [string[]]$Roots = @(),
        [bool]$StrictAnchor = $false,
        [bool]$UseRegex = $false
    )
    $scanRoots = if ($Roots -and $Roots.Count -gt 0) { $Roots } else { $DefaultRegistryRoots }
    Write-Log ("Registry search roots: '{0}'" -f ($scanRoots -join '; ')) 'DEBUG'

    # Normalize the provided display name pattern
    $patternNorm = Normalize-String $DisplayNamePattern

    # Normalize caller-supplied aliases (if any)
    $callerAliasesNorm = @()
    foreach ($a in $Aliases) {
        if (-not [string]::IsNullOrWhiteSpace($a)) { $callerAliasesNorm += (Normalize-String $a) }
    }

    # Build the final alias list:
    # - If caller provided aliases, use those (unique)
    # - Otherwise, fall back to the normalized DisplayNamePattern (the app name)
    if ($callerAliasesNorm.Count -gt 0) {
        $allAliases = $callerAliasesNorm | Select-Object -Unique
    } elseif (-not [string]::IsNullOrWhiteSpace($patternNorm)) {
        $allAliases = @($patternNorm)
    } else {
        $allAliases = @()
    }

    $results = @()
    foreach ($root in $scanRoots) {
        try {
            $items = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }
            foreach ($item in $items) {
                try {
                    $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
                    if ($null -eq $props) { continue }
                    $displayName     = if ($props.PSObject.Properties.Match('DisplayName').Count)     { $props.DisplayName }     else { "" }
                    $displayVersion  = if ($props.PSObject.Properties.Match('DisplayVersion').Count)  { $props.DisplayVersion }  else { "" }
                    $uninstallString = if ($props.PSObject.Properties.Match('UninstallString').Count) { $props.UninstallString } else { "" }
                    $displayIcon     = if ($props.PSObject.Properties.Match('DisplayIcon').Count)     { $props.DisplayIcon }     else { "" }
                    $installLocation = if ($props.PSObject.Properties.Match('InstallLocation').Count) { $props.InstallLocation } else { "" }
                    $publisher       = if ($props.PSObject.Properties.Match('Publisher').Count)       { $props.Publisher }       else { "" }
                    $versionRaw      = if ($props.PSObject.Properties.Match('Version').Count)         { $props.Version }         else { "" }
                    $dnNorm   = Normalize-String $displayName
                    $pubNorm  = Normalize-String $publisher
                    $usNorm   = Normalize-String $uninstallString
                    $diNorm   = Normalize-String $displayIcon
                    $ilNorm   = Normalize-String $installLocation
                    $keyName  = $item.PSChildName.ToLowerInvariant()
                    $matchReason = $null

                    # Strict anchor mode
                    if ($StrictAnchor -and $ExecutablePathHint) {
                        $exeDir = Normalize-String (Split-Path -Path $ExecutablePathHint -Parent)
                        if ($usNorm -like "*$exeDir*" -or $ilNorm -like "*$exeDir*") {
                            $matchReason = 'InstallLocation/UninstallString matches exe dir'
                        } elseif ($diNorm -like "*$exeDir*") {
                            $matchReason = 'DisplayIcon matches exe dir'
                        }
                    } else {
                        foreach ($alias in $allAliases) {
                            if ([string]::IsNullOrWhiteSpace($alias)) { continue }
                            if (Test-AliasMatch -Haystack $dnNorm -Alias $alias -UseRegex:$UseRegex) { $matchReason = 'DisplayName'; break }
                            if (Test-AliasMatch -Haystack $usNorm -Alias $alias -UseRegex:$UseRegex) { $matchReason = 'UninstallString'; break }
                            if (Test-AliasMatch -Haystack $diNorm -Alias $alias -UseRegex:$UseRegex) { $matchReason = 'DisplayIcon'; break }
                            if (Test-AliasMatch -Haystack $ilNorm -Alias $alias -UseRegex:$UseRegex) { $matchReason = 'InstallLocation'; break }
                            if (Test-AliasMatch -Haystack $pubNorm -Alias $alias -UseRegex:$UseRegex){ $matchReason = 'Publisher'; break }
                            if (Test-AliasMatch -Haystack $keyName -Alias $alias -UseRegex:$UseRegex){ $matchReason = 'RegistryKeyName'; break }
                        }
                        # Fallback: anchor to exe directory
                        if (-not $matchReason -and $ExecutablePathHint) {
                            $exeDir2 = Normalize-String (Split-Path -Path $ExecutablePathHint -Parent)
                            if ($usNorm -like "*$exeDir2*" -or $ilNorm -like "*$exeDir2*") {
                                $matchReason = 'InstallLocation/UninstallString matches exe dir'
                            } elseif ($diNorm -like "*$exeDir2*") {
                                $matchReason = 'DisplayIcon matches exe dir'
                            }
                        }
                    }

                    if ($matchReason) {
                        $ver = $null
                        if ($displayVersion) { $ver = Normalize-VersionString -s ($displayVersion -replace ',', '.') }
                        if (-not $ver -and $versionRaw) { $ver = Normalize-VersionString -s ($versionRaw -replace ',', '.') }
                        if (-not $ver -and $props.PSObject.Properties.Match('VersionMajor').Count -gt 0) {
                            $maj = $props.VersionMajor; $min = $props.VersionMinor
                            if ($maj -ne $null -and $min -ne $null) { $ver = "$maj.$min" }
                        }
                        $results += [pscustomobject]@{
                            KeyPath         = $item.PSPath
                            DisplayName     = $displayName
                            Version         = $ver
                            UninstallString = $uninstallString
                            MatchReason     = $matchReason
                        }
                    }
                    # Recurse into subkeys for broad search
                    $subkeys = Get-ChildItem -Path $item.PSPath -ErrorAction SilentlyContinue
                    if ($subkeys) {
                        $results += Search-RegistryForApp -Aliases $Aliases -DisplayNamePattern $DisplayNamePattern -ExecutablePathHint $ExecutablePathHint -Roots @($item.PSPath) -StrictAnchor:$StrictAnchor -UseRegex:$UseRegex
                    }
                } catch {
                    # Ignore errors for inaccessible keys
                }
            }
        } catch {
            # Ignore errors for inaccessible roots
        }
    }
    return $results
}

# ---------- CSV summary ----------
function Write-CsvSummary {
    param(
        [string]$Path,
        [string]$CorrelationId,
        [hashtable]$RunContext,
        [hashtable]$IntuneOutput,
        [int]$TotalDetections,
        [int]$ExpectedCount,
        [int]$ArpMatchCount
    )
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        $dir = Split-Path -Path $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-DirectoryIfMissing -DirectoryPath $dir }

        $row = [pscustomobject]@{
            Timestamp        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            CorrelationId    = $CorrelationId
            User             = $RunContext.UserName
            Elevated         = $RunContext.IsElevated
            PowerShellVer    = $RunContext.PowerShellVer
            AppName          = $IntuneOutput.AppName
            Status           = $IntuneOutput.Status
            ExpectedVersion  = $IntuneOutput.ExpectedVersion
            DetectedVersion  = $IntuneOutput.DetectedVersion
            InstallScope     = $IntuneOutput.InstallScope
            FilePath         = $IntuneOutput.FilePath
            TotalDetections  = $TotalDetections
            ExpectedMatches  = $ExpectedCount
            ArpMatches       = $ArpMatchCount
            ExitCode         = if ($IntuneOutput.Status -eq 'Compliant') { 0 } elseif ($IntuneOutput.Status -eq 'NotInstalled' -and -not $TriggerRemediationForMissingApp) { 0 } else { 1 }
        }

        $row | Export-Csv -Path $Path -NoTypeInformation -Append
    } catch {
        Write-Verbose "Write-CsvSummary failed: $_"
    }
}

# ---------- Output object ----------
$intuneOutput = @{
    AppName         = $AppDisplayName
    FilePath        = ""
    ExpectedVersion = $ExpectedVersion
    DetectedVersion = ""
    InstallScope    = ""
    Status          = "NotDetected"
}

# ---------- Main ----------
try {
    New-DirectoryIfMissing -DirectoryPath (Split-Path -Path $LogFile)

    Write-Log "RunContext: User='$($RunContext.UserName)' Elevated='$($RunContext.IsElevated)' PID='$($RunContext.ProcessId)' PS='$($RunContext.PowerShellVer)' CorrelationId='$CorrelationId'" 'INFO'
    Write-Log ("Parameters: App='{0}' ExpectedVersion='{1}' RegistrySearch='{2}' StrictAnchor={3} Regex={4} LogFile='{5}' LogMaxSizeMB={6} LogMaxFiles={7} MaxRetries={8} RetryDelay={9} TriggerRemediationForMissingApp={10} Csv='{11}' Aliases='{12}' VerboseMode={13}" -f `
        $AppDisplayName, $ExpectedVersion, $RegistrySearchByDisplayName, $RegistryStrictAnchor, $RegistryRegex, $LogFile, $LogMaxSizeMB, $LogMaxFiles, $MaxRetries, $RetryDelay, $TriggerRemediationForMissingApp, $CsvOutputFile, ($RegistryAliases -join '|'), $VerboseMode) 'DEBUG'

    $operationSucceeded = $false
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Log "Attempt $attempt of $MaxRetries" 'INFO'
        try {
            $found = $false
            $detectedItems = @()

            # 1) Machine paths
            $swFiles = Write-SectionStart -Name "File Detection"
            foreach ($path in $MachinePaths) {
                if (Test-Path -LiteralPath $path) {
                    $found = $true
                    $normalizedVersion = Get-FileVersionInfoSafe -Path $path
                    Write-Log "[$AppDisplayName] Detected version '$normalizedVersion' from '$path'" 'INFO'
                    $scope = if ($path -like "$env:LocalAppData*") { "User" } else { "Machine" }
                    $detectedItems += [pscustomobject]@{ FilePath = $path; Version = $normalizedVersion; Scope = $scope }
                    if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                        $intuneOutput.Status = "MalformedVersion"
                        Write-Log "MalformedVersion: File='$path' Version='$normalizedVersion' Expected='$($intuneOutput.ExpectedVersion)'" 'ERROR'
                        Write-SectionEnd -Name "File Detection" -Sw $swFiles
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                } else {
                    Write-Log "[$AppDisplayName] Not found: '$path'" 'DEBUG'
                }
            }

            # 2) Per-user installs across profiles (SYSTEM context)
            foreach ($rel in $PerUserRelativePath) {
                if ([string]::IsNullOrWhiteSpace($rel)) { continue }
                Write-Log "Scanning per-user relative path pattern: '$rel' under C:\Users" 'INFO'
                $perUserHits = Get-PerUserAppPaths -RelativePath $rel
                $countHits = if ($perUserHits) { ($perUserHits | Measure-Object).Count } else { 0 }
                Write-Log "Per-user enumeration found $countHits path(s) for '$rel'" 'INFO'

                foreach ($uPath in $perUserHits) {
                    $found = $true
                    $normalizedVersion = Get-FileVersionInfoSafe -Path $uPath
                    Write-Log "[$AppDisplayName] Detected per-user version '$normalizedVersion' from '$uPath'" 'INFO'
                    $detectedItems += [pscustomobject]@{ FilePath = $uPath; Version = $normalizedVersion; Scope = "User" }
                    if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                        $intuneOutput.Status = "MalformedVersion"
                        Write-Log "MalformedVersion (User): File='$uPath' Version='$normalizedVersion' Expected='$($intuneOutput.ExpectedVersion)'" 'ERROR'
                        Write-SectionEnd -Name "File Detection" -Sw $swFiles
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                }
            }
            Write-SectionEnd -Name "File Detection" -Sw $swFiles

            # Prepare exe hint (prefer machine scope)
            $exeHint = $null
            if ($detectedItems.Count -gt 0) {
                $exeHint = ($detectedItems | Where-Object { $_.Scope -eq 'Machine' } | Select-Object -First 1).FilePath
                if (-not $exeHint) { $exeHint = ($detectedItems | Select-Object -First 1).FilePath }
            }
            Write-Log "ExecutablePathHint='$exeHint'" 'DEBUG'

            # 3) Registry detection (consolidated)
            $registryHits = @()
            if ($RegistrySearchByDisplayName) {
                $swReg = Write-SectionStart -Name "Registry Detection"
                Write-Log "Searching registry entries for aliases and DisplayName matching '$RegistryDisplayNameMatch'" 'INFO'

                $callerAliasesNorm = @()
                foreach ($a in $RegistryAliases) {
                    if (-not [string]::IsNullOrWhiteSpace($a)) { $callerAliasesNorm += (Normalize-String $a) }
                }

                $registryHits = Search-RegistryForApp `
                    -Aliases $callerAliasesNorm `
                    -DisplayNamePattern $RegistryDisplayNameMatch `
                    -ExecutablePathHint $exeHint `
                    -Roots $RegistryRoots `
                    -StrictAnchor $RegistryStrictAnchor `
                    -UseRegex $RegistryRegex

                $countReg = if ($registryHits) { ($registryHits | Measure-Object).Count } else { 0 }
                Write-Log "Total registry matches: $countReg" 'INFO'

                foreach ($h in $registryHits) {
                    $found = $true
                    $ver = $h.Version
                    $scope = if ($h.KeyPath -match 'HKU:\\' -or $h.KeyPath -match 'HKEY_USERS' -or $h.KeyPath -match 'HKCU:\\') { 'User' } else { 'Machine' }
                    $detectedItems += [pscustomobject]@{ FilePath = ("Registry:" + $h.KeyPath); Version = $ver; Scope = $scope }
                    Write-Log "Registry match: Key='$($h.KeyPath)'; Version='$ver'; Reason='$($h.MatchReason)'" 'INFO'
                }
                Write-SectionEnd -Name "Registry Detection" -Sw $swReg
            } else {
                Write-Log "RegistrySearchByDisplayName disabled; skipping registry search." 'WARN'
            }

            # Evaluate aggregated detections
            $totalDetections = $detectedItems.Count
            Write-Log "Aggregated detections: $totalDetections item(s)" 'INFO'

            if ($totalDetections -eq 0) {
                Write-Log "[$AppDisplayName] No executable or registry entry found in machine paths or any user profile." 'WARN'
                throw "FileNotFound"
            }

            # Which entries match expected?
            $expectedMatches = @()
            foreach ($item in $detectedItems) {
                try {
                    if ($item.Version -and (Compare-Versions -InstalledVersion $item.Version -ExpectedVersion $ExpectedVersion)) {
                        $expectedMatches += $item
                    }
                } catch {
                    Write-Log "Version compare error for '$($item.FilePath)': $_" 'WARN'
                }
            }
            $expectedCount = $expectedMatches.Count
            Write-Log "ExpectedVersion='$ExpectedVersion'; Matching entries: $expectedCount of $totalDetections" 'INFO'

            # Aggregate reason totals across all ARP hits
            $reasonTotals = @{}
            foreach ($r in ($arpHits | Select-Object -ExpandProperty MatchReason)) {
                if (-not $reasonTotals.ContainsKey($r)) { $reasonTotals[$r] = 0 }
                $reasonTotals[$r]++
            }
            if ($arpHits.Count -gt 0) {
                $reasonSummaryAll = ($reasonTotals.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                Write-Log "ARP reason totals across all roots: $reasonSummaryAll" 'INFO'
            }

            # Determine final status
            if ($totalDetections -gt 0 -and $expectedCount -eq $totalDetections) {
                $intuneOutput.FilePath        = ($detectedItems | Select-Object -First 1).FilePath
                $intuneOutput.DetectedVersion = ($detectedItems | Select-Object -ExpandProperty Version -Unique) -join ','
                $intuneOutput.InstallScope    = ($detectedItems | Select-Object -ExpandProperty Scope -Unique) -join ','
                $intuneOutput.Status = "Compliant"
                $files = ($detectedItems | ForEach-Object { $_.FilePath }) -join ';'
                Write-Log "Summary: App='$($intuneOutput.AppName)'; Scope=$($intuneOutput.InstallScope); Files='$files'; Detected='$($intuneOutput.DetectedVersion)'; Expected='$($intuneOutput.ExpectedVersion)'; Status=$($intuneOutput.Status); ExitCode=0" 'INFO'
                Write-CsvSummary -Path $CsvOutputFile -CorrelationId $CorrelationId -RunContext $RunContext -IntuneOutput $intuneOutput -TotalDetections $totalDetections -ExpectedCount $expectedCount -ArpMatchCount $arpHits.Count
                $intuneOutput | ConvertTo-Json -Compress; exit 0
            }

            if ($expectedCount -gt 0 -and $expectedCount -lt $totalDetections) {
                $intuneOutput.FilePath        = ($detectedItems | ForEach-Object { $_.FilePath }) -join ';'
                $intuneOutput.DetectedVersion = ($detectedItems | ForEach-Object { $_.Version }) -join ';'
                $intuneOutput.InstallScope    = ($detectedItems | Select-Object -ExpandProperty Scope -Unique) -join ','
                $intuneOutput.Status = "MultipleVersionsDetected"
                Write-Log "Summary: App='$($intuneOutput.AppName)'; Scope=$($intuneOutput.InstallScope); Files='$($intuneOutput.FilePath)'; Detected='$($intuneOutput.DetectedVersion)'; Expected='$($intuneOutput.ExpectedVersion)'; Status=$($intuneOutput.Status); ExitCode=1" 'WARN'
                Write-CsvSummary -Path $CsvOutputFile -CorrelationId $CorrelationId -RunContext $RunContext -IntuneOutput $intuneOutput -TotalDetections $totalDetections -ExpectedCount $expectedCount -ArpMatchCount $arpHits.Count
                $intuneOutput | ConvertTo-Json -Compress; exit 1
            }

            $hasMachine = ($detectedItems | Where-Object { $_.Scope -eq 'Machine' }).Count -gt 0
            $intuneOutput.FilePath        = ($detectedItems | ForEach-Object { $_.FilePath }) -join ';'
            $intuneOutput.DetectedVersion = ($detectedItems | ForEach-Object { $_.Version }) -join ';'
            $intuneOutput.InstallScope    = ($detectedItems | Select-Object -ExpandProperty Scope -Unique) -join ','
            $intuneOutput.Status = if ($hasMachine) { "Outdated" } else { "UserScopeOutdated" }
            Write-Log "Summary: App='$($intuneOutput.AppName)'; Scope=$($intuneOutput.InstallScope); Files='$($intuneOutput.FilePath)'; Detected='$($intuneOutput.DetectedVersion)'; Expected='$($intuneOutput.ExpectedVersion)'; Status=$($intuneOutput.Status); ExitCode=1" 'WARN'
            Write-CsvSummary -Path $CsvOutputFile -CorrelationId $CorrelationId -RunContext $RunContext -IntuneOutput $intuneOutput -TotalDetections $totalDetections -ExpectedCount $expectedCount -ArpMatchCount $arpHits.Count
            $intuneOutput | ConvertTo-Json -Compress; exit 1

        } catch {
            Write-Log "Attempt $attempt failed $_" 'WARN'
            if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelay }
        }
    }
 
    # After retries, still not found
    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-Log "[$AppDisplayName] Not installed on this system." 'INFO'
        $exitCode = if ($TriggerRemediationForMissingApp) { 1 } else { 0 }
        Write-Log "Summary: App='$($intuneOutput.AppName)'; Scope=$($intuneOutput.InstallScope); File='$($intuneOutput.FilePath)'; Detected='$($intuneOutput.DetectedVersion)'; Expected='$($intuneOutput.ExpectedVersion)'; Status=$($intuneOutput.Status); ExitCode=$exitCode" 'INFO'
        Write-CsvSummary -Path $CsvOutputFile -CorrelationId $CorrelationId -RunContext $RunContext -IntuneOutput $intuneOutput -TotalDetections 0 -ExpectedCount 0 -ArpMatchCount 0
        $intuneOutput | ConvertTo-Json -Compress; exit $exitCode
    }

} catch {
    $intuneOutput.Status = "Error"
    Write-Log "[$AppDisplayName] An unexpected error occurred: $_" 'ERROR'
    Write-Log "Summary: App='$($intuneOutput.AppName)'; Scope=$($intuneOutput.InstallScope); File='$($intuneOutput.FilePath)'; Detected='$($intuneOutput.DetectedVersion)'; Expected='$($intuneOutput.ExpectedVersion)'; Status=$($intuneOutput.Status); ExitCode=1" 'ERROR'
    Write-CsvSummary -Path $CsvOutputFile -CorrelationId $CorrelationId -RunContext $RunContext -IntuneOutput $intuneOutput -TotalDetections 0 -ExpectedCount 0 -ArpMatchCount 0
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}
