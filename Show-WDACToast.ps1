[CmdletBinding()]
param(
    [ValidateRange(0, [long]::MaxValue)]
    [long]$EventRecordId = 0,

    # Internal target of the narrowly scoped toast protocol handler.
    [AllowEmptyString()]
    [string]$ReviewActivationUri = '',

    [ValidateRange(0, 1440)]
    [int]$DuplicateCooldownMinutes = 5,

    [ValidatePattern('^https://')]
    [string]$SupportUri = 'https://support.example.com/wdac-review',

    [ValidateNotNullOrEmpty()]
    [string]$ActionLabel = 'Request Review',

    [ValidateNotNullOrEmpty()]
    [string]$AppId = 'Company.WDACToast',

    [ValidateNotNullOrEmpty()]
    [string]$DisplayName = 'Company Security',

    [ValidateNotNullOrEmpty()]
    [string]$InstallDirectory = "$env:ProgramFiles\Company\WDACToast",

    # Defaults to a PNG extracted from the Windows Security application during
    # installation. Supply another local path or HTTPS URI to override it.
    [AllowEmptyString()]
    [string]$LogoPath = '',

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'Company WDAC Block Notification',

    # Controls the execution policy used by the installed Scheduled Task.
    # AllSigned remains the secure default; Bypass is available for deployments
    # that enforce script trust through WDAC or another control.
    [ValidateSet('AllSigned', 'Bypass')]
    [string]$ExecutionPolicy = 'AllSigned',

    # Controls the window state used by the installed Scheduled Task.
    # Hidden prevents a console flash; Minimized is available when the window
    # should remain accessible.
    [ValidateSet('Hidden', 'Minimized')]
    [string]$WindowStyle = 'Hidden',

    # Replaces an existing installation while preserving enough of its identity
    # to remove a renamed task and to roll back a failed task registration.
    [switch]$Upgrade,

    # Required only when moving an installation to a different directory.
    [ValidateNotNullOrEmpty()]
    [string]$UpgradeFromInstallDirectory,

    # Removes the existing machine registration, installed files, and mutable
    # state before installing the deployment copy again. This is intentionally
    # valid only for an installation invocation (EventRecordId 0).
    [switch]$ResetInstallation,

    # Removes the machine task and installed files without touching per-user
    # state unless CleanupLogs is also specified.
    [switch]$Uninstall,

    # Valid only with Uninstall. Deletes only the LOCALAPPDATA state belonging
    # to the execution account (for example, only SYSTEM's state under Intune).
    [switch]$CleanupLogs,

    # Internal entry point used by the monthly log-maintenance Scheduled Task.
    [switch]$LogMaintenance
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DefaultConfiguration = [ordered]@{
    SupportUri = 'https://support.example.com/wdac-review'
    ActionLabel = 'Request Review'
    AppId = 'Company.WDACToast'
    DisplayName = 'Company Security'
    InstallDirectory = "$env:ProgramFiles\Company\WDACToast"
    LogoPath = $null
    TaskName = 'Company WDAC Block Notification'
    ExecutionPolicy = 'AllSigned'
    WindowStyle = 'Hidden'
    DuplicateCooldownMinutes = 5
}
$ScriptDirectory = Split-Path -Parent $PSCommandPath
$InstallationMarkerPath = 'HKLM:\Software\Company\WDACToast'
$RepositoryDefaultInstallDirectory = "$env:ProgramFiles\Company\WDACToast"
# Capture the machine identity before the deployment configuration is allowed to
# select a new target. This makes directory/task renames discoverable even when
# the new package no longer mentions the old values.
$InstallationMarker = Get-ItemProperty -LiteralPath $InstallationMarkerPath -ErrorAction SilentlyContinue
$ConfigurationFile = Join-Path $ScriptDirectory 'WDACToast.json'
$LocalizationFile = Join-Path $ScriptDirectory 'WDACToast.Localization.xml'
$LogoWasConfigured = $PSBoundParameters.ContainsKey('LogoPath')
if (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf) {
    $Configuration = Get-Content -LiteralPath $ConfigurationFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($Name in $DefaultConfiguration.Keys) {
        $Property = $Configuration.PSObject.Properties[$Name]
        if ($null -ne $Property -and -not $PSBoundParameters.ContainsKey($Name)) {
            Set-Variable -Name $Name -Value $Property.Value
            if ($Name -eq 'LogoPath') { $LogoWasConfigured = $true }
        }
    }
}

# Apply defaults after JSON so LogoPath can follow a configured installation
# directory. Explicit command-line parameters always take precedence over JSON.
foreach ($Name in $DefaultConfiguration.Keys) {
    if (-not $PSBoundParameters.ContainsKey($Name) -and
        -not (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf)) {
        Set-Variable -Name $Name -Value $DefaultConfiguration[$Name]
    }
}
if (-not $LogoWasConfigured -and [string]::IsNullOrWhiteSpace([string]$LogoPath)) {
    $LogoPath = Join-Path $InstallDirectory 'MicrosoftDefenderShield.png'
}
$ParsedSupportUri = $null
if ([string]::IsNullOrWhiteSpace([string]$SupportUri) -or
    -not [Uri]::TryCreate($SupportUri, [UriKind]::Absolute, [ref]$ParsedSupportUri) -or
    -not [string]::Equals($ParsedSupportUri.Scheme, 'https', [StringComparison]::OrdinalIgnoreCase) -or
    [string]::IsNullOrWhiteSpace($ParsedSupportUri.Host)) {
    throw "SupportUri in '$ConfigurationFile' must be an HTTPS URI."
}
foreach ($RequiredName in @('ActionLabel', 'AppId', 'DisplayName', 'InstallDirectory', 'TaskName')) {
    if ([string]::IsNullOrWhiteSpace([string](Get-Variable -Name $RequiredName -ValueOnly))) {
        throw "$RequiredName in '$ConfigurationFile' must not be empty."
    }
}
if ([long]$DuplicateCooldownMinutes -lt 0 -or [long]$DuplicateCooldownMinutes -gt 1440) {
    throw "DuplicateCooldownMinutes in '$ConfigurationFile' must be between 0 and 1440."
}
$DuplicateCooldownMinutes = [int]$DuplicateCooldownMinutes
if ([string]$ExecutionPolicy -notin @('AllSigned', 'Bypass')) {
    throw "ExecutionPolicy in '$ConfigurationFile' must be either AllSigned or Bypass."
}
$ExecutionPolicy = [string]$ExecutionPolicy
if ([string]$WindowStyle -notin @('Hidden', 'Minimized')) {
    throw "WindowStyle in '$ConfigurationFile' must be either Hidden or Minimized."
}
$WindowStyle = [string]$WindowStyle

$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
$StateDirectory = Join-Path $env:LOCALAPPDATA 'Company\WDACToast'
$LogDirectory = Join-Path $StateDirectory 'Logs'
$ReviewDirectory = Join-Path $StateDirectory 'Reviews'
$ReviewProtocol = 'company-wdac-review'
$CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$StateFile = Join-Path $StateDirectory "NotificationState-$CurrentSid.json"
$InstalledScript = Join-Path $InstallDirectory 'Show-WDACToast.ps1'
$DefaultLogoPath = Join-Path $InstallDirectory 'MicrosoftDefenderShield.png'
$LogMaintenanceTaskName = "$TaskName Log Maintenance"

function Ensure-CurrentUserAppIdentity {
    $Path = "HKCU:\Software\Classes\AppUserModelId\$AppId"
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name DisplayName -Value $DisplayName -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $Path -Name ShowInSettings -Value 1 -PropertyType DWord -Force | Out-Null
    # Toast protocol activation does not reliably permit file:// targets. Register
    # a per-user handler which accepts only our numeric record URI; the activation
    # entry point validates it again before opening an existing report.
    $ProtocolPath = "HKCU:\Software\Classes\$ReviewProtocol"
    New-Item -Path "$ProtocolPath\shell\open\command" -Force | Out-Null
    New-ItemProperty -Path $ProtocolPath -Name '(default)' -Value 'WDAC review report' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $ProtocolPath -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
    $ProtocolCommand = '"{0}" -NoProfile -NonInteractive -WindowStyle {1} -ExecutionPolicy {2} -File "{3}" -ReviewActivationUri "%1"' -f `
        (Join-Path $PSHOME 'powershell.exe'), $WindowStyle, $ExecutionPolicy, $InstalledScript
    New-ItemProperty -Path "$ProtocolPath\shell\open\command" -Name '(default)' -Value $ProtocolCommand -PropertyType String -Force | Out-Null
    Write-WdacToastLog -Message "Ensured AppUserModelID '$AppId' for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
}

function Remove-CurrentUserAppIdentity {
    param([string[]]$AppIds = @($AppId))
    foreach ($RegisteredAppId in @($AppIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        Remove-Item -LiteralPath "HKCU:\Software\Classes\AppUserModelId\$RegisteredAppId" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath "HKCU:\Software\Classes\$ReviewProtocol" -Recurse -Force -ErrorAction SilentlyContinue
}

function Initialize-WdacToastStateDirectory {
    New-Item -Path $StateDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $ReviewDirectory -ItemType Directory -Force | Out-Null
}

function Write-WdacToastLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $Entry = '{0} [{1}] [PID:{2}] {3}' -f (Get-Date).ToUniversalTime().ToString('o'), $Level, $PID, $Message
    Write-Verbose $Entry
    if ($Level -eq 'WARN') {
        Write-Warning $Message
    }
    try {
        New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        # The month in the file name provides deterministic rotation without a
        # rename race when several event-triggered instances run concurrently.
        $MonthlyLog = 'WDACToast-{0}.log' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM')
        Add-Content -LiteralPath (Join-Path $LogDirectory $MonthlyLog) -Value $Entry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Logging must never hide the original failure. The task history still
        # receives this fallback when the user's local log cannot be written.
        Write-Warning "$Entry (file logging failed: $($_.Exception.Message))"
    }
}

function Invoke-WdacToastLogMaintenance {
    Initialize-WdacToastStateDirectory
    $Cutoff = (Get-Date).ToUniversalTime().AddMonths(-2)
    $RemovedCount = 0
    foreach ($LogFile in @(Get-ChildItem -LiteralPath $LogDirectory -File -ErrorAction SilentlyContinue)) {
        if ($LogFile.LastWriteTimeUtc -lt $Cutoff) {
            Remove-Item -LiteralPath $LogFile.FullName -Force -ErrorAction Stop
            $RemovedCount++
        }
    }
    foreach ($ReviewFile in @(Get-ChildItem -LiteralPath $ReviewDirectory -Filter '*.html' -File -ErrorAction SilentlyContinue)) {
        if ($ReviewFile.LastWriteTimeUtc -lt $Cutoff) {
            Remove-Item -LiteralPath $ReviewFile.FullName -Force -ErrorAction Stop
            $RemovedCount++
        }
    }
    Write-WdacToastLog -Message "Monthly log and review maintenance removed $RemovedCount file(s) older than $($Cutoff.ToString('o'))."
}

function Write-ConfigurationCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        # One message is intentionally unused for each result. Allow callers to
        # pass an empty string for that inactive branch without parameter binding
        # failing before the check can be logged.
        [Parameter(Mandatory)][AllowEmptyString()][string]$SuccessMessage,
        [Parameter(Mandatory)][AllowEmptyString()][string]$FailureMessage
    )

    if ($Passed) {
        Write-WdacToastLog -Message "Configuration check [$Name] passed: $SuccessMessage"
    }
    else {
        Write-WdacToastLog -Level WARN -Message "Configuration check [$Name] failed: $FailureMessage"
    }
    return $Passed
}

function Get-OptionalRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    # Get-ItemPropertyValue can emit PSArgumentException when the key exists but
    # the requested value does not. A missing preference/policy means "not
    # configured" and must not terminate the renderer under ErrorAction Stop.
    $Item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $Item) { return $null }
    $Property = $Item.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

function Get-PreviousWdacToastInstallations {
    [CmdletBinding()]
    param()

    $Installations = @()
    $MarkerHasIdentity = $null -ne $InstallationMarker -and
        $null -ne $InstallationMarker.PSObject.Properties['InstallDirectory'] -and
        $null -ne $InstallationMarker.PSObject.Properties['TaskName'] -and
        $null -ne $InstallationMarker.PSObject.Properties['AppId'] -and
        -not [string]::IsNullOrWhiteSpace([string]$InstallationMarker.InstallDirectory) -and
        -not [string]::IsNullOrWhiteSpace([string]$InstallationMarker.TaskName) -and
        -not [string]::IsNullOrWhiteSpace([string]$InstallationMarker.AppId)
    if ($MarkerHasIdentity) {
        $Installations += [pscustomobject]@{
            InstallDirectory = [string]$InstallationMarker.InstallDirectory
            TaskName = [string]$InstallationMarker.TaskName
            AppId = [string]$InstallationMarker.AppId
            Source = 'machine installation marker'
        }
        return @($Installations)
    }

    # Legacy releases had no machine marker. Inspect both the repository's
    # historical default and the directory selected by this deployment.
    foreach ($CandidateDirectory in @($RepositoryDefaultInstallDirectory, $InstallDirectory) | Select-Object -Unique) {
        $Candidate = [ordered]@{
            InstallDirectory = [string]$CandidateDirectory
            TaskName = [string]$DefaultConfiguration.TaskName
            AppId = [string]$DefaultConfiguration.AppId
            Source = 'legacy installed configuration'
        }
        $CandidateConfigurationFile = Join-Path $CandidateDirectory 'WDACToast.json'
        $CandidateScript = Join-Path $CandidateDirectory 'Show-WDACToast.ps1'
        if (-not (Test-Path -LiteralPath $CandidateConfigurationFile -PathType Leaf) -and
            -not (Test-Path -LiteralPath $CandidateScript -PathType Leaf)) { continue }
        if (Test-Path -LiteralPath $CandidateConfigurationFile -PathType Leaf) {
            try {
                $LegacyConfiguration = Get-Content -LiteralPath $CandidateConfigurationFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if (-not [string]::IsNullOrWhiteSpace([string]$LegacyConfiguration.InstallDirectory)) { $Candidate.InstallDirectory = [string]$LegacyConfiguration.InstallDirectory }
                if (-not [string]::IsNullOrWhiteSpace([string]$LegacyConfiguration.TaskName)) { $Candidate.TaskName = [string]$LegacyConfiguration.TaskName }
                if (-not [string]::IsNullOrWhiteSpace([string]$LegacyConfiguration.AppId)) { $Candidate.AppId = [string]$LegacyConfiguration.AppId }
            }
            catch {
                Write-WdacToastLog -Level WARN -Message "Could not read legacy configuration '$CandidateConfigurationFile': $($_.Exception.Message)"
            }
        }
        $Installations += [pscustomobject]$Candidate
    }
    return @($Installations)
}

function Set-WdacToastInstallationMarker {
    New-Item -Path $InstallationMarkerPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $InstallationMarkerPath -Name InstallDirectory -Value $InstallDirectory -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $InstallationMarkerPath -Name TaskName -Value $TaskName -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $InstallationMarkerPath -Name AppId -Value $AppId -PropertyType String -Force -ErrorAction Stop | Out-Null
}

function Get-WdacToastStrings {
    [CmdletBinding()]
    param()

    # GlobalizationPreferences follows the user's Windows display-language
    # preference list. CurrentUICulture is retained for older Windows builds or
    # hosts where the WinRT projection is unavailable.
    $PreferredLanguages = @()
    try {
        [void][Windows.System.UserProfile.GlobalizationPreferences, Windows.System.UserProfile, ContentType = WindowsRuntime]
        $PreferredLanguages = @([Windows.System.UserProfile.GlobalizationPreferences]::Languages)
    }
    catch {
        $PreferredLanguages = @([System.Globalization.CultureInfo]::CurrentUICulture.Name)
    }
    if ($PreferredLanguages.Count -eq 0) {
        $PreferredLanguages = @([System.Globalization.CultureInfo]::CurrentUICulture.Name)
    }

    if (-not (Test-Path -LiteralPath $LocalizationFile -PathType Leaf)) {
        throw "The localization resource file is missing at '$LocalizationFile'."
    }
    [xml]$Resources = Get-Content -LiteralPath $LocalizationFile -Raw -ErrorAction Stop
    $Languages = @($Resources.localization.language)
    $Selected = $null

    foreach ($PreferredLanguage in $PreferredLanguages) {
        $Selected = $Languages | Where-Object {
            [string]::Equals([string]$_.tag, [string]$PreferredLanguage, [StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
        if ($null -ne $Selected) { break }

        $NeutralLanguage = ([string]$PreferredLanguage -split '-')[0]
        $Selected = $Languages | Where-Object {
            ([string]$_.tag -split '-')[0] -eq $NeutralLanguage
        } | Select-Object -First 1
        if ($null -ne $Selected) { break }
    }

    if ($null -eq $Selected) {
        $FallbackLanguage = [string]$Resources.localization.fallbackLanguage
        $Selected = $Languages | Where-Object {
            [string]::Equals([string]$_.tag, $FallbackLanguage, [StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1
    }
    if ($null -eq $Selected) {
        throw "Localization file '$LocalizationFile' does not contain its configured fallback language."
    }

    $Strings = @{}
    foreach ($StringNode in @($Selected.string)) {
        $Strings[[string]$StringNode.name] = [string]$StringNode.InnerText
    }
    $RequiredStrings = @('Title', 'Message', 'UnknownFile', 'NotProvided', 'BlockedAppPath', 'CalledByAppPath', 'BlockedByPolicy', 'VersionFormat', 'RequestReview', 'Dismiss', 'ReportTitle', 'ReportExplanation', 'ReportApplicationName', 'ReportApplicationPath', 'ReportDescription', 'ReportProduct', 'ReportVersion', 'ReportPublisher', 'ReportCallingProcess', 'ReportCallerDescription', 'ReportCallerProduct', 'ReportCallerVersion', 'ReportCallerPublisher', 'ReportPolicyName', 'ReportPolicyId', 'ReportPolicyVersion', 'ReportStatus', 'ReportSigningScenario', 'ReportRequestedLevel', 'ReportValidatedLevel', 'ReportSha256', 'ReportSha1', 'ReportEventTime', 'ReportComputer', 'ReportActivityId', 'ReportProvider', 'ReportRecordId', 'ReportExactErrorHeading', 'ReportCopyHint', 'ReportCopyButton', 'ReportCopySuccess', 'ReportCopyFailure', 'ReportSupportHeading', 'ReportSupportInstructions', 'ReportSupportStepOne', 'ReportSupportStepTwo', 'ReportSupportStepThree', 'ReportOpenSupport')
    foreach ($RequiredString in $RequiredStrings) {
        if (-not $Strings.ContainsKey($RequiredString) -or [string]::IsNullOrWhiteSpace([string]$Strings[$RequiredString])) {
            throw "Language '$($Selected.tag)' is missing required string '$RequiredString' in '$LocalizationFile'."
        }
    }

    return [pscustomobject]@{
        Language = [string]$Selected.tag
        Strings = $Strings
    }
}

function Test-WdacToastConfiguration {
    [CmdletBinding()]
    param([switch]$IncludeRendererChecks)

    Write-WdacToastLog -Message "Starting configuration checks. Host=$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion); User=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name); Interactive=$([Environment]::UserInteractive)."
    $Results = [System.Collections.Generic.List[bool]]::new()
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $MaintenanceTask = Get-ScheduledTask -TaskName $LogMaintenanceTaskName -ErrorAction SilentlyContinue

    $Results.Add((Write-ConfigurationCheck -Name 'Installed script' -Passed (Test-Path -LiteralPath $InstalledScript -PathType Leaf) -SuccessMessage $InstalledScript -FailureMessage "The installed script is missing at '$InstalledScript'."))
    if ($IncludeRendererChecks) {
        $AppIdRegistryPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
        $RegistryValues = Get-ItemProperty -LiteralPath $AppIdRegistryPath -ErrorAction SilentlyContinue
        $Results.Add((Write-ConfigurationCheck -Name 'Application identity' -Passed ($null -ne $RegistryValues) -SuccessMessage $AppIdRegistryPath -FailureMessage "The per-user AppUserModelID '$AppId' is not registered at '$AppIdRegistryPath'."))
        if ($null -ne $RegistryValues) {
            $RegisteredDisplayName = if ($RegistryValues.PSObject.Properties['DisplayName']) { [string]$RegistryValues.DisplayName } else { $null }
            $RegisteredShowInSettings = if ($RegistryValues.PSObject.Properties['ShowInSettings']) { $RegistryValues.ShowInSettings } else { $null }
            $Results.Add((Write-ConfigurationCheck -Name 'Application display name' -Passed ($RegisteredDisplayName -eq $DisplayName) -SuccessMessage "DisplayName is '$DisplayName'." -FailureMessage "Expected DisplayName '$DisplayName', found '$RegisteredDisplayName'."))
            $Results.Add((Write-ConfigurationCheck -Name 'Application notification settings' -Passed ($null -ne $RegisteredShowInSettings -and [int]$RegisteredShowInSettings -eq 1) -SuccessMessage 'ShowInSettings is enabled.' -FailureMessage "ShowInSettings should be 1, found '$RegisteredShowInSettings'."))
        }
    }

    $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task' -Passed ($null -ne $Task) -SuccessMessage "Task '$TaskName' exists." -FailureMessage "Computer-level task '$TaskName' does not exist."))
    $Results.Add((Write-ConfigurationCheck -Name 'Log maintenance task' -Passed ($null -ne $MaintenanceTask) -SuccessMessage "Monthly task '$LogMaintenanceTaskName' exists." -FailureMessage "Monthly log maintenance task '$LogMaintenanceTaskName' does not exist."))
    if ($null -ne $Task) {
        $TaskAction = @($Task.Actions) | Select-Object -First 1
        $TaskExecute = if ($null -ne $TaskAction) { [string]$TaskAction.Execute } else { '' }
        $TaskArguments = if ($null -ne $TaskAction) { [string]$TaskAction.Arguments } else { '' }
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task state' -Passed ($Task.State -ne 'Disabled') -SuccessMessage "Task state is $($Task.State)." -FailureMessage 'The task is disabled.'))
        $PrincipalIsInteractive = $Task.Principal.GroupId -eq 'S-1-5-4' -and $Task.Principal.RunLevel -eq 'Limited'
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task principal' -Passed $PrincipalIsInteractive -SuccessMessage 'Task is assigned to the well-known INTERACTIVE group at least privilege.' -FailureMessage "Expected GroupId S-1-5-4 and Limited run level; found GroupId '$($Task.Principal.GroupId)', UserId '$($Task.Principal.UserId)', LogonType '$($Task.Principal.LogonType)', RunLevel '$($Task.Principal.RunLevel)'."))
        $ActionIsValid = $null -ne $TaskAction -and $TaskExecute -like '*\WindowsPowerShell\v1.0\powershell.exe' -and $TaskArguments -like "*${InstalledScript}*" -and $TaskArguments -like "*-WindowStyle $WindowStyle*" -and $TaskArguments -like "*-ExecutionPolicy $ExecutionPolicy*" -and $TaskArguments -notlike '*-Broker*'
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task action' -Passed $ActionIsValid -SuccessMessage "Task launches the renderer directly with Windows PowerShell 5.1 using window style $WindowStyle and execution policy $ExecutionPolicy." -FailureMessage "The task action is unexpected. Expected WindowStyle '$WindowStyle' and ExecutionPolicy '$ExecutionPolicy'; Execute='$TaskExecute'; Arguments='$TaskArguments'."))
    }

    $EventLog = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
    $Results.Add((Write-ConfigurationCheck -Name 'Code Integrity event log' -Passed ($null -ne $EventLog -and $EventLog.IsEnabled) -SuccessMessage "'$LogName' is available and enabled." -FailureMessage "'$LogName' is unavailable or disabled in the current context."))
    if ($SupportUri -eq 'https://support.example.com/wdac-review') {
        $Results.Add((Write-ConfigurationCheck -Name 'Support URI' -Passed $false -SuccessMessage '' -FailureMessage "The placeholder SupportUri '$SupportUri' is still configured; replace it with your organization's HTTPS review URL."))
    }
    else {
        $Results.Add((Write-ConfigurationCheck -Name 'Support URI' -Passed $true -SuccessMessage $SupportUri -FailureMessage ''))
    }

    if ($IncludeRendererChecks) {
        $IsWindowsPowerShell = $PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5
        $Results.Add((Write-ConfigurationCheck -Name 'PowerShell host' -Passed $IsWindowsPowerShell -SuccessMessage 'Windows PowerShell 5.1 is in use.' -FailureMessage "Rendering requires Windows PowerShell 5.1; current host is $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)."))
        $Results.Add((Write-ConfigurationCheck -Name 'Interactive session' -Passed ([Environment]::UserInteractive) -SuccessMessage 'The current process has an interactive user session.' -FailureMessage 'The process is not in an interactive user session, so Windows cannot display its toast.'))

        $ToastEnabled = Get-OptionalRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled
        $Results.Add((Write-ConfigurationCheck -Name 'User notification preference' -Passed ($null -eq $ToastEnabled -or [int]$ToastEnabled -ne 0) -SuccessMessage "ToastEnabled is not disabled (value: '$ToastEnabled')." -FailureMessage 'HKCU PushNotifications\ToastEnabled is 0. Enable notifications for this user.'))
        $PolicyDisabled = Get-OptionalRegistryValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name DisableNotificationCenter
        $Results.Add((Write-ConfigurationCheck -Name 'Notification policy' -Passed ($null -eq $PolicyDisabled -or [int]$PolicyDisabled -ne 1) -SuccessMessage "DisableNotificationCenter is not enabled (value: '$PolicyDisabled')." -FailureMessage 'User policy DisableNotificationCenter is 1; an administrator must change the policy before toasts can appear.'))
        $PushServices = @(Get-Service -Name 'WpnUserService*' -ErrorAction SilentlyContinue)
        $RunningPushService = @($PushServices | Where-Object Status -eq 'Running').Count -gt 0
        $Results.Add((Write-ConfigurationCheck -Name 'Push notification service' -Passed $RunningPushService -SuccessMessage "A WpnUserService instance is running." -FailureMessage "No running WpnUserService instance was found (found $($PushServices.Count) instance(s))."))
    }

    $FailedCount = @($Results | Where-Object { -not $_ }).Count
    Write-WdacToastLog -Message "Configuration checks completed: $($Results.Count - $FailedCount) passed, $FailedCount warning(s)."
    return $FailedCount -eq 0
}

function Test-WdacToastInstalled {
    $SourceScript = $PSCommandPath
    $InstalledScriptIsCurrent = Test-Path -LiteralPath $InstalledScript -PathType Leaf
    if (
        $InstalledScriptIsCurrent -and
        -not [string]::IsNullOrWhiteSpace($SourceScript) -and
        (Test-Path -LiteralPath $SourceScript -PathType Leaf) -and
        -not [string]::Equals($SourceScript, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)
    ) {
        $SourceHash = (Get-FileHash -LiteralPath $SourceScript -Algorithm SHA256).Hash
        $InstalledHash = (Get-FileHash -LiteralPath $InstalledScript -Algorithm SHA256).Hash
        $InstalledScriptIsCurrent = $SourceHash -eq $InstalledHash
        if (-not $InstalledScriptIsCurrent) {
            Write-WdacToastLog -Level WARN -Message "The installed script differs from the deployment source and will be upgraded. Source='$SourceScript'; Installed='$InstalledScript'."
        }
    }

    return (
        $InstalledScriptIsCurrent -and
        ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue))
    )
}

function Install-WdacToast {
    param([switch]$DeferMigration)

    $PreviousInstallations = @(Get-PreviousWdacToastInstallations)
    $SourceScript = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($SourceScript) -or -not (Test-Path -LiteralPath $SourceScript)) {
        throw 'The script must be run from a saved .ps1 file before it can install itself.'
    }

    New-Item -Path $InstallDirectory -ItemType Directory -Force | Out-Null
    Initialize-WdacToastStateDirectory
    if (-not [string]::Equals($SourceScript, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $SourceScript -Destination $InstalledScript -Force
    }
    Ensure-CurrentUserAppIdentity
    $InstalledConfigurationFile = Join-Path $InstallDirectory 'WDACToast.json'
    if (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf) {
        if (-not [string]::Equals($ConfigurationFile, $InstalledConfigurationFile, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $ConfigurationFile -Destination $InstalledConfigurationFile -Force
        }
        Write-WdacToastLog -Message "Installed configuration is present at '$InstalledConfigurationFile'."
    }
    $InstalledLocalizationFile = Join-Path $InstallDirectory 'WDACToast.Localization.xml'
    if (-not (Test-Path -LiteralPath $LocalizationFile -PathType Leaf)) {
        throw "The deployment package is missing '$LocalizationFile'."
    }
    if (-not [string]::Equals($LocalizationFile, $InstalledLocalizationFile, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $LocalizationFile -Destination $InstalledLocalizationFile -Force
    }
    Write-WdacToastLog -Message "Installed localization resources at '$InstalledLocalizationFile'."
    $InstalledCommand = Get-Command -Name $InstalledScript -CommandType ExternalScript -ErrorAction Stop
    if (-not $InstalledCommand.Parameters.ContainsKey('EventRecordId')) {
        throw "The installed script at '$InstalledScript' does not declare the EventRecordId parameter."
    }
    Write-WdacToastLog -Message "Installed script is present at '$InstalledScript'."

    if ([string]::Equals($LogoPath, $DefaultLogoPath, [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path -LiteralPath $DefaultLogoPath -PathType Leaf)) {
        $WindowsSecurityExecutable = Join-Path $env:WINDIR 'System32\SecurityHealthSystray.exe'
        if (Test-Path -LiteralPath $WindowsSecurityExecutable -PathType Leaf) {
            try {
                Add-Type -AssemblyName System.Drawing
                $ShieldIcon = [System.Drawing.Icon]::ExtractAssociatedIcon($WindowsSecurityExecutable)
                if ($null -ne $ShieldIcon) {
                    $ShieldBitmap = $null
                    try {
                        $ShieldBitmap = $ShieldIcon.ToBitmap()
                        $ShieldBitmap.Save($DefaultLogoPath, [System.Drawing.Imaging.ImageFormat]::Png)
                    }
                    finally {
                        if ($null -ne $ShieldBitmap) { $ShieldBitmap.Dispose() }
                        $ShieldIcon.Dispose()
                    }
                    Write-WdacToastLog -Message "Created the default Microsoft Defender shield image at '$DefaultLogoPath'."
                }
            }
            catch {
                Write-WdacToastLog -Level WARN -Message "Unable to create the default Microsoft Defender shield image: $($_.Exception.Message)"
            }
        }
        if (-not (Test-Path -LiteralPath $DefaultLogoPath -PathType Leaf)) {
            Write-WdacToastLog -Level WARN -Message "The Windows Security icon could not be extracted from '$WindowsSecurityExecutable'. Notifications will be shown without the default image."
        }
    }

    $EscapedScript = [System.Security.SecurityElement]::Escape($InstalledScript)
    $TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Displays WDAC notifications in the currently interactive user's session.</Description></RegistrationInfo>
  <Triggers><EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;&lt;Select Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;*[System[EventID=3077]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription><ValueQueries><Value name="EventRecordID">Event/System/EventRecordID</Value></ValueQueries></EventTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-4</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -WindowStyle $WindowStyle -ExecutionPolicy $ExecutionPolicy -File &quot;$EscapedScript&quot; -EventRecordId &quot;`$(EventRecordID)&quot; -ExecutionPolicy $ExecutionPolicy -WindowStyle $WindowStyle</Arguments></Exec></Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $TaskName -Xml $TaskXml -Force | Out-Null
    Write-WdacToastLog -Message "Registered Scheduled Task '$TaskName' for the well-known INTERACTIVE group (S-1-5-4) at least privilege with execution policy '$ExecutionPolicy'."

    $MaintenanceTaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Rotates and removes expired WDAC notification logs for the currently interactive user.</Description></RegistrationInfo>
  <Triggers><CalendarTrigger><StartBoundary>2024-01-01T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/></Months></ScheduleByMonth></CalendarTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-4</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -WindowStyle $WindowStyle -ExecutionPolicy $ExecutionPolicy -File &quot;$EscapedScript&quot; -LogMaintenance -ExecutionPolicy $ExecutionPolicy -WindowStyle $WindowStyle</Arguments></Exec></Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $LogMaintenanceTaskName -Xml $MaintenanceTaskXml -Force | Out-Null
    Write-WdacToastLog -Message "Registered monthly Scheduled Task '$LogMaintenanceTaskName' to remove log files older than two months."

    if (-not $DeferMigration) {
        $RegisteredTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ($null -eq $RegisteredTask) { throw "Scheduled Task '$TaskName' was not registered successfully." }
        $RegisteredMaintenanceTask = Get-ScheduledTask -TaskName $LogMaintenanceTaskName -ErrorAction Stop
        if ($null -eq $RegisteredMaintenanceTask) { throw "Scheduled Task '$LogMaintenanceTaskName' was not registered successfully." }
        foreach ($PreviousInstallation in $PreviousInstallations) {
            if (-not [string]::IsNullOrWhiteSpace($PreviousInstallation.TaskName) -and
                -not [string]::Equals($PreviousInstallation.TaskName, $TaskName, [StringComparison]::OrdinalIgnoreCase)) {
                foreach ($PreviousTask in @($PreviousInstallation.TaskName, "$($PreviousInstallation.TaskName) Log Maintenance")) {
                    if ($null -ne (Get-ScheduledTask -TaskName $PreviousTask -ErrorAction SilentlyContinue)) {
                        Unregister-ScheduledTask -TaskName $PreviousTask -Confirm:$false -ErrorAction Stop
                    }
                    if ($null -ne (Get-ScheduledTask -TaskName $PreviousTask -ErrorAction SilentlyContinue)) {
                        throw "Previous Scheduled Task '$PreviousTask' is still registered."
                    }
                }
            }
        }
        $PreviousAppIds = @($PreviousInstallations | ForEach-Object AppId | Where-Object { $_ -ne $AppId })
        Remove-CurrentUserAppIdentity -AppIds $PreviousAppIds
        foreach ($PreviousInstallation in $PreviousInstallations) {
            if (-not [string]::IsNullOrWhiteSpace($PreviousInstallation.InstallDirectory) -and
                -not [string]::Equals($PreviousInstallation.InstallDirectory, $InstallDirectory, [StringComparison]::OrdinalIgnoreCase) -and
                (Test-Path -LiteralPath $PreviousInstallation.InstallDirectory)) {
                Remove-Item -LiteralPath $PreviousInstallation.InstallDirectory -Recurse -Force -ErrorAction Stop
            }
        }
        # This is the commit record: never advertise the new identity until the
        # task replacement and old-directory cleanup have both succeeded.
        Set-WdacToastInstallationMarker
    }
}

function Upgrade-WdacToastInstallation {
    if ([string]::Equals($PSCommandPath, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Upgrade must be run from the new deployment copy, not '$InstalledScript'."
    }

    $DetectedInstallations = @(Get-PreviousWdacToastInstallations)
    $MarkedInstallation = @($DetectedInstallations | Where-Object Source -eq 'machine installation marker' | Select-Object -First 1)
    $PreviousDirectory = if ($MarkedInstallation.Count -gt 0) {
        [string]$MarkedInstallation[0].InstallDirectory
    }
    elseif ($PSBoundParameters.ContainsKey('UpgradeFromInstallDirectory')) {
        $UpgradeFromInstallDirectory
    }
    else {
        $LegacyInstallation = @($DetectedInstallations | Where-Object {
            Test-Path -LiteralPath (Join-Path $_.InstallDirectory 'WDACToast.json') -PathType Leaf
        } | Select-Object -First 1)
        if ($LegacyInstallation.Count -gt 0) { [string]$LegacyInstallation[0].InstallDirectory } else { $InstallDirectory }
    }
    $PreviousConfigurationFile = Join-Path $PreviousDirectory 'WDACToast.json'
    if (-not (Test-Path -LiteralPath $PreviousConfigurationFile -PathType Leaf) -and $MarkedInstallation.Count -eq 0) {
        throw "Upgrade could not find the prior installed configuration at '$PreviousConfigurationFile'. Use UpgradeFromInstallDirectory when migrating directories."
    }

    # Capture the complete prior configuration (including future identity
    # properties), as well as the identity values used by this version, before
    # Install-WdacToast overwrites any destination file.
    $PreviousConfiguration = if (Test-Path -LiteralPath $PreviousConfigurationFile -PathType Leaf) {
        Get-Content -LiteralPath $PreviousConfigurationFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    else {
        [pscustomobject]@{
            TaskName = [string]$MarkedInstallation[0].TaskName
            InstallDirectory = [string]$MarkedInstallation[0].InstallDirectory
            AppId = [string]$MarkedInstallation[0].AppId
        }
    }
    $PreviousTaskName = if ($MarkedInstallation.Count -gt 0) { [string]$MarkedInstallation[0].TaskName } else { [string]$PreviousConfiguration.TaskName }
    $RecordedPreviousDirectory = [string]$PreviousConfiguration.InstallDirectory
    if ([string]::IsNullOrWhiteSpace($PreviousTaskName) -or [string]::IsNullOrWhiteSpace($RecordedPreviousDirectory)) {
        throw "Prior installed configuration '$PreviousConfigurationFile' must contain TaskName and InstallDirectory."
    }
    $PreviousIdentity = [ordered]@{}
    foreach ($Property in $PreviousConfiguration.PSObject.Properties) {
        $PreviousIdentity[$Property.Name] = $Property.Value
    }
    Write-WdacToastLog -Message "Captured prior installation identity from '$PreviousConfigurationFile': TaskName='$PreviousTaskName'; InstallDirectory='$RecordedPreviousDirectory'; AppId='$($PreviousIdentity.AppId)'; DisplayName='$($PreviousIdentity.DisplayName)'."

    $BackupDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("WDACToast-upgrade-{0}" -f [guid]::NewGuid().ToString('N'))
    $DestinationExisted = Test-Path -LiteralPath $InstallDirectory
    if ($DestinationExisted) {
        Copy-Item -LiteralPath $InstallDirectory -Destination $BackupDirectory -Recurse -Force -ErrorAction Stop
    }
    $PreviousTaskXml = $null
    $PreviousMaintenanceTaskName = "$PreviousTaskName Log Maintenance"
    $PreviousMaintenanceTaskXml = $null
    if ($null -ne (Get-ScheduledTask -TaskName $PreviousTaskName -ErrorAction SilentlyContinue)) {
        $PreviousTaskXml = Export-ScheduledTask -TaskName $PreviousTaskName -ErrorAction Stop
    }
    if ($null -ne (Get-ScheduledTask -TaskName $PreviousMaintenanceTaskName -ErrorAction SilentlyContinue)) {
        $PreviousMaintenanceTaskXml = Export-ScheduledTask -TaskName $PreviousMaintenanceTaskName -ErrorAction Stop
    }

    try {
        # Install uses Register-ScheduledTask -Force, replacing a same-name task.
        Install-WdacToast -DeferMigration

        if (-not [string]::Equals($PreviousTaskName, $TaskName, [StringComparison]::OrdinalIgnoreCase)) {
            Unregister-ScheduledTask -TaskName $PreviousTaskName -Confirm:$false -ErrorAction Stop
            Unregister-ScheduledTask -TaskName $PreviousMaintenanceTaskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        $IntendedTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $TaskName)
        $IntendedMaintenanceTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $LogMaintenanceTaskName)
        $OldTasks = if ([string]::Equals($PreviousTaskName, $TaskName, [StringComparison]::OrdinalIgnoreCase)) { @() } else {
            @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -in @($PreviousTaskName, $PreviousMaintenanceTaskName))
        }
        if ($IntendedTasks.Count -ne 1 -or $IntendedMaintenanceTasks.Count -ne 1 -or $OldTasks.Count -ne 0) {
            throw "Upgrade verification expected notification and maintenance tasks for '$TaskName' and no previous tasks; found $($IntendedTasks.Count), $($IntendedMaintenanceTasks.Count), and $($OldTasks.Count)."
        }
        $Action = @($IntendedTasks[0].Actions) | Select-Object -First 1
        if ($null -eq $Action -or [string]$Action.Arguments -notlike "*${InstalledScript}*" -or [string]$Action.Arguments -notlike "*-WindowStyle $WindowStyle*") {
            throw "Upgrade verification found that Scheduled Task '$TaskName' does not point to '$InstalledScript' with window style '$WindowStyle'."
        }

        if (-not [string]::Equals($RecordedPreviousDirectory, $InstallDirectory, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $RecordedPreviousDirectory -Recurse -Force -ErrorAction Stop
        }
        Set-WdacToastInstallationMarker
        Write-WdacToastLog -Message "Verified upgraded Scheduled Task '$TaskName' points to '$InstalledScript' and no previous task remains."
    }
    catch {
        $UpgradeFailure = $_
        # File copying is transactional for upgrades: restore the destination
        # snapshot and prior task, or explicitly report rollback failure.
        $RollbackFailures = @()
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $LogMaintenanceTaskName -Confirm:$false -ErrorAction SilentlyContinue
            if ($null -ne $PreviousTaskXml) {
                Register-ScheduledTask -TaskName $PreviousTaskName -Xml $PreviousTaskXml -Force -ErrorAction Stop | Out-Null
            }
            if ($null -ne $PreviousMaintenanceTaskXml) {
                Register-ScheduledTask -TaskName $PreviousMaintenanceTaskName -Xml $PreviousMaintenanceTaskXml -Force -ErrorAction Stop | Out-Null
            }
        }
        catch { $RollbackFailures += "task rollback: $($_.Exception.Message)" }
        try {
            Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
            if ($DestinationExisted) { Copy-Item -LiteralPath $BackupDirectory -Destination $InstallDirectory -Recurse -Force -ErrorAction Stop }
        }
        catch { $RollbackFailures += "file rollback: $($_.Exception.Message)" }
        $RollbackStatus = if ($RollbackFailures.Count -eq 0) { 'Rollback restored the prior files and task.' } else { "Rollback was incomplete: $($RollbackFailures -join '; ')" }
        throw "Upgrade failed: $($UpgradeFailure.Exception.Message) $RollbackStatus"
    }
    finally {
        Remove-Item -LiteralPath $BackupDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Reset-WdacToastInstallation {
    if ([string]::Equals($PSCommandPath, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        throw "ResetInstallation must be run from the new deployment copy, not '$InstalledScript'."
    }
    $TaskNames = @($TaskName, $LogMaintenanceTaskName)
    $RegisteredAppIds = @($AppId)
    $InstalledConfigurationFile = Join-Path $InstallDirectory 'WDACToast.json'

    # Also remove the name recorded by the previous installation so renaming the
    # task in a new package does not leave an orphaned event subscription.
    if (Test-Path -LiteralPath $InstalledConfigurationFile -PathType Leaf) {
        try {
            $Previous = Get-Content -LiteralPath $InstalledConfigurationFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace([string]$Previous.TaskName)) {
                $TaskNames += [string]$Previous.TaskName
                $TaskNames += "$([string]$Previous.TaskName) Log Maintenance"
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$Previous.AppId)) {
                $RegisteredAppIds += [string]$Previous.AppId
            }
        }
        catch {
            Write-WdacToastLog -Level WARN -Message "Could not read the previous configuration during reset; current configured names will still be removed. $($_.Exception.Message)"
        }
    }

    foreach ($RegisteredTaskName in @($TaskNames | Select-Object -Unique)) {
        Unregister-ScheduledTask -TaskName $RegisteredTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    Remove-CurrentUserAppIdentity -AppIds $RegisteredAppIds

    Write-WdacToastLog -Message 'Reset the WDAC toast task, installed files, and state for the current profile.'
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction SilentlyContinue
    # Keep this as the final state-directory operation. Write-WdacToastLog
    # creates its file-log directory, so logging after this point would restore
    # state that reset is meant to discard before the new installation starts.
    Remove-Item -LiteralPath $StateDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

function Uninstall-WdacToast {
    if ($EventRecordId -ne 0) {
        throw 'Uninstall requires an installation-mode invocation (EventRecordId = 0).'
    }

    $Failures = [System.Collections.Generic.List[string]]::new()
    $PreviousInstallations = @(Get-PreviousWdacToastInstallations)
    $TaskNames = @($TaskName, $LogMaintenanceTaskName) + @($PreviousInstallations | ForEach-Object { $_.TaskName; "$($_.TaskName) Log Maintenance" })
    $InstallationDirectories = @($InstallDirectory) + @($PreviousInstallations | ForEach-Object InstallDirectory)
    $RegisteredAppIds = @($AppId) + @($PreviousInstallations | ForEach-Object AppId)
    $InstalledConfigurationFile = Join-Path $InstallDirectory 'WDACToast.json'

    # Read the installed configuration before removing either tasks or files.
    # Its TaskName may differ from the name requested by this deployment copy.
    if (Test-Path -LiteralPath $InstalledConfigurationFile -PathType Leaf) {
        try {
            $InstalledConfiguration = Get-Content -LiteralPath $InstalledConfigurationFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace([string]$InstalledConfiguration.TaskName)) {
                $TaskNames += [string]$InstalledConfiguration.TaskName
                $TaskNames += "$([string]$InstalledConfiguration.TaskName) Log Maintenance"
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$InstalledConfiguration.AppId)) {
                $RegisteredAppIds += [string]$InstalledConfiguration.AppId
            }
        }
        catch {
            $Message = "Could not read installed configuration '$InstalledConfigurationFile': $($_.Exception.Message)"
            $Failures.Add($Message)
            Write-Warning $Message
        }
    }

    try {
        Remove-CurrentUserAppIdentity -AppIds $RegisteredAppIds
        Write-WdacToastLog -Message 'Removed the current user AppUserModelID registration.'
    }
    catch {
        $Failures.Add("Failed to remove current-user notification activation registration: $($_.Exception.Message)")
    }

    foreach ($RegisteredTaskName in @($TaskNames | Select-Object -Unique)) {
        try {
            $MatchingTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $RegisteredTaskName)
            if ($MatchingTasks.Count -gt 0) {
                Unregister-ScheduledTask -TaskName $RegisteredTaskName -Confirm:$false -ErrorAction Stop
            }
            $RemainingTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $RegisteredTaskName)
            if ($RemainingTasks.Count -gt 0) {
                throw "Scheduled Task '$RegisteredTaskName' is still registered."
            }
            Write-WdacToastLog -Message "Verified removal of Scheduled Task '$RegisteredTaskName'."
        }
        catch {
            $Message = "Failed to remove or verify Scheduled Task '$RegisteredTaskName': $($_.Exception.Message)"
            $Failures.Add($Message)
            Write-Warning $Message
        }
    }

    # Attempt file cleanup only after every requested/recorded task name has
    # been processed, even when one of the task operations failed.
    foreach ($RegisteredInstallDirectory in @($InstallationDirectories | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        try {
            if (Test-Path -LiteralPath $RegisteredInstallDirectory) {
                Remove-Item -LiteralPath $RegisteredInstallDirectory -Recurse -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $RegisteredInstallDirectory) {
                throw "Installation directory '$RegisteredInstallDirectory' still exists."
            }
        }
        catch {
            $Message = "Failed to remove or verify installation directory '$RegisteredInstallDirectory': $($_.Exception.Message)"
            $Failures.Add($Message)
            Write-Warning $Message
        }
    }

    try {
        Remove-Item -LiteralPath $InstallationMarkerPath -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $InstallationMarkerPath) { throw "Installation marker '$InstallationMarkerPath' still exists." }
    }
    catch {
        $Message = "Failed to remove or verify installation marker '$InstallationMarkerPath': $($_.Exception.Message)"
        $Failures.Add($Message)
        Write-Warning $Message
    }

    if ($CleanupLogs) {
        try {
            if (Test-Path -LiteralPath $StateDirectory) {
                Remove-Item -LiteralPath $StateDirectory -Recurse -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $StateDirectory) {
                throw "Current-account state directory '$StateDirectory' still exists."
            }
        }
        catch {
            $Message = "Failed to remove or verify current-account state directory '$StateDirectory': $($_.Exception.Message)"
            $Failures.Add($Message)
            Write-Warning $Message
        }
    }

    if ($Failures.Count -gt 0) {
        throw "WDAC toast uninstall completed with $($Failures.Count) failure(s): $($Failures -join ' | ')"
    }
}

function Get-NamedEventData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    [xml]$EventXml = $Event.ToXml()
    $Data = [ordered]@{}

    foreach ($Node in @($EventXml.Event.EventData.Data)) {
        # Use XmlElement APIs rather than PowerShell's XML property adapter. Under
        # StrictMode, an element containing only text does not reliably expose a
        # synthetic '#text' property, and Name can resolve to the element name
        # instead of the Name attribute.
        $Name = [string]$Node.GetAttribute('Name')
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $Data[$Name] = [string]$Node.InnerText
        }
    }

    return $Data
}

function Get-FirstEventValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$EventData,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        if ($EventData.Contains($Name)) {
            $Value = [string]$EventData[$Name]
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                return $Value
            }
        }
    }

    return $null
}

function ConvertFrom-NtDevicePath {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^\\Device\\HarddiskVolume\d+(?:\\|$)') {
        return $Path
    }

    # QueryDosDevice is the Windows-supported mapping between an NT device name
    # (as recorded by Code Integrity) and its DOS drive letter. This avoids
    # guessing that HarddiskVolume3 is C:, which is not portable between PCs.
    if (-not ('WdacToast.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace WdacToast {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maxLength);
    }
}
'@
    }

    foreach ($Letter in [char[]](67..90)) {
        $Drive = "$Letter`:"
        $Target = [System.Text.StringBuilder]::new(1024)
        if ([WdacToast.NativeMethods]::QueryDosDevice($Drive, $Target, $Target.Capacity) -gt 0) {
            $DevicePath = ($Target.ToString() -split [char]0)[0]
            if ($Path.Equals($DevicePath, [StringComparison]::OrdinalIgnoreCase)) { return $Drive }
            if ($Path.StartsWith("$DevicePath\", [StringComparison]::OrdinalIgnoreCase)) {
                return $Drive + $Path.Substring($DevicePath.Length)
            }
        }
    }

    return $Path
}

function Get-BlockedFileDetails {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)

    $Details = [ordered]@{ Description = $null; Product = $null; Version = $null; Publisher = $null }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $Details }

    $Item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -ne $Item) {
        $VersionInfo = $Item.VersionInfo
        $Details.Description = $VersionInfo.FileDescription
        $Details.Product = $VersionInfo.ProductName
        $Details.Version = $VersionInfo.FileVersion
        $Details.Publisher = $VersionInfo.CompanyName
    }
    return $Details
}

function Get-NotificationState {
    if (-not (Test-Path -LiteralPath $StateFile)) { return @{} }

    try {
        $StateObject = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        $State = @{}
        foreach ($Property in $StateObject.PSObject.Properties) {
            $State[$Property.Name] = [datetime]$Property.Value
        }
        return $State
    }
    catch {
        Write-Warning "Ignoring unreadable notification state: $($_.Exception.Message)"
        return @{}
    }
}

function Save-NotificationState {
    param([Parameter(Mandatory)][hashtable]$State)

    $TemporaryFile = "$StateFile.$PID.tmp"
    try {
        $State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $TemporaryFile -Encoding UTF8
        Move-Item -LiteralPath $TemporaryFile -Destination $StateFile -Force
    }
    finally {
        Remove-Item -LiteralPath $TemporaryFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-StableHash {
    param([Parameter(Mandatory)][string]$Text)

    $Sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($Sha256.ComputeHash($Bytes))).Replace('-', '')
    }
    finally {
        $Sha256.Dispose()
    }
}

function Open-WdacReviewPage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ActivationUri)

    $Match = [regex]::Match($ActivationUri, '^company-wdac-review://open/([0-9]+)/([0-9a-f]{32})$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $Match.Success) { throw 'The review activation URI is invalid.' }
    $RecordId = [long]$Match.Groups[1].Value
    $Nonce = $Match.Groups[2].Value
    $Path = Join-Path $ReviewDirectory "review-$RecordId-$Nonce.html"
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "The local review report for record $RecordId was not found." }
    Start-Process -FilePath $Path
}

function New-WdacReviewPage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Strings,
        [Parameter(Mandatory)][ValidatePattern('^https://')][string]$SupportUri
    )

    New-Item -Path $ReviewDirectory -ItemType Directory -Force | Out-Null
    $Encode = { param([AllowNull()]$Value) [Net.WebUtility]::HtmlEncode($(if ([string]::IsNullOrWhiteSpace([string]$Value)) { $Strings.NotProvided } else { [string]$Value })) }
    $Rows = [ordered]@{
        $Strings.ReportApplicationName = $Result.FileName; $Strings.ReportApplicationPath = $Result.FilePath
        $Strings.ReportDescription = $Result.FileDescription; $Strings.ReportProduct = $Result.ProductName
        $Strings.ReportVersion = $Result.FileVersion; $Strings.ReportPublisher = $Result.Publisher
        $Strings.ReportCallingProcess = $Result.ProcessPath; $Strings.ReportCallerDescription = $Result.CallerDescription
        $Strings.ReportCallerProduct = $Result.CallerProductName; $Strings.ReportCallerVersion = $Result.CallerFileVersion
        $Strings.ReportCallerPublisher = $Result.CallerPublisher; $Strings.ReportPolicyName = $Result.PolicyName
        $Strings.ReportPolicyId = $Result.PolicyId; $Strings.ReportPolicyVersion = $Result.PolicyVersion
        $Strings.ReportStatus = $Result.Status; $Strings.ReportSigningScenario = $Result.SigningScenario
        $Strings.ReportRequestedLevel = $Result.RequestedSigningLevel; $Strings.ReportValidatedLevel = $Result.ValidatedSigningLevel
        $Strings.ReportSha256 = $Result.Sha256Hash; $Strings.ReportSha1 = $Result.Sha1Hash
        $Strings.ReportEventTime = $Result.TimeCreated; $Strings.ReportComputer = $Result.Computer
        $Strings.ReportActivityId = $Result.ActivityId; $Strings.ReportProvider = $Result.ProviderName
        $Strings.ReportRecordId = $Result.EventRecordId
    }
    $ErrorText = foreach ($Entry in $Rows.GetEnumerator()) { '{0}: {1}' -f $Entry.Key, $(if ([string]::IsNullOrWhiteSpace([string]$Entry.Value)) { $Strings.NotProvided } else { [string]$Entry.Value }) }
    $BlockedFileName = [string]$Result.FileName
    if ([string]::IsNullOrWhiteSpace($BlockedFileName) -and -not [string]::IsNullOrWhiteSpace([string]$Result.FilePath)) {
        $BlockedFileName = [string]$Result.FilePath -replace '^.*[\\/]', ''
    }
    if ([string]::IsNullOrWhiteSpace($BlockedFileName)) {
        $BlockedFileName = $Strings.UnknownFile
    }
    $ErrorHeading = $Strings.ReportExactErrorHeading -f $BlockedFileName
    $Nonce = [guid]::NewGuid().ToString('N')
    $FileName = 'review-{0}-{1}.html' -f ([long]$Result.EventRecordId), $Nonce
    $Path = Join-Path $ReviewDirectory $FileName
    $Html = @'
<!doctype html><html lang="{0}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{1}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#17202a}}main{{max-width:960px;margin:auto;padding:clamp(1rem,4vw,3rem)}}section{{background:#fff;border-radius:.6rem;padding:1.25rem;margin:1rem 0;box-shadow:0 1px 4px #0002}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f3f3;padding:1rem;user-select:text}}.button{{display:inline-block;border:0;background:#075ea8;color:#fff;padding:.75rem 1rem;border-radius:.3rem;text-decoration:none;font:inherit;font-weight:600;cursor:pointer}}.copy-row{{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}}#copy-status{{font-weight:600}}</style></head><body><main>
<h1>{1}</h1><p>{2}</p>
<section><h2>{3}</h2><p>{4}</p><ol><li>{5}</li><li>{6}</li><li>{7}</li></ol><a class="button" href="{8}" target="_blank" rel="noopener noreferrer">{9}</a></section>
<section><h2>{10}</h2><p>{11}</p><div class="copy-row"><button class="button" id="copy-details" type="button">{12}</button><span id="copy-status" role="status" aria-live="polite"></span><span id="copy-success" hidden>{14}</span><span id="copy-failure" hidden>{15}</span></div><pre id="error-details" aria-label="{10}" tabindex="0">{13}</pre></section></main>
<script>(function(){{'use strict';var button=document.getElementById('copy-details'),details=document.getElementById('error-details'),status=document.getElementById('copy-status'),success=document.getElementById('copy-success'),failure=document.getElementById('copy-failure');function fallback(text){{var area=document.createElement('textarea');area.value=text;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();area.setSelectionRange(0,area.value.length);var copied=false;try{{copied=document.execCommand('copy')}}catch(e){{copied=false}}finally{{document.body.removeChild(area)}}return copied}}function show(copied){{status.textContent=(copied?success:failure).textContent;if(!copied){{var selection=window.getSelection(),range=document.createRange();range.selectNodeContents(details);selection.removeAllRanges();selection.addRange(range);details.focus()}}}}button.addEventListener('click',function(){{var text=details.textContent;if(navigator.clipboard&&navigator.clipboard.writeText){{navigator.clipboard.writeText(text).then(function(){{show(true)}},function(){{show(fallback(text))}})}}else{{show(fallback(text))}}}})}}());</script></body></html>
'@ -f (& $Encode $Result.Language), (& $Encode $Strings.ReportTitle), (& $Encode $Strings.ReportExplanation),
        (& $Encode $Strings.ReportSupportHeading), (& $Encode $Strings.ReportSupportInstructions),
        (& $Encode $Strings.ReportSupportStepOne), (& $Encode $Strings.ReportSupportStepTwo),
        (& $Encode $Strings.ReportSupportStepThree), (& $Encode $SupportUri), (& $Encode $Strings.ReportOpenSupport),
        (& $Encode $ErrorHeading), (& $Encode $Strings.ReportCopyHint), (& $Encode $Strings.ReportCopyButton),
        (& $Encode ($ErrorText -join [Environment]::NewLine)), (& $Encode $Strings.ReportCopySuccess),
        (& $Encode $Strings.ReportCopyFailure)
    Set-Content -LiteralPath $Path -Value $Html -Encoding UTF8
    return [pscustomobject]@{ Path = $Path; ActivationUri = "$ReviewProtocol`://open/$([long]$Result.EventRecordId)/$Nonce" }
}

function Show-ToastNotification {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Details,
        [Parameter(Mandatory)][string]$Language,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Strings,
        [Parameter(Mandatory)][string]$ReviewPageUri,
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][string]$Group
    )

    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw "Toast WinRT projection requires Windows PowerShell 5.1 (Desktop edition). Current host: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion). Run WindowsPowerShell\v1.0\powershell.exe, not pwsh.exe."
    }
    if (-not [Environment]::UserInteractive) {
        throw 'Toast notifications require an interactive user session; do not run the renderer as SYSTEM or with a non-interactive logon type.'
    }

    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    }
    catch {
        throw "Windows toast WinRT types are unavailable. Windows 10/11 with the Windows notification platform is required. $($_.Exception.Message)"
    }

    $ToastEnabled = Get-OptionalRegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled
    if ($null -ne $ToastEnabled -and [int]$ToastEnabled -eq 0) {
        throw 'Toast notifications are disabled for the current user (HKCU PushNotifications\ToastEnabled is 0). Enable notifications in Windows Settings or through organizational policy.'
    }

    $Escape = { param([AllowNull()][string]$Value) [System.Security.SecurityElement]::Escape($(if ([string]::IsNullOrWhiteSpace($Value)) { $Strings.NotProvided } else { $Value })) }
    $DetailNodes = foreach ($Entry in $Details.GetEnumerator()) {
        '<text hint-style="captionSubtle" hint-wrap="true" hint-maxLines="1">{0}</text><text hint-style="body" hint-wrap="true" hint-maxLines="4">{1}</text>' -f
            (& $Escape ([string]$Entry.Key)), (& $Escape ([string]$Entry.Value))
    }

    $LocalizedActionLabel = if ($ActionLabel -eq 'Request Review') { $Strings.RequestReview } else { $ActionLabel }
    $EscapedReviewPageUri = & $Escape $ReviewPageUri
    $ActionXml = '<actions><action content="{0}" arguments="dismiss" activationType="system"/><action content="{1}" arguments="{2}" activationType="protocol" afterActivationBehavior="pendingUpdate"/></actions>' -f
        (& $Escape $Strings.Dismiss), (& $Escape $LocalizedActionLabel), $EscapedReviewPageUri

    $ImageXml = ''
    if (-not [string]::IsNullOrWhiteSpace($LogoPath)) {
        $LogoUri = $LogoPath
        if (-not [Uri]::IsWellFormedUriString($LogoUri, [UriKind]::Absolute)) {
            if (Test-Path -LiteralPath $LogoPath -PathType Leaf) {
                $LogoUri = ([Uri](Resolve-Path -LiteralPath $LogoPath).Path).AbsoluteUri
            }
            elseif ([string]::Equals($LogoPath, $DefaultLogoPath, [StringComparison]::OrdinalIgnoreCase)) {
                Write-WdacToastLog -Level WARN -Message "Default notification image '$DefaultLogoPath' is unavailable; continuing without an image."
                $LogoUri = $null
            }
            else {
                throw "The configured LogoPath '$LogoPath' does not exist and is not an absolute URI."
            }
        }
        if ($null -ne $LogoUri -and -not ($LogoUri.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase) -or $LogoUri.StartsWith('file://', [StringComparison]::OrdinalIgnoreCase))) {
            throw 'LogoPath must be a local file path, file URI, or HTTPS URI.'
        }
        if ($null -ne $LogoUri) {
            $ImageXml = '<image placement="appLogoOverride" src="{0}"/>' -f (& $Escape $LogoUri)
        }
    }

    # The BCP-47 lang attribute is part of the Microsoft ToastGeneric schema and
    # lets Windows apply the appropriate font and text shaping to this payload.
    $ToastXml = '<toast launch="{0}" activationType="protocol" afterActivationBehavior="pendingUpdate"><visual><binding template="ToastGeneric" lang="{1}">{2}<text hint-maxLines="1">{3}</text><text hint-maxLines="2">{4}</text><group><subgroup>{5}</subgroup></group></binding></visual>{6}</toast>' -f
        $EscapedReviewPageUri, (& $Escape $Language), $ImageXml, (& $Escape $Title), (& $Escape $Message), ($DetailNodes -join ''), $ActionXml

    $Document = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $Document.LoadXml($ToastXml)
    $Toast = [Windows.UI.Notifications.ToastNotification]::new($Document)
    $Toast.Tag = $Tag
    $Toast.Group = $Group
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
}

function Invoke-WdacToast {
    Write-WdacToastLog -Message "Invocation started with EventRecordId=$EventRecordId, Upgrade=$Upgrade, ResetInstallation=$ResetInstallation, Uninstall=$Uninstall, CleanupLogs=$CleanupLogs, AppId='$AppId', TaskName='$TaskName', InstallDirectory='$InstallDirectory', ExecutionPolicy='$ExecutionPolicy', WindowStyle='$WindowStyle'."
    if (-not [string]::IsNullOrWhiteSpace($ReviewActivationUri)) {
        Open-WdacReviewPage -ActivationUri $ReviewActivationUri
        return
    }
    if ($Upgrade -and $EventRecordId -ne 0) {
        throw 'Upgrade requires EventRecordId = 0 and cannot be combined with event processing.'
    }
    if ($ResetInstallation -and $EventRecordId -ne 0) {
        throw 'ResetInstallation cannot be combined with EventRecordId. Run reset as a separate elevated installation command.'
    }
    if ($Uninstall -and $ResetInstallation) {
        throw 'Uninstall and ResetInstallation are mutually exclusive.'
    }
    if ($Upgrade -and ($ResetInstallation -or $Uninstall)) {
        throw 'Upgrade is mutually exclusive with ResetInstallation and Uninstall.'
    }
    if ($PSBoundParameters.ContainsKey('UpgradeFromInstallDirectory') -and -not $Upgrade) {
        throw 'UpgradeFromInstallDirectory is valid only when Upgrade is supplied.'
    }
    if ($Uninstall -and $EventRecordId -ne 0) {
        throw 'Uninstall requires EventRecordId = 0 and cannot be combined with event processing.'
    }
    if ($CleanupLogs -and -not $Uninstall) {
        throw 'CleanupLogs is valid only when Uninstall is supplied.'
    }
    if ($LogMaintenance) {
        if ($EventRecordId -ne 0 -or $Upgrade -or $ResetInstallation -or $Uninstall -or $CleanupLogs) {
            throw 'LogMaintenance cannot be combined with installation, event processing, or uninstall options.'
        }
        Invoke-WdacToastLogMaintenance
        return
    }
    if ($EventRecordId -eq 0) {
        if ($Uninstall) {
            Uninstall-WdacToast
            return
        }
        # An explicit installation run must always copy the invoking source.
        # Merely checking that a file exists leaves an older, incompatible copy
        # in Program Files and causes parameter binding to fail before it can run.
        if ($ResetInstallation) { Reset-WdacToastInstallation }
        if ($Upgrade) { Upgrade-WdacToastInstallation } else { Install-WdacToast }
        [void](Test-WdacToastConfiguration)
        Write-WdacToastLog -Message "Installation completed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        Write-WdacToastLog -Level WARN -Message 'EventRecordId is 0, so this invocation only installed or validated the components; it did not attempt to display a toast. Pass a valid Event ID 3077 record ID to test rendering.'
        Write-Output "WDAC toast notification was installed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        return
    }

    if (-not (Test-WdacToastInstalled)) {
        throw 'The computer-level installation is incomplete. Run the deployment script from an elevated Windows PowerShell session to repair it.'
    }

    Ensure-CurrentUserAppIdentity
    [void](Test-WdacToastConfiguration -IncludeRendererChecks)
    Write-WdacToastLog -Message "Processing WDAC EventRecordId $EventRecordId."
    $XPath = "*[System[(EventID=3077) and (EventRecordID=$EventRecordId)]]"
    $Event = Get-WinEvent -LogName $LogName -FilterXPath $XPath -ErrorAction Stop |
        Select-Object -First 1

    if (-not $Event) {
        throw "WDAC Event ID 3077 with record ID $EventRecordId was not found."
    }

    $EventData = Get-NamedEventData -Event $Event
    $RawFilePath = Get-FirstEventValue -EventData $EventData -Names @('File Name', 'FileName', 'FilePath', 'ImageName', 'File')
    $RawProcessPath = Get-FirstEventValue -EventData $EventData -Names @('Process Name', 'ProcessName', 'ProcessPath', 'ParentProcessName')
    $FilePath = ConvertFrom-NtDevicePath -Path $RawFilePath
    $ProcessPath = ConvertFrom-NtDevicePath -Path $RawProcessPath
    $PolicyName = Get-FirstEventValue -EventData $EventData -Names @('PolicyName', 'Policy Name', 'PolicyFriendlyName')
    $PolicyId = Get-FirstEventValue -EventData $EventData -Names @('PolicyID', 'PolicyId', 'PolicyGUID')
    $PolicyVersion = Get-FirstEventValue -EventData $EventData -Names @('PolicyVersion', 'Policy Version')
    $Status = Get-FirstEventValue -EventData $EventData -Names @('Status', 'ErrorCode')
    $RequestedSigningLevel = Get-FirstEventValue -EventData $EventData -Names @('Requested Signing Level', 'RequestedSigningLevel')
    $ValidatedSigningLevel = Get-FirstEventValue -EventData $EventData -Names @('Validated Signing Level', 'ValidatedSigningLevel')
    $SigningScenario = Get-FirstEventValue -EventData $EventData -Names @('SI Signing Scenario', 'SigningScenario')
    $Sha256Hash = Get-FirstEventValue -EventData $EventData -Names @('SHA256 Hash', 'SHA256Hash', 'SHA256 Flat Hash', 'SHA256FlatHash')
    $Sha1Hash = Get-FirstEventValue -EventData $EventData -Names @('SHA1 Hash', 'SHA1Hash', 'SHA1 Flat Hash', 'SHA1FlatHash')
    $FileDetails = Get-BlockedFileDetails -Path $FilePath
    $CallerDetails = Get-BlockedFileDetails -Path $ProcessPath
    $Localization = Get-WdacToastStrings
    Write-WdacToastLog -Message "Selected toast language '$($Localization.Language)' from the Windows user language preferences."

    $FileName = if ([string]::IsNullOrWhiteSpace($FilePath)) {
        $Localization.Strings.UnknownFile
    }
    else {
        $FilePath -replace '^.*[\\/]', ''
    }
    $ProcessFileName = if ([string]::IsNullOrWhiteSpace($ProcessPath)) {
        $Localization.Strings.UnknownFile
    }
    else {
        $ProcessPath -replace '^.*[\\/]', ''
    }

    $Result = [ordered]@{
        EventId = $Event.Id
        Language = $Localization.Language
        EventRecordId = $Event.RecordId
        TimeCreated = $Event.TimeCreated
        Computer = $Event.MachineName
        FileName = $FileName
        FilePath = $FilePath
        ProcessPath = $ProcessPath
        RawFilePath = $RawFilePath
        RawProcessPath = $RawProcessPath
        FileDescription = $FileDetails.Description
        ProductName = $FileDetails.Product
        FileVersion = $FileDetails.Version
        Publisher = $FileDetails.Publisher
        CallerDescription = $CallerDetails.Description
        CallerProductName = $CallerDetails.Product
        CallerFileVersion = $CallerDetails.Version
        CallerPublisher = $CallerDetails.Publisher
        PolicyName = $PolicyName
        PolicyId = $PolicyId
        PolicyVersion = $PolicyVersion
        Status = $Status
        RequestedSigningLevel = $RequestedSigningLevel
        ValidatedSigningLevel = $ValidatedSigningLevel
        SigningScenario = $SigningScenario
        Sha256Hash = $Sha256Hash
        Sha1Hash = $Sha1Hash
        ActivityId = $Event.ActivityId
        ProviderName = $Event.ProviderName
        RawEventData = $EventData
        RawEventXml = $Event.ToXml()
    }

    $LogFile = Join-Path $LogDirectory ('WDAC-{0}-{1}.json' -f $Event.TimeCreated.ToString('yyyyMMdd-HHmmss'), $Event.RecordId)
    $Result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LogFile -Encoding UTF8
    Write-WdacToastLog -Message "Wrote event diagnostics to '$LogFile'. Parsed FilePath='$FilePath'; ProcessPath='$ProcessPath'; PolicyName='$PolicyName'; PolicyId='$PolicyId'; Status='$Status'."
    $ReviewPage = New-WdacReviewPage -Result $Result -Strings $Localization.Strings -SupportUri $SupportUri
    Write-WdacToastLog -Message "Wrote local review report to '$($ReviewPage.Path)'."

    $NotificationKeySource = if ([string]::IsNullOrWhiteSpace($FilePath)) { "event-$($Event.RecordId)" } else { $FilePath.ToLowerInvariant() }
    $KeyHash = Get-StableHash -Text $NotificationKeySource
    $State = Get-NotificationState

    if ($DuplicateCooldownMinutes -gt 0 -and $State.ContainsKey($KeyHash)) {
        $Elapsed = $Event.TimeCreated - [datetime]$State[$KeyHash]
        if ($Elapsed.TotalMinutes -lt $DuplicateCooldownMinutes) {
            Write-WdacToastLog -Level WARN -Message "Duplicate toast suppressed for '$FilePath'; elapsed $([math]::Round($Elapsed.TotalMinutes, 2)) minute(s), cooldown $DuplicateCooldownMinutes minute(s). The event JSON was still written."
            exit 0
        }
    }

    $PolicyDisplay = if ([string]::IsNullOrWhiteSpace($PolicyVersion)) {
        $PolicyName
    }
    elseif ([string]::IsNullOrWhiteSpace($PolicyName)) {
        $PolicyVersion
    }
    else {
        $Localization.Strings.VersionFormat -f $PolicyName, $PolicyVersion
    }
    $ToastDetails = [ordered]@{
        ('{0} {1}' -f $Localization.Strings.BlockedAppPath, $FileName) = $FilePath
        ('{0} {1}' -f $Localization.Strings.CalledByAppPath, $ProcessFileName) = $ProcessPath
        ($Localization.Strings.BlockedByPolicy) = $PolicyDisplay
    }
    $ToastTag = "wdac-$($Event.RecordId)"
    $ToastGroup = 'wdac-blocks'
    Write-WdacToastLog -Message "Submitting toast to the Windows notification platform with AppId '$AppId'."
    Show-ToastNotification `
        -Title $Localization.Strings.Title `
        -Message $Localization.Strings.Message `
        -Details $ToastDetails `
        -Language $Localization.Language `
        -Strings $Localization.Strings `
        -ReviewPageUri $ReviewPage.ActivationUri `
        -Tag $ToastTag `
        -Group $ToastGroup
    Write-WdacToastLog -Message 'The Windows notification platform accepted the toast. Windows can still suppress its presentation because of Do Not Disturb/Focus Assist or per-app notification settings.'

    $State[$KeyHash] = $Event.TimeCreated
    $Cutoff = (Get-Date).AddDays(-7)
    foreach ($Key in @($State.Keys)) {
        if ([datetime]$State[$Key] -lt $Cutoff) { $State.Remove($Key) }
    }
    Save-NotificationState -State $State
    Write-WdacToastLog -Message "Displayed notification for WDAC EventRecordId $EventRecordId."
}

try {
    Invoke-WdacToast
}
catch {
    $Failure = $_
    $Context = if ($EventRecordId -eq 0) { 'installation' } else { "EventRecordId $EventRecordId" }
    $Details = "$Context failed: $($Failure.Exception.Message)"
    if ($Failure.InvocationInfo -and -not [string]::IsNullOrWhiteSpace($Failure.InvocationInfo.PositionMessage)) {
        $Details += " | $($Failure.InvocationInfo.PositionMessage -replace '[\r\n]+', ' ')"
    }
    # A cleanup uninstall must not recreate the state/log directory it just
    # removed. Its warnings and terminating error remain visible to the caller.
    if (-not ($Uninstall -and $CleanupLogs)) {
        Write-WdacToastLog -Level ERROR -Message $Details
    }
    Write-Error -ErrorRecord $Failure
    exit 1
}
