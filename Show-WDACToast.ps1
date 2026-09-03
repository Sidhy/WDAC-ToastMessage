[CmdletBinding()]
param(
    [ValidateRange(0, [long]::MaxValue)]
    [long]$EventRecordId = 0,

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
    [string]$TaskName = 'Company WDAC Block Notification'
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
    DuplicateCooldownMinutes = 5
}
$ScriptDirectory = Split-Path -Parent $PSCommandPath
$ConfigurationFile = Join-Path $ScriptDirectory 'WDACToast.json'
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
if ([string]::IsNullOrWhiteSpace([string]$SupportUri) -or $SupportUri -notmatch '^https://') {
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

$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
$StateDirectory = Join-Path $env:ProgramData 'Company\WDACToast'
$LogDirectory = Join-Path $StateDirectory 'Logs'
$StateFile = Join-Path $StateDirectory 'NotificationState.json'
$InstalledScript = Join-Path $InstallDirectory 'Show-WDACToast.ps1'
$DefaultLogoPath = Join-Path $InstallDirectory 'MicrosoftDefenderShield.png'

function Get-InteractiveUserIdentity {
    # An installer started with alternate administrator credentials has a
    # different Windows identity from the user who owns the desktop. Locate the
    # Explorer process in this session so the task and HKCU-equivalent
    # registration are assigned to the user who can actually receive the toast.
    $CurrentProcess = Get-Process -Id $PID
    $Explorer = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $CurrentProcess.SessionId } |
        Select-Object -First 1)
    if ($Explorer.Count -gt 0) {
        $Owner = Invoke-CimMethod -InputObject $Explorer[0] -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($null -ne $Owner -and $Owner.ReturnValue -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$Owner.User)) {
            $AccountName = if ([string]::IsNullOrWhiteSpace([string]$Owner.Domain)) { [string]$Owner.User } else { "$($Owner.Domain)\$($Owner.User)" }
            $Sid = ([System.Security.Principal.NTAccount]$AccountName).Translate([System.Security.Principal.SecurityIdentifier])
            return [pscustomobject]@{ Name = $AccountName; Sid = $Sid.Value }
        }
    }

    throw 'No logged-on Explorer user was found in this Windows session. Installation requires an interactive user so the task is never registered to an administrator or service account by mistake.'
}

function Initialize-WdacToastStateDirectory {
    New-Item -Path $StateDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null

    # Use a well-known SID rather than a localized account name. Modify applies
    # to this directory and descendants, allowing every interactive account to
    # maintain shared duplicate state and diagnostics after an elevated install.
    $AuthenticatedUsers = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    foreach ($Directory in @($StateDirectory, $LogDirectory)) {
        $Acl = Get-Acl -LiteralPath $Directory
        $Rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $AuthenticatedUsers,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $Acl.SetAccessRule($Rule)
        Set-Acl -LiteralPath $Directory -AclObject $Acl
    }
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
        Add-Content -LiteralPath (Join-Path $LogDirectory 'WDACToast.log') -Value $Entry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Logging must never hide the original failure. The task history still
        # receives this fallback when ProgramData cannot be written.
        Write-Warning "$Entry (file logging failed: $($_.Exception.Message))"
    }
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

function Test-WdacToastConfiguration {
    [CmdletBinding()]
    param([switch]$IncludeRendererChecks)

    Write-WdacToastLog -Message "Starting configuration checks. Host=$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion); User=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name); Interactive=$([Environment]::UserInteractive)."
    $Results = [System.Collections.Generic.List[bool]]::new()
    $TaskUser = Get-InteractiveUserIdentity
    $AppIdRegistryPath = "Registry::HKEY_USERS\$($TaskUser.Sid)\Software\Classes\AppUserModelId\$AppId"
    $RegistryValues = Get-ItemProperty -LiteralPath $AppIdRegistryPath -ErrorAction SilentlyContinue
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    $Results.Add((Write-ConfigurationCheck -Name 'Installed script' -Passed (Test-Path -LiteralPath $InstalledScript -PathType Leaf) -SuccessMessage $InstalledScript -FailureMessage "The installed script is missing at '$InstalledScript'."))
    $Results.Add((Write-ConfigurationCheck -Name 'Application identity' -Passed ($null -ne $RegistryValues) -SuccessMessage $AppIdRegistryPath -FailureMessage "The per-user AppUserModelID '$AppId' is not registered at '$AppIdRegistryPath'."))
    if ($null -ne $RegistryValues) {
        $RegisteredDisplayName = if ($RegistryValues.PSObject.Properties['DisplayName']) { [string]$RegistryValues.DisplayName } else { $null }
        $RegisteredShowInSettings = if ($RegistryValues.PSObject.Properties['ShowInSettings']) { $RegistryValues.ShowInSettings } else { $null }
        $Results.Add((Write-ConfigurationCheck -Name 'Application display name' -Passed ($RegisteredDisplayName -eq $DisplayName) -SuccessMessage "DisplayName is '$DisplayName'." -FailureMessage "Expected DisplayName '$DisplayName', found '$RegisteredDisplayName'."))
        $Results.Add((Write-ConfigurationCheck -Name 'Application notification settings' -Passed ($null -ne $RegisteredShowInSettings -and [int]$RegisteredShowInSettings -eq 1) -SuccessMessage 'ShowInSettings is enabled.' -FailureMessage "ShowInSettings should be 1, found '$RegisteredShowInSettings'."))
    }

    $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task' -Passed ($null -ne $Task) -SuccessMessage "Task '$TaskName' exists." -FailureMessage "Task '$TaskName' does not exist for this user."))
    if ($null -ne $Task) {
        $ExpectedSid = $TaskUser.Sid
        $TaskAction = @($Task.Actions) | Select-Object -First 1
        $TaskExecute = if ($null -ne $TaskAction) { [string]$TaskAction.Execute } else { '' }
        $TaskArguments = if ($null -ne $TaskAction) { [string]$TaskAction.Arguments } else { '' }
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task state' -Passed ($Task.State -ne 'Disabled') -SuccessMessage "Task state is $($Task.State)." -FailureMessage 'The task is disabled.'))
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task user' -Passed ($Task.Principal.UserId -eq $ExpectedSid -and $Task.Principal.LogonType -eq 'InteractiveToken') -SuccessMessage "Task uses InteractiveToken for SID $ExpectedSid." -FailureMessage "Expected InteractiveToken for SID $ExpectedSid; found LogonType '$($Task.Principal.LogonType)' and UserId '$($Task.Principal.UserId)'."))
        $ActionIsValid = $null -ne $TaskAction -and $TaskExecute -like '*\WindowsPowerShell\v1.0\powershell.exe' -and $TaskArguments -like "*${InstalledScript}*" -and $TaskArguments -like '*-ExecutionPolicy AllSigned*'
        $Results.Add((Write-ConfigurationCheck -Name 'Scheduled Task action' -Passed $ActionIsValid -SuccessMessage "Task launches Windows PowerShell 5.1 with AllSigned and '$InstalledScript'." -FailureMessage "The task action is unexpected. Execute='$TaskExecute'; Arguments='$TaskArguments'."))
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

        $ToastEnabled = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled -ErrorAction SilentlyContinue
        $Results.Add((Write-ConfigurationCheck -Name 'User notification preference' -Passed ($null -eq $ToastEnabled -or [int]$ToastEnabled -ne 0) -SuccessMessage "ToastEnabled is not disabled (value: '$ToastEnabled')." -FailureMessage 'HKCU PushNotifications\ToastEnabled is 0. Enable notifications for this user.'))
        $PolicyDisabled = Get-ItemPropertyValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name DisableNotificationCenter -ErrorAction SilentlyContinue
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
    $AppIdRegistryPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
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
        (Test-Path -LiteralPath $AppIdRegistryPath) -and
        ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue))
    )
}

function Install-WdacToast {
    $SourceScript = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($SourceScript) -or -not (Test-Path -LiteralPath $SourceScript)) {
        throw 'The script must be run from a saved .ps1 file before it can install itself.'
    }

    New-Item -Path $InstallDirectory -ItemType Directory -Force | Out-Null
    Initialize-WdacToastStateDirectory
    if (-not [string]::Equals($SourceScript, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $SourceScript -Destination $InstalledScript -Force
    }
    $InstalledConfigurationFile = Join-Path $InstallDirectory 'WDACToast.json'
    if (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf) {
        if (-not [string]::Equals($ConfigurationFile, $InstalledConfigurationFile, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $ConfigurationFile -Destination $InstalledConfigurationFile -Force
        }
        Write-WdacToastLog -Message "Installed configuration is present at '$InstalledConfigurationFile'."
    }
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

    $TaskUser = Get-InteractiveUserIdentity
    $AppIdRegistryPath = "Registry::HKEY_USERS\$($TaskUser.Sid)\Software\Classes\AppUserModelId\$AppId"
    New-Item -Path $AppIdRegistryPath -Force | Out-Null
    New-ItemProperty -Path $AppIdRegistryPath -Name DisplayName -Value $DisplayName -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $AppIdRegistryPath -Name ShowInSettings -Value 1 -PropertyType DWord -Force | Out-Null
    Write-WdacToastLog -Message "Registered AppUserModelID '$AppId' for interactive user '$($TaskUser.Name)' with display name '$DisplayName'."

    $EscapedScript = [System.Security.SecurityElement]::Escape($InstalledScript)
    $EscapedUserSid = [System.Security.SecurityElement]::Escape($TaskUser.Sid)
    $TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Displays an interactive notification for new WDAC Event ID 3077 records.</Description></RegistrationInfo>
  <Triggers><EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;&lt;Select Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;*[System[EventID=3077]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription><ValueQueries><Value name="EventRecordID">Event/System/EventRecordID</Value></ValueQueries></EventTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$EscapedUserSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File &quot;$EscapedScript&quot; -EventRecordId &quot;`$(EventRecordID)&quot;</Arguments></Exec></Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $TaskName -Xml $TaskXml -Force | Out-Null
    Write-WdacToastLog -Message "Registered Scheduled Task '$TaskName' with InteractiveToken and least privilege for interactive user '$($TaskUser.Name)' (SID $($TaskUser.Sid))."
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

function Show-ToastNotification {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Lines
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

    $ToastEnabled = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled -ErrorAction SilentlyContinue
    if ($null -ne $ToastEnabled -and [int]$ToastEnabled -eq 0) {
        throw 'Toast notifications are disabled for the current user (HKCU PushNotifications\ToastEnabled is 0). Enable notifications in Windows Settings or through organizational policy.'
    }

    $EscapedTitle = [System.Security.SecurityElement]::Escape($Title)
    $TextNodes = foreach ($Line in $Lines) {
        # Pass complete values to wrapped adaptive text nodes. Applying a
        # character limit here permanently removes review details.
        '<text hint-wrap="true">{0}</text>' -f [System.Security.SecurityElement]::Escape($Line)
    }
    $ActionXml = if ([string]::IsNullOrWhiteSpace($SupportUri)) {
        ''
    }
    else {
        '<actions><action content="{0}" arguments="{1}" activationType="protocol"/></actions>' -f
            [System.Security.SecurityElement]::Escape($ActionLabel), [System.Security.SecurityElement]::Escape($SupportUri)
    }

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
            $ImageXml = '<image placement="appLogoOverride" src="{0}"/>' -f [System.Security.SecurityElement]::Escape($LogoUri)
        }
    }

    $ToastXml = '<toast><visual><binding template="ToastGeneric">{0}<text>{1}</text>{2}</binding></visual>{3}</toast>' -f
        $ImageXml, $EscapedTitle, ($TextNodes -join ''), $ActionXml

    $Document = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $Document.LoadXml($ToastXml)
    $Toast = [Windows.UI.Notifications.ToastNotification]::new($Document)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
}

function Invoke-WdacToast {
    Write-WdacToastLog -Message "Invocation started with EventRecordId=$EventRecordId, AppId='$AppId', TaskName='$TaskName', InstallDirectory='$InstallDirectory'."
    if ($EventRecordId -eq 0) {
        # An explicit installation run must always copy the invoking source.
        # Merely checking that a file exists leaves an older, incompatible copy
        # in Program Files and causes parameter binding to fail before it can run.
        Install-WdacToast
        [void](Test-WdacToastConfiguration)
        Write-WdacToastLog -Message "Installation completed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        Write-WdacToastLog -Level WARN -Message 'EventRecordId is 0, so this invocation only installed or validated the components; it did not attempt to display a toast. Pass a valid Event ID 3077 record ID to test rendering.'
        Write-Output "WDAC toast notification was installed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        return
    }

    if (-not (Test-WdacToastInstalled)) {
        Write-WdacToastLog -Level WARN -Message 'Installation is incomplete; repairing the installed script, application identity, and Scheduled Task.'
        Install-WdacToast
    }

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
    $Status = Get-FirstEventValue -EventData $EventData -Names @('Status', 'ErrorCode')
    $RequestedSigningLevel = Get-FirstEventValue -EventData $EventData -Names @('Requested Signing Level', 'RequestedSigningLevel')
    $ValidatedSigningLevel = Get-FirstEventValue -EventData $EventData -Names @('Validated Signing Level', 'ValidatedSigningLevel')
    $SigningScenario = Get-FirstEventValue -EventData $EventData -Names @('SI Signing Scenario', 'SigningScenario')
    $Sha256Hash = Get-FirstEventValue -EventData $EventData -Names @('SHA256 Hash', 'SHA256Hash', 'SHA256 Flat Hash', 'SHA256FlatHash')
    $Sha1Hash = Get-FirstEventValue -EventData $EventData -Names @('SHA1 Hash', 'SHA1Hash', 'SHA1 Flat Hash', 'SHA1FlatHash')
    $FileDetails = Get-BlockedFileDetails -Path $FilePath
    $CallerDetails = Get-BlockedFileDetails -Path $ProcessPath

    $FileName = if ([string]::IsNullOrWhiteSpace($FilePath)) {
        'Unknown file'
    }
    else {
        $FilePath -replace '^.*[\\/]', ''
    }

    $Result = [ordered]@{
        EventId = $Event.Id
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

    $ToastLines = @(
        "FilePath: $FilePath"
        "ProcessPath: $ProcessPath"
        "PolicyName: $PolicyName"
        "PolicyId: $PolicyId"
        'Security reason: This application is not approved by your organization or could put this device and company data at risk.'
    )
    if (-not [string]::IsNullOrWhiteSpace($CallerDetails.Description)) { $ToastLines += "Calling application: $($CallerDetails.Description)" }
    if (-not [string]::IsNullOrWhiteSpace($CallerDetails.Product)) { $ToastLines += "Caller product: $($CallerDetails.Product)" }
    if (-not [string]::IsNullOrWhiteSpace($CallerDetails.Publisher)) { $ToastLines += "Caller publisher: $($CallerDetails.Publisher)" }
    if (-not [string]::IsNullOrWhiteSpace($CallerDetails.Version)) { $ToastLines += "Caller version: $($CallerDetails.Version)" }
    if (-not [string]::IsNullOrWhiteSpace($FileDetails.Description)) { $ToastLines += "Description: $($FileDetails.Description)" }
    if (-not [string]::IsNullOrWhiteSpace($FileDetails.Product)) { $ToastLines += "Product: $($FileDetails.Product)" }
    if (-not [string]::IsNullOrWhiteSpace($FileDetails.Publisher)) { $ToastLines += "Publisher: $($FileDetails.Publisher)" }
    if (-not [string]::IsNullOrWhiteSpace($FileDetails.Version)) { $ToastLines += "Version: $($FileDetails.Version)" }
    if (-not [string]::IsNullOrWhiteSpace($Status)) { $ToastLines += "Status: $Status" }
    if (-not [string]::IsNullOrWhiteSpace($ValidatedSigningLevel)) { $ToastLines += "Validated signing level: $ValidatedSigningLevel" }
    $ToastLines += "Reference: WDAC-$($Event.RecordId)"

    Write-WdacToastLog -Message "Submitting toast to the Windows notification platform with AppId '$AppId' and $($ToastLines.Count) body line(s)."
    Show-ToastNotification -Title 'Application blocked by security policy' -Lines $ToastLines
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
    Write-WdacToastLog -Level ERROR -Message $Details
    Write-Error -ErrorRecord $Failure
    exit 1
}
