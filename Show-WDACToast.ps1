[CmdletBinding()]
param(
    [ValidateRange(0, [long]::MaxValue)]
    [long]$EventRecordId = 0,

    [ValidateRange(0, 1440)]
    [int]$DuplicateCooldownMinutes = 5,

    [ValidatePattern('^https://')]
    [string]$SupportUri = 'https://support.example.com/wdac-review',

    [ValidateNotNullOrEmpty()]
    [string]$AppId = 'Company.WDACToast',

    [ValidateNotNullOrEmpty()]
    [string]$DisplayName = 'Company Security',

    [ValidateNotNullOrEmpty()]
    [string]$InstallDirectory = "$env:ProgramFiles\Company\WDACToast",

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'Company WDAC Block Notification'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
$StateDirectory = Join-Path $env:ProgramData 'Company\WDACToast'
$LogDirectory = Join-Path $StateDirectory 'Logs'
$StateFile = Join-Path $StateDirectory 'NotificationState.json'
$InstalledScript = Join-Path $InstallDirectory 'Show-WDACToast.ps1'

function Write-WdacToastLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $Entry = '{0} [{1}] [PID:{2}] {3}' -f (Get-Date).ToUniversalTime().ToString('o'), $Level, $PID, $Message
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

function Test-WdacToastInstalled {
    $AppIdRegistryPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
    return (
        (Test-Path -LiteralPath $InstalledScript) -and
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
    if (-not [string]::Equals($SourceScript, $InstalledScript, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $SourceScript -Destination $InstalledScript -Force
    }

    $AppIdRegistryPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
    New-Item -Path $AppIdRegistryPath -Force | Out-Null
    New-ItemProperty -Path $AppIdRegistryPath -Name DisplayName -Value $DisplayName -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $AppIdRegistryPath -Name ShowInSettings -Value 1 -PropertyType DWord -Force | Out-Null

    $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $EscapedScript = [System.Security.SecurityElement]::Escape($InstalledScript)
    $EscapedUserSid = [System.Security.SecurityElement]::Escape($CurrentIdentity.User.Value)
    $EscapedAppId = [System.Security.SecurityElement]::Escape($AppId)
    $EscapedDisplayName = [System.Security.SecurityElement]::Escape($DisplayName)
    $EscapedSupportUri = [System.Security.SecurityElement]::Escape($SupportUri)
    $EscapedInstallDirectory = [System.Security.SecurityElement]::Escape($InstallDirectory)
    $EscapedTaskName = [System.Security.SecurityElement]::Escape($TaskName)
    $TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Displays an interactive notification for new WDAC Event ID 3077 records.</Description></RegistrationInfo>
  <Triggers><EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;&lt;Select Path="Microsoft-Windows-CodeIntegrity/Operational"&gt;*[System[EventID=3077]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription><ValueQueries><Value name="EventRecordID">Event/System/EventRecordID</Value></ValueQueries></EventTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$EscapedUserSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File &quot;$EscapedScript&quot; -EventRecordId &quot;`$(EventRecordID)&quot; -AppId &quot;$EscapedAppId&quot; -DisplayName &quot;$EscapedDisplayName&quot; -SupportUri &quot;$EscapedSupportUri&quot; -InstallDirectory &quot;$EscapedInstallDirectory&quot; -TaskName &quot;$EscapedTaskName&quot;</Arguments></Exec></Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $TaskName -Xml $TaskXml -Force | Out-Null
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

function Limit-Text {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text,

        [ValidateRange(4, 1000)]
        [int]$MaximumLength = 140
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return 'Unknown' }
    if ($Text.Length -le $MaximumLength) { return $Text }
    return $Text.Substring(0, $MaximumLength - 3) + '...'
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
        '<text>{0}</text>' -f [System.Security.SecurityElement]::Escape($Line)
    }
    $ActionXml = if ([string]::IsNullOrWhiteSpace($SupportUri)) {
        ''
    }
    else {
        '<actions><action content="Request review" arguments="{0}" activationType="protocol"/></actions>' -f
            [System.Security.SecurityElement]::Escape($SupportUri)
    }

    $ToastXml = '<toast><visual><binding template="ToastGeneric"><text>{0}</text>{1}</binding></visual>{2}</toast>' -f
        $EscapedTitle, ($TextNodes -join ''), $ActionXml

    $Document = [Windows.Data.Xml.Dom.XmlDocument]::new()
    $Document.LoadXml($ToastXml)
    $Toast = [Windows.UI.Notifications.ToastNotification]::new($Document)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
}

function Invoke-WdacToast {
    if (-not (Test-WdacToastInstalled)) {
        Write-WdacToastLog -Message 'Installation is incomplete; repairing the installed script, application identity, and Scheduled Task.'
        Install-WdacToast
    }

    if ($EventRecordId -eq 0) {
        Write-WdacToastLog -Message "Installation completed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        Write-Output "WDAC toast notification was installed for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        return
    }

    Write-WdacToastLog -Message "Processing WDAC EventRecordId $EventRecordId."
    $XPath = "*[System[(EventID=3077) and (EventRecordID=$EventRecordId)]]"
    $Event = Get-WinEvent -LogName $LogName -FilterXPath $XPath -ErrorAction Stop |
        Select-Object -First 1

    if (-not $Event) {
        throw "WDAC Event ID 3077 with record ID $EventRecordId was not found."
    }

    $EventData = Get-NamedEventData -Event $Event
    $FilePath = Get-FirstEventValue -EventData $EventData -Names @('File Name', 'FileName', 'FilePath', 'ImageName', 'File')
    $ProcessPath = Get-FirstEventValue -EventData $EventData -Names @('Process Name', 'ProcessName', 'ProcessPath', 'ParentProcessName')
    $PolicyName = Get-FirstEventValue -EventData $EventData -Names @('PolicyName', 'Policy Name', 'PolicyFriendlyName')
    $PolicyId = Get-FirstEventValue -EventData $EventData -Names @('PolicyID', 'PolicyId', 'PolicyGUID')
    $Status = Get-FirstEventValue -EventData $EventData -Names @('Status', 'ErrorCode')

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
        PolicyName = $PolicyName
        PolicyId = $PolicyId
        Status = $Status
        ActivityId = $Event.ActivityId
        ProviderName = $Event.ProviderName
        RawEventData = $EventData
        RawEventXml = $Event.ToXml()
    }

    $LogFile = Join-Path $LogDirectory ('WDAC-{0}-{1}.json' -f $Event.TimeCreated.ToString('yyyyMMdd-HHmmss'), $Event.RecordId)
    $Result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LogFile -Encoding UTF8

    $NotificationKeySource = if ([string]::IsNullOrWhiteSpace($FilePath)) { "event-$($Event.RecordId)" } else { $FilePath.ToLowerInvariant() }
    $KeyHash = Get-StableHash -Text $NotificationKeySource
    $State = Get-NotificationState

    if ($DuplicateCooldownMinutes -gt 0 -and $State.ContainsKey($KeyHash)) {
        $Elapsed = $Event.TimeCreated - [datetime]$State[$KeyHash]
        if ($Elapsed.TotalMinutes -lt $DuplicateCooldownMinutes) {
            Write-Verbose "Duplicate toast suppressed for $FilePath"
            exit 0
        }
    }

    $ToastLines = @(
        "File: $(Limit-Text -Text $FileName -MaximumLength 80)"
        "Location: $(Limit-Text -Text $FilePath -MaximumLength 130)"
    )
    if (-not [string]::IsNullOrWhiteSpace($ProcessPath)) { $ToastLines += "Started by: $(Limit-Text -Text $ProcessPath -MaximumLength 100)" }
    if (-not [string]::IsNullOrWhiteSpace($PolicyName)) { $ToastLines += "Policy: $(Limit-Text -Text $PolicyName -MaximumLength 80)" }
    elseif (-not [string]::IsNullOrWhiteSpace($PolicyId)) { $ToastLines += "Policy: $(Limit-Text -Text $PolicyId -MaximumLength 80)" }
    $ToastLines += "Reference: WDAC-$($Event.RecordId)"

    Show-ToastNotification -Title 'Application blocked by security policy' -Lines $ToastLines

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
