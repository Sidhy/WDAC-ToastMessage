from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
collector = (ROOT / "Show-WDACToast.ps1").read_text(encoding="utf-8")
configuration = (ROOT / "WDACToast.json").read_text(encoding="utf-8")

required_collector_fragments = [
    "[long]$EventRecordId",
    "EventID=3077",
    "EventRecordID=$EventRecordId",
    "'File Name'",
    "'Process Name'",
    "$Event.ToXml()",
    "SecurityElement]::Escape",
    "BitConverter]::ToString",
    "function Test-WdacToastInstalled",
    "$InstalledScriptIsCurrent = $SourceHash -eq $InstalledHash",
    "The installed script differs from the deployment source and will be upgraded",
    "function Install-WdacToast",
    "function Get-InteractiveUserIdentity",
    "Get-CimInstance -ClassName Win32_Process",
    "No logged-on Explorer user was found",
    "function Initialize-WdacToastStateDirectory",
    "[System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')",
    "[System.Security.AccessControl.FileSystemRights]::Modify",
    'Registry::HKEY_USERS\\$($TaskUser.Sid)',
    "$InstalledCommand.Parameters.ContainsKey('EventRecordId')",
    "An explicit installation run must always copy the invoking source",
    "if (-not (Test-WdacToastInstalled))",
    "$Node.GetAttribute('Name')",
    "$Node.InnerText",
    "function Write-WdacToastLog",
    "function Test-WdacToastConfiguration",
    "Configuration check [$Name] failed",
    "[Parameter(Mandatory)][AllowEmptyString()][string]$SuccessMessage",
    "[Parameter(Mandatory)][AllowEmptyString()][string]$FailureMessage",
    "EventRecordId is 0",
    "WpnUserService*",
    "DisableNotificationCenter",
    "Submitting toast to the Windows notification platform",
    "$PSVersionTable.PSEdition -ne 'Desktop'",
    "[Environment]::UserInteractive",
    "PushNotifications' -Name ToastEnabled",
    "Windows toast WinRT types are unavailable",
    "function ConvertFrom-NtDevicePath",
    "QueryDosDevice",
    "function Get-BlockedFileDetails",
    "FileDescription = $FileDetails.Description",
    "RawFilePath = $RawFilePath",
    "placement=\"appLogoOverride\"",
    "MicrosoftDefenderShield.png",
    "[string]$ActionLabel = 'Request Review'",
    "$ConfigurationFile = Join-Path $ScriptDirectory 'WDACToast.json'",
    "$DefaultLogoPath = Join-Path $InstallDirectory 'MicrosoftDefenderShield.png'",
    "Copy-Item -LiteralPath $ConfigurationFile -Destination $InstalledConfigurationFile -Force",
    "SecurityHealthSystray.exe",
    "CallerDescription = $CallerDetails.Description",
    "RequestedSigningLevel = $RequestedSigningLevel",
    "Sha256Hash = $Sha256Hash",
    "Security reason: This application is not approved by your organization",
    '"FilePath: $FilePath"',
    '"ProcessPath: $ProcessPath"',
    '"PolicyName: $PolicyName"',
    '"PolicyId: $PolicyId"',
    '<text hint-wrap="true">{0}</text>',
    "Write-Error -ErrorRecord $Failure",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "$env\\:ProgramData" not in collector
assert "$Node.'#text'" not in collector
assert "ExecutionPolicy Bypass" not in collector
assert "View more details" not in collector
assert '"File: $(Limit-Text' not in collector
assert '"Location: $(Limit-Text' not in collector
assert '"Requested by: $(Limit-Text' not in collector
assert '"Caller location: $(Limit-Text' not in collector
assert "function Limit-Text" not in collector
assert "MaximumLength" not in collector
assert "<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>" in collector
assert "Event/System/EventRecordID" in collector
assert '`$(EventRecordID)' in collector
assert "catch {\n    $Failure = $_" in collector
assert "exit 1" in collector
install_branch = collector.index("if ($EventRecordId -eq 0) {")
repair_branch = collector.index("if (-not (Test-WdacToastInstalled))", install_branch)
assert install_branch < repair_branch, "explicit installation must run before event-only repair"
assert "if ($EventRecordId -eq 0) {\n        # An explicit installation run" in collector
assert not (ROOT / "Install-WDACToast.ps1").exists()
assert [path.name for path in ROOT.glob("*.ps1")] == ["Show-WDACToast.ps1"]

match = re.search(r'\$TaskXml = @"\n(.*?)\n"@', collector, re.DOTALL)
assert match, "scheduled-task XML template was not found"
xml = match.group(1)
xml = xml.replace("$EscapedUserSid", "S-1-5-21-1")
xml = xml.replace("$EscapedScript", r"C:\Program Files\Company\WDACToast\Show-WDACToast.ps1")
xml = xml.replace("$EscapedAppId", "Company.WDACToast")
xml = xml.replace("$EscapedDisplayName", "Company Security")
xml = xml.replace("$EscapedLogoPath", r"C:\Branding\security.png")
xml = xml.replace("$EscapedSupportUri", "https://support.example.test/details")
xml = xml.replace("$EscapedInstallDirectory", r"C:\Program Files\Company\WDACToast")
xml = xml.replace("$EscapedTaskName", "Company WDAC Block Notification")
xml = xml.replace("`$(EventRecordID)", "123")
ET.fromstring(xml)

parsed_configuration = json.loads(configuration)
assert parsed_configuration["ActionLabel"] == "Request Review"
assert parsed_configuration["LogoPath"] == r"C:\Program Files\Company\WDACToast\MicrosoftDefenderShield.png"
assert "ProgramData" not in parsed_configuration["LogoPath"]

print("Static WDAC collector and task XML checks passed.")
