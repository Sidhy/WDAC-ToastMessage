from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
collector = (ROOT / "Show-WDACToast.ps1").read_text(encoding="utf-8")
configuration = (ROOT / "WDACToast.json").read_text(encoding="utf-8")
localization = (ROOT / "WDACToast.Localization.xml").read_text(encoding="utf-8")

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
    "function Ensure-CurrentUserAppIdentity",
    "function Initialize-WdacToastStateDirectory",
    "Join-Path $env:LOCALAPPDATA 'Company\\WDACToast'",
    "NotificationState-$CurrentSid.json",
    "$InstalledCommand.Parameters.ContainsKey('EventRecordId')",
    "An explicit installation run must always copy the invoking source",
    "if (-not (Test-WdacToastInstalled))",
    "$Node.GetAttribute('Name')",
    "$Node.InnerText",
    "function Write-WdacToastLog",
    "function Test-WdacToastConfiguration",
    "function Get-OptionalRegistryValue",
    "$Item.PSObject.Properties[$Name]",
    "function Reset-WdacToastInstallation",
    "function Uninstall-WdacToast",
    "[switch]$Uninstall",
    "[switch]$CleanupLogs",
    "Uninstall and ResetInstallation are mutually exclusive",
    "CleanupLogs is valid only when Uninstall is supplied",
    "Unregister-ScheduledTask -TaskName $RegisteredTaskName -Confirm:$false -ErrorAction Stop",
    'Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $RegisteredTaskName',
    "Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction Stop",
    "Remove-Item -LiteralPath $StateDirectory -Recurse -Force -ErrorAction Stop",
    "Unregister-ScheduledTask",
    "ResetInstallation cannot be combined with EventRecordId",
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
    "function Get-WdacToastStrings",
    "GlobalizationPreferences]::Languages",
    "$Localization.Strings.BlockedAppPath",
    "$Localization.Strings.CalledByAppPath",
    "$Localization.Strings.BlockedByPolicy",
    "$PolicyVersion = Get-FirstEventValue",
    "PolicyVersion = $PolicyVersion",
    '<text hint-maxLines="1">{2}</text>',
    '<text hint-maxLines="2">{3}</text>',
    '<group><subgroup>{5}</subgroup></group>',
    'template="ToastGeneric" lang="{0}"',
    '(& $Escape $Strings.MoreDetails)',
    '(& $Escape $Strings.Dismiss)',
    '(& $Escape $LocalizedActionLabel)',
    "Write-Error -ErrorRecord $Failure",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "$env\\:ProgramData" not in collector
assert "$Node.'#text'" not in collector
assert "ExecutionPolicy Bypass" not in collector
assert "S-1-5-18" not in collector
assert "WTSQueryUserToken" not in collector
assert "DuplicateTokenEx" not in collector
assert "CreateProcessAsUser" not in collector
assert "ServiceAccount" not in collector
assert "AuthenticatedUsers" not in collector
assert "Set-Acl" not in collector
assert "Registry::HKEY_USERS" not in collector
assert not re.search(r"\bGet-ItemPropertyValue\s+-", collector)
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
uninstall_branch = collector.index("function Uninstall-WdacToast")
installed_config_read = collector.index("Get-Content -LiteralPath $InstalledConfigurationFile -Raw -ErrorAction Stop", uninstall_branch)
install_directory_removal = collector.index("Remove-Item -LiteralPath $InstallDirectory -Recurse -Force -ErrorAction Stop", uninstall_branch)
assert installed_config_read < install_directory_removal, "uninstall must read installed configuration before deleting files"
readme = (ROOT / "README.md").read_text(encoding="utf-8")
assert '-Command "Unregister-ScheduledTask' not in readme
assert "-File .\\Show-WDACToast.ps1 -Uninstall" in readme
install_branch = collector.index("if ($EventRecordId -eq 0) {")
repair_branch = collector.index("if (-not (Test-WdacToastInstalled))", install_branch)
assert install_branch < repair_branch, "explicit installation must run before event-only repair"
assert "if ($EventRecordId -eq 0) {\n        if ($Uninstall)" in collector
assert "return\n        }\n        # An explicit installation run" in collector
assert not (ROOT / "Install-WDACToast.ps1").exists()
assert [path.name for path in ROOT.glob("*.ps1")] == ["Show-WDACToast.ps1"]

match = re.search(r'\$TaskXml = @"\n(.*?)\n"@', collector, re.DOTALL)
assert match, "scheduled-task XML template was not found"
xml = match.group(1)
xml = xml.replace("$EscapedScript", r"C:\Program Files\Company\WDACToast\Show-WDACToast.ps1")
xml = xml.replace("$EscapedAppId", "Company.WDACToast")
xml = xml.replace("$EscapedDisplayName", "Company Security")
xml = xml.replace("$EscapedLogoPath", r"C:\Branding\security.png")
xml = xml.replace("$EscapedSupportUri", "https://support.example.test/details")
xml = xml.replace("$EscapedInstallDirectory", r"C:\Program Files\Company\WDACToast")
xml = xml.replace("$EscapedTaskName", "Company WDAC Block Notification")
xml = xml.replace("`$(EventRecordID)", "123")
ET.fromstring(xml)
task = ET.fromstring(xml)
ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
assert task.findtext(".//t:GroupId", namespaces=ns) == "S-1-5-4"
assert task.findtext(".//t:RunLevel", namespaces=ns) == "LeastPrivilege"
assert task.find(".//t:UserId", namespaces=ns) is None
assert task.find(".//t:LogonType", namespaces=ns) is None
assert "-Broker" not in task.findtext(".//t:Arguments", namespaces=ns)
assert "InteractiveToken" not in xml

parsed_configuration = json.loads(configuration)
assert parsed_configuration["ActionLabel"] == "Request Review"
assert parsed_configuration["LogoPath"] == r"C:\Program Files\Company\WDACToast\MicrosoftDefenderShield.png"
assert "ProgramData" not in parsed_configuration["LogoPath"]

localization_root = ET.fromstring(localization)
assert localization_root.attrib["fallbackLanguage"] == "en"
expected_languages = {"en", "it-IT", "nl-NL", "de-DE", "fr-FR", "uk-UA", "da-DK", "es-ES", "es-AR", "pt-PT", "pt-BR"}
languages = {node.attrib["tag"]: node for node in localization_root.findall("language")}
assert set(languages) == expected_languages
required_strings = {node.attrib["name"] for node in languages["en"].findall("string")}
assert required_strings == {"Title", "Message", "UnknownFile", "NotProvided", "BlockedAppPath", "CalledByAppPath", "BlockedByPolicy", "VersionFormat", "MoreDetails", "Dismiss", "RequestReview"}
for tag, language in languages.items():
    strings = language.findall("string")
    assert {node.attrib["name"] for node in strings} == required_strings, f"{tag} has incomplete localization"
    assert all((node.text or "").strip() for node in strings), f"{tag} has an empty localized string"

print("Static WDAC collector and task XML checks passed.")
