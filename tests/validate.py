from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
collector = (ROOT / "Show-WDACToast.ps1").read_text(encoding="utf-8")
configuration = (ROOT / "WDACToast.json").read_text(encoding="utf-8")
localization = (ROOT / "WDACToast.Localization.xml").read_text(encoding="utf-8")
profile_cleanup = (ROOT / "Cleanup-WDACToastAllProfiles.ps1").read_text(encoding="utf-8")

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
    "[switch]$Upgrade",
    "[ValidateSet('AllSigned', 'Bypass')]",
    "[string]$ExecutionPolicy = 'AllSigned'",
    "ExecutionPolicy in '$ConfigurationFile' must be either AllSigned or Bypass",
    "[ValidateSet('Hidden', 'Minimized')]",
    "[string]$WindowStyle = 'Hidden'",
    "WindowStyle in '$ConfigurationFile' must be either Hidden or Minimized",
    "function Upgrade-WdacToastInstallation",
    "$InstallationMarkerPath = 'HKLM:\\Software\\Company\\WDACToast'",
    "function Get-PreviousWdacToastInstallations",
    "function Set-WdacToastInstallationMarker",
    "New-ItemProperty -Path $InstallationMarkerPath -Name InstallDirectory",
    "New-ItemProperty -Path $InstallationMarkerPath -Name TaskName",
    "New-ItemProperty -Path $InstallationMarkerPath -Name AppId",
    "Upgrade is mutually exclusive with ResetInstallation and Uninstall",
    "Upgrade requires EventRecordId = 0",
    "Register-ScheduledTask -TaskName $PreviousTaskName -Xml $PreviousTaskXml -Force",
    "Uninstall and ResetInstallation are mutually exclusive",
    "CleanupLogs is valid only when Uninstall is supplied",
    "Unregister-ScheduledTask -TaskName $RegisteredTaskName -Confirm:$false -ErrorAction Stop",
    'Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $RegisteredTaskName',
    "Remove-Item -LiteralPath $RegisteredInstallDirectory -Recurse -Force -ErrorAction Stop",
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
    '(& $Escape $Strings.Dismiss)',
    '(& $Escape $LocalizedActionLabel)',
    "Write-Error -ErrorRecord $Failure",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "$env\\:ProgramData" not in collector
assert "$Node.'#text'" not in collector
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
assert "$Strings.MoreDetails" not in collector
assert "[string]$DetailsUri" not in collector
assert "-DetailsUri $DetailsUri" not in collector
assert '"File: $(Limit-Text' not in collector
assert '"Location: $(Limit-Text' not in collector
assert '"Requested by: $(Limit-Text' not in collector
assert '"Caller location: $(Limit-Text' not in collector
assert "function Limit-Text" not in collector
assert "MaximumLength" not in collector
assert "<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>" in collector
assert "<Hidden>false</Hidden>" in collector
assert "-NoProfile -NonInteractive -WindowStyle $WindowStyle -ExecutionPolicy $ExecutionPolicy" in collector
assert "Event/System/EventRecordID" in collector
assert '`$(EventRecordID)' in collector
assert "catch {\n    $Failure = $_" in collector
assert "exit 1" in collector
uninstall_branch = collector.index("function Uninstall-WdacToast")
installed_config_read = collector.index("Get-Content -LiteralPath $InstalledConfigurationFile -Raw -ErrorAction Stop", uninstall_branch)
install_directory_removal = collector.index("Remove-Item -LiteralPath $RegisteredInstallDirectory -Recurse -Force -ErrorAction Stop", uninstall_branch)
assert installed_config_read < install_directory_removal, "uninstall must read installed configuration before deleting files"
marker_read = collector.index("Get-ItemProperty -LiteralPath $InstallationMarkerPath")
configuration_read = collector.index("Get-Content -LiteralPath $ConfigurationFile -Raw")
assert marker_read < configuration_read, "the machine marker must be read before deployment configuration resolves the new target"
assert "@($RepositoryDefaultInstallDirectory, $InstallDirectory)" in collector

def function_body(name: str) -> str:
    """Return a top-level PowerShell function through the next declaration."""
    start = collector.index(f"function {name} {{")
    next_function = collector.find("\nfunction ", start + 1)
    return collector[start : next_function if next_function != -1 else len(collector)]

assert "Remove-Item -LiteralPath $InstallationMarkerPath" in function_body("Uninstall-WdacToast")

upgrade_body = function_body("Upgrade-WdacToastInstallation")
upgrade_read = upgrade_body.index("Get-Content -LiteralPath $PreviousConfigurationFile -Raw -ErrorAction Stop")
upgrade_copy = upgrade_body.index("\n        Install-WdacToast")
upgrade_register = collector.index("Register-ScheduledTask -TaskName $TaskName -Xml $TaskXml -Force")
assert upgrade_read < upgrade_copy, "upgrade must capture installed identity before overwriting files"
assert upgrade_register != -1, "same-name upgrades must force task replacement"
old_name_guard = upgrade_body.index("if (-not [string]::Equals($PreviousTaskName, $TaskName")
old_name_removal = upgrade_body.index("Unregister-ScheduledTask -TaskName $PreviousTaskName", old_name_guard)
verification = upgrade_body.index("$IntendedTasks.Count -ne 1")
assert old_name_guard < old_name_removal < verification, "renamed upgrades must remove and verify the old task"
assert "[string]$Action.Arguments -notlike \"*${InstalledScript}*\"" in upgrade_body
assert '[string]$Action.Arguments -notlike "*-WindowStyle $WindowStyle*"' in upgrade_body
assert "Rollback restored the prior files and task" in upgrade_body
upgrade_marker_write = upgrade_body.index("Set-WdacToastInstallationMarker")
upgrade_old_directory_removal = upgrade_body.index("Remove-Item -LiteralPath $RecordedPreviousDirectory")
assert verification < upgrade_old_directory_removal < upgrade_marker_write, (
    "upgrade must verify replacement, remove the former directory, and only then update the marker"
)

install_body = function_body("Install-WdacToast")
configuration_check_body = function_body("Test-WdacToastConfiguration")
assert '$TaskArguments -like "*-WindowStyle $WindowStyle*"' in configuration_check_body
install_register = install_body.index("Register-ScheduledTask -TaskName $TaskName")
install_old_task_removal = install_body.index("Unregister-ScheduledTask -TaskName $PreviousInstallation.TaskName")
install_old_directory_removal = install_body.index("Remove-Item -LiteralPath $PreviousInstallation.InstallDirectory")
install_marker_write = install_body.index("Set-WdacToastInstallationMarker")
assert install_register < install_old_task_removal < install_old_directory_removal < install_marker_write


for cleanup_function in ("Reset-WdacToastInstallation", "Uninstall-WdacToast"):
    body = function_body(cleanup_function)
    final_state_removal = body.rfind("Remove-Item -LiteralPath $StateDirectory")
    assert final_state_removal != -1, f"{cleanup_function} must remove the state directory"
    after_state_removal = body[final_state_removal:]
    assert not re.search(r"\bWrite-WdacToastLog\b", after_state_removal), (
        f"{cleanup_function} must not file-log after its final state-directory removal"
    )

readme = (ROOT / "README.md").read_text(encoding="utf-8")
assert '-Command "Unregister-ScheduledTask' not in readme
assert "-File .\\Show-WDACToast.ps1 -Uninstall" in readme
assert "HKLM:\\Software\\Company\\WDACToast" in readme
assert "repository default" in readme and "currently configured" in readme
assert "Administrator rights for every install, upgrade, reset, and uninstall" in readme
assert "`-WindowStyle Hidden`" in readme
assert "`<Hidden>false</Hidden>`" in readme

intune_package_instructions = readme.split("### 1. Prepare the package", 1)[1].split(
    "### 2. Configure the Win32 app", 1
)[0]
normalized_intune_package_instructions = re.sub(r"\s+", " ", intune_package_instructions)
# Keep the documented package synchronized with files that Install-WdacToast
# requires even when no optional configuration or branding has been supplied.
unconditional_install_files = {
    "Show-WDACToast.ps1": "$SourceScript = $PSCommandPath",
    "WDACToast.Localization.xml": "The deployment package is missing '$LocalizationFile'.",
}
for filename, requirement in unconditional_install_files.items():
    assert requirement in install_body, f"Install-WdacToast no longer proves that {filename} is required"
    assert f"`{filename}`" in intune_package_instructions, (
        f"Intune packaging instructions omit required file {filename}"
    )
assert "`WDACToast.json`" in intune_package_instructions
assert "any branding asset intentionally supplied" in normalized_intune_package_instructions
assert "before signing" in normalized_intune_package_instructions
assert "do not edit the script after signing" in normalized_intune_package_instructions
install_branch = collector.index("if ($EventRecordId -eq 0) {")
repair_branch = collector.index("if (-not (Test-WdacToastInstalled))", install_branch)
assert install_branch < repair_branch, "explicit installation must run before event-only repair"
assert "if ($EventRecordId -eq 0) {\n        if ($Uninstall)" in collector
assert "return\n        }\n        # An explicit installation run" in collector
assert not (ROOT / "Install-WDACToast.ps1").exists()
assert {path.name for path in ROOT.glob("*.ps1")} == {
    "Show-WDACToast.ps1",
    "Cleanup-WDACToastAllProfiles.ps1",
}
assert "CurrentVersion\\ProfileList" in profile_cleanup
assert "$RelativeStatePath = 'AppData\\Local\\Company\\WDACToast'" in profile_cleanup
assert "[Environment]::ExpandEnvironmentVariables" in profile_cleanup
assert "Remove-Item -LiteralPath $StateDirectory -Recurse -Force" in profile_cleanup
assert "NTUSER.DAT" in profile_cleanup and "HKEY_USERS" in profile_cleanup
assert "Registry::HKEY_USERS" not in profile_cleanup
assert "Remove-Item -LiteralPath $ProfileDirectory" not in profile_cleanup
assert "Cleanup-WDACToastAllProfiles.ps1" in readme
assert "SYSTEM profile, **not** every" in readme
assert "registration is inert" in readme

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
xml = xml.replace("$ExecutionPolicy", "Bypass")
xml = xml.replace("$WindowStyle", "Minimized")
xml = xml.replace("`$(EventRecordID)", "123")
ET.fromstring(xml)
task = ET.fromstring(xml)
ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
assert task.findtext(".//t:GroupId", namespaces=ns) == "S-1-5-4"
assert task.findtext(".//t:RunLevel", namespaces=ns) == "LeastPrivilege"
assert task.find(".//t:UserId", namespaces=ns) is None
assert task.find(".//t:LogonType", namespaces=ns) is None
assert task.findtext(".//t:Hidden", namespaces=ns) == "false"
assert "-Broker" not in task.findtext(".//t:Arguments", namespaces=ns)
assert "InteractiveToken" not in xml
assert "-NoProfile -NonInteractive -WindowStyle Minimized -ExecutionPolicy Bypass" in task.findtext(
    ".//t:Arguments", namespaces=ns
)
assert "-ExecutionPolicy Bypass" in task.findtext(".//t:Arguments", namespaces=ns)
assert task.findtext(".//t:Arguments", namespaces=ns).endswith("-WindowStyle Minimized")

parsed_configuration = json.loads(configuration)
assert parsed_configuration["ActionLabel"] == "Request Review"
assert parsed_configuration["ExecutionPolicy"] == "AllSigned"
assert parsed_configuration["WindowStyle"] == "Hidden"
assert parsed_configuration["LogoPath"] == r"C:\Program Files\Company\WDACToast\MicrosoftDefenderShield.png"
assert "ProgramData" not in parsed_configuration["LogoPath"]

localization_root = ET.fromstring(localization)
assert localization_root.attrib["fallbackLanguage"] == "en"
expected_languages = {"en", "it-IT", "nl-NL", "de-DE", "fr-FR", "uk-UA", "da-DK", "es-ES", "es-AR", "pt-PT", "pt-BR"}
languages = {node.attrib["tag"]: node for node in localization_root.findall("language")}
assert set(languages) == expected_languages
required_strings = {node.attrib["name"] for node in languages["en"].findall("string")}
assert required_strings == {"Title", "Message", "UnknownFile", "NotProvided", "BlockedAppPath", "CalledByAppPath", "BlockedByPolicy", "VersionFormat", "Dismiss", "RequestReview"}
english_strings = {node.attrib["name"]: node.text for node in languages["en"].findall("string")}
assert english_strings["BlockedAppPath"] == "Blocked App:"
assert english_strings["CalledByAppPath"] == "Executed by:"
assert english_strings["BlockedByPolicy"] == "WDAC Policy:"
for tag, language in languages.items():
    strings = language.findall("string")
    assert {node.attrib["name"] for node in strings} == required_strings, f"{tag} has incomplete localization"
    assert all((node.text or "").strip() for node in strings), f"{tag} has an empty localized string"

print("Static WDAC collector and task XML checks passed.")
