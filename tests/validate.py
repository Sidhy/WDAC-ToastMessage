from pathlib import Path
from html.parser import HTMLParser
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
    "function Invoke-WdacToastLogMaintenance",
    "WDACToast-{0}.log",
    ".AddMonths(-2)",
    "[switch]$LogMaintenance",
    "$TaskName Log Maintenance",
    "<CalendarTrigger>",
    "<StartWhenAvailable>true</StartWhenAvailable>",
    "-LogMaintenance",
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
    '<text hint-maxLines="1">{3}</text>',
    '<text hint-maxLines="2">{4}</text>',
    '<group><subgroup>{5}</subgroup></group>',
    'hint-style="body" hint-wrap="true" hint-maxLines="4"',
    'template="ToastGeneric" lang="{1}"',
    '(& $Escape $LocalizedActionLabel)',
    "Write-Error -ErrorRecord $Failure",
    'activationType="protocol" afterActivationBehavior="pendingUpdate"',
    "$Toast.Tag = $Tag",
    "$Toast.Group = $Group",
    "$ToastTag = \"wdac-$($Event.RecordId)\"",
    "$ToastGroup = 'wdac-blocks'",
    "Remove-CurrentUserAppIdentity",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "function New-WdacReviewPage" in collector
assert "company-wdactoast://copy" not in collector
assert "Windows.Clipboard" not in collector
assert "$AlertStateDirectory" not in collector
assert "function Save-WdacAlertState" not in collector
assert "function Invoke-WdacToastActivation" not in collector
assert "function Show-WdacReplacementNotification" not in collector
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
assert "[string]$ReviewPageUri" in collector
assert "-ReviewPageUri $ReviewPage.ActivationUri" in collector
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

assert "ToUpperInvariant()" not in function_body("Show-ToastNotification")
identity_body = function_body("Ensure-CurrentUserAppIdentity")
assert "AppUserModelId\\$AppId" in identity_body
assert "$ReviewProtocol" in identity_body
assert "URL Protocol" in identity_body
assert "shell\\open\\command" in identity_body


toast_body = function_body("Show-ToastNotification")
assert toast_body.count("<action ") == 2, "toast XML must define exactly two actions"
assert 'content="{0}" arguments="dismiss" activationType="system"' in toast_body
assert 'content="{1}" arguments="{2}" activationType="protocol" afterActivationBehavior="pendingUpdate"' in toast_body
assert "(& $Escape $Strings.Dismiss)" in toast_body
assert "(& $Escape $LocalizedActionLabel)" in toast_body
assert "$EscapedReviewPageUri = & $Escape $ReviewPageUri" in toast_body
assert "(& $Escape $SupportUri)" not in toast_body
assert "[ValidatePattern('^https://')]" in collector
assert "company-wdactoast" not in toast_body

# Materialize the XML-producing format strings to validate the routing contract
# represented by the generated toast, rather than checking isolated fragments.
review_uri = "company-wdac-review://open/314/0123456789abcdef0123456789abcdef"
action_template = re.search(r"\$ActionXml = '([^\n]+)' -f", toast_body).group(1)
action_xml = action_template.format("Dismiss", "Request Review", review_uri.replace("&", "&amp;"))
toast_template = re.search(r"\$ToastXml = '([^\n]+)' -f", toast_body).group(1)
toast_xml = toast_template.format(
    review_uri.replace("&", "&amp;"), "en-US", "", "Blocked app", "Review report available", "", action_xml
)
toast = ET.fromstring(toast_xml)
assert toast.get("launch") == review_uri, "the toast body must target the Review Report page"
assert toast.get("activationType") == "protocol", "toast body activation must use the report protocol"
assert toast.get("afterActivationBehavior") == "pendingUpdate"
actions = toast.findall("./actions/action")
request_review = next(action for action in actions if action.get("content") == "Request Review")
assert request_review.get("arguments") == review_uri, "Request Review must retain the report protocol URI"
assert request_review.get("activationType") == "protocol"
assert request_review.get("afterActivationBehavior") == "pendingUpdate"
system_actions = [action for action in actions if action.get("activationType") == "system"]
assert len(system_actions) == 1, "Dismiss must be the sole system-activation action"
assert system_actions[0].get("content") == "Dismiss" and system_actions[0].get("arguments") == "dismiss"

assert "-FileName $FileName" not in function_body("Invoke-WdacToast")
assert "$ProcessPath -replace '^.*[\\\\/]', ''" in function_body("Invoke-WdacToast")
assert "('{0} {1}' -f $Localization.Strings.BlockedAppPath, $FileName) = $FilePath" in function_body("Invoke-WdacToast")
assert "('{0} {1}' -f $Localization.Strings.CalledByAppPath, $ProcessFileName) = $ProcessPath" in function_body("Invoke-WdacToast")
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
install_old_task_removal = install_body.index("Unregister-ScheduledTask -TaskName $PreviousTask")
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
assert "`Logs\\WDACToast-yyyy-MM.log`" in readme
assert "more than two months old" in readme

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
assert "other users' unloaded HKCU" in readme

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

maintenance_match = re.search(r'\$MaintenanceTaskXml = @"\n(.*?)\n"@', collector, re.DOTALL)
assert maintenance_match, "monthly log-maintenance task XML template was not found"
maintenance_xml = maintenance_match.group(1)
maintenance_xml = maintenance_xml.replace("$EscapedScript", r"C:\Program Files\Company\WDACToast\Show-WDACToast.ps1")
maintenance_xml = maintenance_xml.replace("$ExecutionPolicy", "Bypass")
maintenance_xml = maintenance_xml.replace("$WindowStyle", "Minimized")
maintenance_task = ET.fromstring(maintenance_xml)
assert maintenance_task.findtext(".//t:GroupId", namespaces=ns) == "S-1-5-4"
assert maintenance_task.findtext(".//t:StartWhenAvailable", namespaces=ns) == "true"
assert maintenance_task.findtext(".//t:ScheduleByMonth/t:DaysOfMonth/t:Day", namespaces=ns) == "1"
assert len(maintenance_task.findall(".//t:ScheduleByMonth/t:Months/*", namespaces=ns)) == 12
assert "-LogMaintenance" in maintenance_task.findtext(".//t:Arguments", namespaces=ns)

parsed_configuration = json.loads(configuration)
assert parsed_configuration["ActionLabel"] == "Request Review"
assert parsed_configuration["ExecutionPolicy"] == "AllSigned"
assert parsed_configuration["WindowStyle"] == "Hidden"
assert parsed_configuration["LogoPath"] == r"C:\Program Files\Company\WDACToast\MicrosoftDefenderShield.png"
assert "ProgramData" not in parsed_configuration["LogoPath"]

localization_root = ET.fromstring(localization)
assert localization_root.attrib["fallbackLanguage"] == "en"
expected_languages = {
    "en", "it-IT", "nl-NL", "de-DE", "fr-FR", "uk-UA", "da-DK", "es-ES", "es-AR", "pt-PT", "pt-BR",
    "ko-KR", "ja-JP", "hu-HU", "cs-CZ", "ar-MA", "ro-RO",
}
requested_languages = {"ko-KR", "ja-JP", "hu-HU", "cs-CZ", "ar-MA", "ro-RO"}
languages = {node.attrib["tag"]: node for node in localization_root.findall("language")}
assert set(languages) == expected_languages
assert requested_languages <= set(languages), "one or more requested locales are missing"
required_strings = {node.attrib["name"] for node in languages["en"].findall("string")}
assert {"Title", "Message", "UnknownFile", "NotProvided", "BlockedAppPath", "CalledByAppPath", "BlockedByPolicy", "VersionFormat", "RequestReview", "Dismiss"} <= required_strings
english_strings = {node.attrib["name"]: node.text for node in languages["en"].findall("string")}
approved_english_explanation = (
    "Your organization blocked this application because it is not approved for use or may present a security risk. "
    "Some legitimate applications and Windows tools can also be blocked because they are commonly misused by attackers. "
    "This does not mean the application is malware."
)
approved_english_toast = (
    "Your organization blocked this application because it is not approved or may pose a security risk. "
    "This does not mean it is malware."
)
assert english_strings["Message"] == approved_english_toast
assert english_strings["ReportExplanation"] == approved_english_explanation
assert english_strings["BlockedAppPath"] == "Blocked App:"
assert english_strings["CalledByAppPath"] == "Executed by:"
assert english_strings["BlockedByPolicy"] == "WDAC Policy:"
for tag, language in languages.items():
    strings = language.findall("string")
    values = {node.attrib["name"]: (node.text or "").strip() for node in strings}
    assert {node.attrib["name"] for node in strings} == required_strings, f"{tag} has incomplete localization"
    assert all((node.text or "").strip() for node in strings), f"{tag} has an empty localized string"
    assert values["Message"], f"{tag} has an empty toast message"
    assert values["ReportExplanation"], f"{tag} has an empty report explanation"
    assert len(values["Message"]) <= 200, f"{tag} has an overly long toast message"
    assert len(values["Message"].split()) <= 30, f"{tag} toast message has too many words"
    assert values["Message"] != values["ReportExplanation"], f"{tag} toast message is not concise"
    if tag != "en":
        assert values["Message"] != approved_english_toast, f"{tag} does not have a locale-specific toast message"
    assert len(values["Title"]) <= 60 and len(values["Title"].split()) <= 8, f"{tag} has an overly long toast title"
    detail_labels = [values[name] for name in ("BlockedAppPath", "CalledByAppPath", "BlockedByPolicy")]
    assert all(label.endswith(":") and len(label) <= 24 for label in detail_labels), f"{tag} has an overly long detail label"
    action_labels = [values[name] for name in ("RequestReview", "Dismiss")]
    assert all(len(label) <= 24 and len(label.split()) <= 3 for label in action_labels), f"{tag} has an overly long action label"

assert not (ROOT / "ToastActivator").exists()
assert "WDACToast.Activator.exe" not in collector

print("Static WDAC collector and task XML checks passed.")


# Event-specific, encoded local review report workflow.
review_body = function_body("New-WdacReviewPage")
assert "[Net.WebUtility]::HtmlEncode" in review_body
assert "[guid]::NewGuid().ToString('N')" in review_body
assert "review-{0}-{1}.html" in review_body
assert "$ReviewDirectory" in review_body
assert "$Result.RawEventXml" not in review_body and "ReportRawEventHeading" not in review_body
assert "<details><summary>" not in review_body and "<pre" in review_body
assert "<table" not in review_body.lower() and "$TableRows" not in review_body
assert "navigator.clipboard.writeText" in review_body
assert "document.execCommand('copy')" in review_body
assert "area.select()" in review_body and "setSelectionRange" in review_body
assert "range.selectNodeContents(details)" in review_body and "details.focus()" in review_body
assert 'role="status"' in review_body and 'aria-live="polite"' in review_body
assert '<button class="button" id="copy-details" type="button">' in review_body
assert "(& $Encode $SupportUri)" in review_body
assert "ReportExactErrorHeading" in review_body and "ReportCopyButton" in review_body
assert "$ErrorHeading = $Strings.ReportExactErrorHeading -f $BlockedFileName" in review_body
assert "(& $Encode $ErrorHeading)" in review_body
assert "$BlockedFileName = $Strings.UnknownFile" in review_body
assert all(key in review_body for key in ("ReportSupportStepOne", "ReportSupportStepTwo", "ReportSupportStepThree"))
for value in ("$Strings.ReportCopySuccess", "$Strings.ReportCopyFailure", "$Strings.ReportSupportStepOne", "$Strings.ReportSupportStepTwo", "$Strings.ReportSupportStepThree"):
    assert f"(& $Encode {value})" in review_body
report_template = re.search(r"\$Html = @'\n(.*?)\n'@ -f", review_body, re.DOTALL).group(1)
assert report_template.count("<li>") == 3
assert report_template.index("<h1>{1}</h1><p>{2}</p>") < report_template.index("<h2>{3}</h2><p>{4}</p>")
assert report_template.index("<li>{7}</li>") < report_template.index('href="{8}"')
assert report_template.index('href="{8}"') < report_template.index("<h2>{10}</h2>")
support_uri = "https://support.example.test/wdac-review?source=report&amp;kind=request"
values = ["report value"] * 16
values[7] = "Explain why this application &amp; its access are needed."
values[8] = support_uri
values[9] = "Open Support Portal"
values[10] = "Blocked Application Details: blocked&lt;app&gt;&amp;.exe"
report_html = report_template.format(*values)
assert "<li>Explain why this application & its access are needed.</li>" not in report_html
assert "<li>Explain why this application &amp; its access are needed.</li>" in report_html
assert "<h2>Blocked Application Details: blocked&lt;app&gt;&amp;.exe</h2>" in report_html
assert 'aria-label="Blocked Application Details: blocked&lt;app&gt;&amp;.exe"' in report_html

class ReportLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.append(dict(attrs))


report_parser = ReportLinkParser()
report_parser.feed(report_html)
support_links = [link for link in report_parser.links if link.get("class") == "button"]
assert len(support_links) == 1 and support_links[0].get("href") == support_uri.replace("&amp;", "&"), (
    "the Review Report page must open the configured Support Portal"
)
invoke_body = function_body("Invoke-WdacToast")
assert invoke_body.index("New-WdacReviewPage") < invoke_body.index("Show-ToastNotification")
assert "$ReviewPage.ActivationUri" in invoke_body
assert "RawEventXml = $Event.ToXml()" in invoke_body
maintenance_body = function_body("Invoke-WdacToastLogMaintenance")
assert "$ReviewDirectory" in maintenance_body and "*.html" in maintenance_body
assert ".AddMonths(-2)" in maintenance_body
assert "AppData\\Local\\Company\\WDACToast" in profile_cleanup
assert "Remove-Item -LiteralPath $StateDirectory -Recurse" in profile_cleanup

localization_root = ET.fromstring(localization)
required_report_keys = {
    "ReportTitle", "ReportExplanation", "ReportApplicationName",
    "ReportApplicationPath", "ReportCallingProcess", "ReportPolicyName", "ReportPolicyId",
    "ReportPolicyVersion", "ReportStatus", "ReportSigningScenario", "ReportRequestedLevel",
    "ReportValidatedLevel", "ReportSha256", "ReportSha1", "ReportEventTime", "ReportComputer",
    "ReportActivityId", "ReportProvider", "ReportRecordId", "ReportExactErrorHeading",
    "ReportCopyHint", "ReportCopyButton", "ReportCopySuccess", "ReportCopyFailure",
    "ReportSupportInstructions", "ReportSupportStepOne", "ReportSupportStepTwo",
    "ReportSupportStepThree", "ReportOpenSupport",
}
language_key_sets = [{node.get("name") for node in language.findall("string")} for language in localization_root.findall("language")]
assert language_key_sets and all(keys == language_key_sets[0] for keys in language_key_sets)
assert required_report_keys <= language_key_sets[0]
assert "ReportDetailsHeading" not in language_key_sets[0] and "ReportCopyBeforeSupport" not in language_key_sets[0]
localized_report_keys = {
    "ReportTitle", "ReportExplanation", "ReportApplicationName", "ReportApplicationPath",
    "ReportDescription", "ReportProduct", "ReportVersion", "ReportPublisher",
    "ReportCallingProcess", "ReportCallerDescription", "ReportCallerProduct",
    "ReportCallerVersion", "ReportCallerPublisher", "ReportPolicyName", "ReportPolicyId",
    "ReportPolicyVersion", "ReportStatus", "ReportSigningScenario", "ReportRequestedLevel",
    "ReportValidatedLevel", "ReportSha256", "ReportSha1", "ReportEventTime",
    "ReportComputer", "ReportActivityId", "ReportProvider", "ReportRecordId",
    "ReportExactErrorHeading", "ReportCopyHint", "ReportCopyButton", "ReportCopySuccess",
    "ReportCopyFailure", "ReportSupportHeading", "ReportSupportInstructions",
    "ReportSupportStepOne", "ReportSupportStepTwo", "ReportSupportStepThree",
    "ReportOpenSupport",
}
# Add only (locale, key) pairs whose complete label is genuinely language-neutral.
language_neutral_report_values = set()
localized_values = {
    language.get("tag"): {node.get("name"): (node.text or "").strip() for node in language.findall("string")}
    for language in localization_root.findall("language")
}
for tag, strings in localized_values.items():
    assert strings["ReportExactErrorHeading"].count("{0}") == 1, f"{tag} report heading must contain exactly one {{0}} placeholder"
    if tag != "en":
        reused_english = {
            key for key in localized_report_keys
            if strings[key] == localized_values["en"][key]
            and (tag, key) not in language_neutral_report_values
        }
        assert not reused_english, f"{tag} has English report UI: {sorted(reused_english)}"
assert "ReportSupportStepThree" in required_strings and "ReportRawEventHeading" not in required_strings
assert "'ReportSupportStepThree'" in collector and "'ReportRawEventHeading'" not in collector
assert "local review page" in readme.lower() and "company-wdac-review" in readme
assert "older than two months" in readme and "sensitive" in readme.lower()
