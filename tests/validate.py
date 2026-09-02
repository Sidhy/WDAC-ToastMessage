from pathlib import Path
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
collector = (ROOT / "Show-WDACToast.ps1").read_text(encoding="utf-8")

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
    "Write-Error -ErrorRecord $Failure",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "$env\\:ProgramData" not in collector
assert "$Node.'#text'" not in collector
assert "ExecutionPolicy Bypass" not in collector
assert "<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>" in collector
assert "Event/System/EventRecordID" in collector
assert '`$(EventRecordID)' in collector
assert "catch {\n    $Failure = $_" in collector
assert "exit 1" in collector
assert not (ROOT / "Install-WDACToast.ps1").exists()
assert [path.name for path in ROOT.glob("*.ps1")] == ["Show-WDACToast.ps1"]

match = re.search(r'\$TaskXml = @"\n(.*?)\n"@', collector, re.DOTALL)
assert match, "scheduled-task XML template was not found"
xml = match.group(1)
xml = xml.replace("$EscapedUserSid", "S-1-5-21-1")
xml = xml.replace("$EscapedScript", r"C:\Program Files\Company\WDACToast\Show-WDACToast.ps1")
xml = xml.replace("$EscapedAppId", "Company.WDACToast")
xml = xml.replace("`$(EventRecordID)", "123")
ET.fromstring(xml)

print("Static WDAC collector and task XML checks passed.")
