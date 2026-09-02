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
    "function Install-WdacToast",
    "if (-not (Test-WdacToastInstalled))",
]
for fragment in required_collector_fragments:
    assert fragment in collector, f"collector is missing {fragment!r}"

assert "$env\\:ProgramData" not in collector
assert "ExecutionPolicy Bypass" not in collector
assert "<MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>" in collector
assert "Event/System/EventRecordID" in collector
assert '`$(EventRecordID)' in collector
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
