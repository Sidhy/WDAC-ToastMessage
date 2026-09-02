# WDAC Event 3077 Toast Notification

`Show-WDACToast.ps1` installs and runs a per-user Windows notification for Windows Defender Application Control enforcement events.

## How it works

The script has two entry paths:

1. When run without an event record ID, it installs itself under `C:\Program Files\Company\WDACToast`, registers a custom toast application identity, and creates an event-triggered Scheduled Task for the current user.
2. When the Scheduled Task supplies an `EventRecordId`, the installed script retrieves that exact Event ID 3077 record, writes complete diagnostics, applies duplicate suppression, and displays the toast.

The installation check runs on every invocation. If an invocation detects a missing installation file, application identity registration, or Scheduled Task registration, it recreates the missing components before processing an event.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1.
- Permission to read `Microsoft-Windows-CodeIntegrity/Operational` in the target user context.
- Administrator rights for the initial installation under Program Files.
- A code-signed production script permitted by the deployed WDAC policy. The Scheduled Task uses `-ExecutionPolicy AllSigned`.

The task runs with `InteractiveToken`, so it is registered separately for each user who should see notifications. A SYSTEM task cannot display a toast directly in an interactive user's session.

## Configure

Before signing and deploying the script, set organization-specific defaults near the beginning of `Show-WDACToast.ps1`:

- `SupportUri` — an organization-controlled HTTPS review URL.
- `AppId` — a stable application identity, such as `Contoso.WDACToast`.
- `DisplayName` — the notification sender shown to users.
- `InstallDirectory` and `TaskName` — optional deployment-specific names.

The same values can be supplied as command-line parameters during installation.

## Install

Run the single script from an elevated PowerShell session under the account that should receive notifications:

```powershell
.\Show-WDACToast.ps1 `
    -AppId 'Contoso.WDACToast' `
    -DisplayName 'Contoso Security' `
    -SupportUri 'https://support.contoso.example/wdac-review'
```

The command is idempotent. Running it again repairs missing installation components.

The production file must be signed before installation because the Scheduled Task invokes the installed copy with `AllSigned`:

```powershell
$certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Show-WDACToast.ps1 -Certificate $certificate
```

## Event processing

The Scheduled Task listens only for Event ID 3077 in:

```text
Microsoft-Windows-CodeIntegrity/Operational
```

Its value query passes `Event/System/EventRecordID` to the script. The collector then uses an XPath query containing both Event ID 3077 and the supplied record ID. Event data is parsed from XML rather than localized message text.

Known field alternatives include the spaced names used by current events (`File Name` and `Process Name`) and unspaced names found on other provider versions.

## Diagnostics and duplicate suppression

Each event is written before the notification decision to:

```text
C:\ProgramData\Company\WDACToast\Logs\WDAC-<timestamp>-<record-id>.json
```

The JSON includes selected fields, all named `EventData` values, and the complete event XML. Treat this directory as security-relevant data and apply an ACL appropriate to the deployment.

Notifications for the same lowercase file path are suppressed for five minutes by default. Every underlying event is still logged. Use `-DuplicateCooldownMinutes 0` to disable suppression or supply a value up to 1440 minutes.

## Security properties

- Dynamic event values and configured action values are XML escaped before toast XML is created.
- The toast action accepts only a configured HTTPS URI.
- Event content is never used to construct a command or executable action.
- The state file is replaced atomically, and Scheduled Task instances are queued to prevent concurrent state updates.
- No execution-policy bypass is used.
- Raw status codes remain in diagnostics; unvalidated status-to-text mappings are not presented to users.

The toast and local JSON are supplementary user and support signals. Retain the native Code Integrity log or centrally collected WDAC telemetry as the authoritative security record.

## Windows test procedure

Test Code Integrity log access from the target standard-user session:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3077
} -MaxEvents 1
```

To process the latest event manually:

```powershell
$recordId = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3077
} -MaxEvents 1 | Select-Object -ExpandProperty RecordId

& "$env:ProgramFiles\Company\WDACToast\Show-WDACToast.ps1" -EventRecordId $recordId -Verbose
```

Validate toast branding, support-link activation, Focus Assist behavior, duplicate suppression, Fast User Switching, and task history on every supported Windows build.

If users cannot read the event log, use a separate protected SYSTEM collector and a per-user renderer. Secure that handoff so standard users cannot inject notification text or actions.
