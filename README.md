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
- An interactive user session with the Windows Push Notifications user service available. Do not invoke the renderer with PowerShell 7 (`pwsh.exe`) or as SYSTEM: PowerShell 7 does not provide the Windows PowerShell 5.1 WinRT type projection used by `Windows.UI.Notifications`.
- Notifications enabled for the user in Windows Settings (and not disabled by organizational policy). The script reports an explicit error when `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled` is present and set to `0`; it does not override that preference or policy.
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
It also compares the deployment source with the installed copy and replaces an
outdated installed script before re-registering the task. Run the newly deployed
source file—not the existing Program Files copy—when upgrading.

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

Operational activity and caught errors are appended to:

```text
C:\ProgramData\Company\WDACToast\Logs\WDACToast.log
```

Every invocation now logs its parameters and execution stages. Configuration checks report the installed script, per-user AppUserModelID values, Scheduled Task state/user/action, Code Integrity log, support URI, Windows PowerShell host, interactive session, notification preference and policy, and push-notification service. Passing `-Verbose` mirrors all `INFO` entries to the console; failed checks and duplicate suppression are both written to the file and shown as PowerShell warnings.

If the command reports installation success but no toast, check the warning immediately above it. An unset or empty `$recordId` converts to the default `EventRecordId` value of `0`; that mode only installs and validates the components. Confirm the value before invoking the script:

```powershell
$recordId
if ($recordId -le 0) { throw 'No WDAC Event ID 3077 record was found.' }
```

After a rendering attempt, the log explicitly distinguishes submission to the Windows notification platform from actual on-screen presentation. Windows may accept a toast and still hide it because of Do Not Disturb/Focus Assist or per-application notification settings.

The top-level error handler logs the failing installation or event-record context, exception message, and PowerShell source position, writes the original error to the Scheduled Task history, and exits with code `1`. If the log directory itself cannot be written, logging falls back to a warning without masking the original error.

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

If PowerShell reports that `EventRecordId` is not a recognized parameter, the
copy in Program Files predates event-record processing (or is a different
script). Confirm which file is being invoked and inspect its declared parameters:

```powershell
$installed = "$env:ProgramFiles\Company\WDACToast\Show-WDACToast.ps1"
(Get-Command $installed).Parameters.Keys | Sort-Object
Get-FileHash $installed -Algorithm SHA256
```

Then run the current, signed deployment source from an elevated Windows
PowerShell 5.1 session. This upgrades the installed copy and task; invoking the
stale installed copy cannot update code that it does not contain:

```powershell
& 'C:\Path\To\Current\Show-WDACToast.ps1' `
    -AppId 'Contoso.WDACToast' `
    -DisplayName 'Contoso Security' `
    -SupportUri 'https://support.contoso.example/wdac-review' `
    -Verbose

(Get-Command $installed).Parameters.ContainsKey('EventRecordId')
```

Validate toast branding, support-link activation, Focus Assist behavior, duplicate suppression, Fast User Switching, and task history on every supported Windows build.

### Troubleshoot missing WinRT types

If the log reports `Unable to find type [Windows.UI.Notifications...]`, first verify the actual host and user context used for that invocation:

```powershell
$PSVersionTable | Select-Object PSEdition, PSVersion
[Environment]::UserInteractive
Get-Service -Name 'WpnUserService*'
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name ToastEnabled -ErrorAction SilentlyContinue
```

The installed task deliberately launches 64-bit Windows PowerShell 5.1 and uses `InteractiveToken`. A manual test launched in PowerShell 7 can therefore fail even though the task configuration is correct. Re-run it with `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` in the affected user's signed-in session. Windows Server Core and other systems without the Windows notification platform are not supported.

For comparison, the referenced [Toast Notification Script](https://github.com/imabdk/Toast-Notification-Script/blob/master/Remediate-ToastNotification.ps1) checks the workstation OS, the current user's push-notification setting, user context, application registration, and the notification service before loading the same WinRT types. This project keeps only the prerequisites relevant to its narrower WDAC renderer: the installer owns its per-user AppUserModelID, the task owns the interactive Windows PowerShell host, and the renderer validates its host, session, user preference, and WinRT availability. It intentionally does **not** enable notifications, restart services, or change enterprise-managed settings on the user's behalf.

If users cannot read the event log, use a separate protected SYSTEM collector and a per-user renderer. Secure that handoff so standard users cannot inject notification text or actions.
