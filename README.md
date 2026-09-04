# WDAC Event 3077 Toast Notification

`Show-WDACToast.ps1` installs one Windows Defender Application Control event task whose principal is the built-in **INTERACTIVE** group. Task Scheduler therefore runs the toast directly in a signed-in interactive user's context, at least privilege, without LocalSystem or token impersonation.

## How it works

The script has two entry paths:

1. When run without an event record ID, it installs itself under `C:\Program Files\Company\WDACToast` and creates one event-triggered Scheduled Task assigned to the well-known INTERACTIVE SID (`S-1-5-4`).
2. When an event fires while an interactive user is signed in, Task Scheduler runs
   the action as a member of the INTERACTIVE group at `LeastPrivilege`. The
   renderer creates that user's toast application identity, retrieves the exact
   Event ID 3077 record, writes user-profile diagnostics, applies duplicate
   suppression, and submits a toast to Windows.

The application identity is created on demand in the renderer's `HKCU`, so a user who signs in after deployment needs no separate installation. A missing installation must be repaired by rerunning the deployment script elevated; a standard-user renderer never attempts an administrative repair.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1.
- A signed-in interactive user session with the Windows Push Notifications user service available. Do not invoke the renderer with PowerShell 7 (`pwsh.exe`) or as SYSTEM: PowerShell 7 does not provide the Windows PowerShell 5.1 WinRT type projection used by `Windows.UI.Notifications`.
- Notifications enabled for the user in Windows Settings (and not disabled by organizational policy). The script reports an explicit error when `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled` is present and set to `0`; it does not override that preference or policy.
- Permission to read `Microsoft-Windows-CodeIntegrity/Operational` in the target user context.
- Administrator rights for the initial installation under Program Files.
- A code-signed production script permitted by the deployed WDAC policy. The Scheduled Task uses `-ExecutionPolicy AllSigned`.

Event 3077 is emitted for an enforced App Control policy block. Audit-mode events
use other IDs and do not trigger this task. See Microsoft's [App Control event ID
reference](https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations).

The task is not tied to the installer or a named user. Its group principal is the well-known INTERACTIVE SID, it uses `LeastPrivilege`, and its action directly invokes the signed renderer. No service account, stored password, user-token duplication, native session launcher, or execution-policy bypass is used.

## Configure

Configuration is read from `WDACToast.json` beside `Show-WDACToast.ps1`. During
installation, the JSON file is copied beside the installed script under
`C:\Program Files\Company\WDACToast`. The Scheduled Task supplies only the event
record ID, so subsequent edits to the installed JSON take effect on its next
invocation. If the file is absent, the built-in defaults are used. Explicit
command-line parameters override JSON values.

Static notification text is read from `WDACToast.Localization.xml`, which is
also copied beside the installed script. At render time the script reads the
signed-in user's ordered Windows display-language preferences, selects an exact
BCP-47 match first, then a matching base language, and finally English when no
configured language matches. The selected BCP-47 tag is emitted on the
`ToastGeneric` binding's standard `lang` attribute so Windows uses the proper
font and text shaping.

The supplied resources include English (`en`), Italian (`it-IT`), Dutch
(`nl-NL`), German (`de-DE`), French (`fr-FR`), Ukrainian (`uk-UA`), Danish
(`da-DK`), Spanish for Spain and Argentina (`es-ES`, `es-AR`), and Portuguese
for Portugal and Brazil (`pt-PT`, `pt-BR`). Keep the English entry because it is
the configured fallback. Every language entry must contain all string names
present in the English entry. A custom `ActionLabel` remains unchanged;
the default **Request Review** label is localized with the rest of the toast.

The source JSON is copied only when it exists. Removing it from a later upgrade
package does **not** delete a JSON file already installed in Program Files; use
`-ResetInstallation` when intentionally returning to built-in defaults. Treat
`InstallDirectory` and `TaskName` as installation settings and rerun installation
after changing either one. The other settings are consumed by the renderer on
each invocation.

Edit the supplied JSON before deployment:

```json
{
  "SupportUri": "https://support.contoso.example/wdac-review",
  "ActionLabel": "Request Review",
  "AppId": "Contoso.WDACToast",
  "DisplayName": "Contoso Security",
  "InstallDirectory": "C:\\Program Files\\Company\\WDACToast",
  "LogoPath": "C:\\Program Files\\Company\\WDACToast\\MicrosoftDefenderShield.png",
  "TaskName": "Company WDAC Block Notification",
  "DuplicateCooldownMinutes": 5
}
```

Available settings are:

- `SupportUri` — an organization-controlled HTTPS review URL.
- `ActionLabel` — text for the action that opens `SupportUri`; the default is
  **Request Review**.
- `AppId` — a stable application identity, such as `Contoso.WDACToast`.
- `DisplayName` — the notification sender shown to users.
- `LogoPath` — notification image. By default the installer extracts the
  Microsoft Defender shield from the built-in Windows Security application and
  saves it beside the installed script under
  `C:\Program Files\Company\WDACToast`. Supply another local
  PNG/JPG path, `file://` URI, or HTTPS URI to override it, or an empty string to
  disable the image.
- `InstallDirectory` and `TaskName` — optional deployment-specific names.
- `DuplicateCooldownMinutes` — suppression window from `0` (disabled) through
  `1440`; the default is five minutes.

Command-line parameters take precedence over matching JSON properties:

| Parameter | Purpose |
| --- | --- |
| `EventRecordId` | `0` installs; a positive record ID processes that exact 3077 event. |
| `DuplicateCooldownMinutes` | Overrides the configured suppression window for this invocation. |
| `SupportUri`, `ActionLabel`, `AppId`, `DisplayName`, `LogoPath` | Override notification behavior or branding. |
| `InstallDirectory`, `TaskName` | Override machine installation names; use the same values consistently on later installation/reset commands. |
| `ResetInstallation` | Removes and rebuilds the installation; valid only with `EventRecordId = 0` and only from a deployment copy outside the installed directory. |

The script enables strict mode and stops on errors. A successful installation or
suppressed duplicate exits `0`; an uncaught installation or rendering error is
logged and exits `1`.

Mutable notification state, operational logs, and per-event JSON diagnostics are
stored in `%LOCALAPPDATA%\Company\WDACToast` for the account running that
invocation. Event invocations therefore write to the user who receives the
toast; an elevated or Intune installation writes its installation log beneath
the administrator or SYSTEM profile instead.
The script does not grant Authenticated Users access to a shared machine
directory. Branding and signed program files remain under Program Files. The
same configuration values can be supplied as command-line parameters during
installation.

## Install

Run the single script once from an elevated Windows PowerShell session. The user
who performs installation does not become the task owner or notification target:

```powershell
.\Show-WDACToast.ps1 `
    -AppId 'Contoso.WDACToast' `
    -DisplayName 'Contoso Security' `
    -LogoPath 'C:\Program Files\Contoso\Branding\security.png' `
    -SupportUri 'https://support.contoso.example/wdac-review'
```

Do not install once per user or create user-specific task names. The INTERACTIVE
group principal lets Task Scheduler select a signed-in interactive token instead
of permanently binding the task to the installer. Mutable state remains inside
the selected user's profile.

The command is idempotent. Every installation run copies the invoking source over
the Program Files copy and re-registers the components, even when they already
exist. This is required for upgrades: run the downloaded/deployment copy above,
not `C:\Program Files\Company\WDACToast\Show-WDACToast.ps1`, and do not pass
`EventRecordId` during installation.

An installation invocation uses `EventRecordId = 0`. It installs and runs
configuration checks, emits a warning that no toast was attempted, and then
returns success unless an operation throws. Configuration-check warnings are
diagnostic: their Boolean result is not an installation gate.

For a normal update, run the new signed deployment copy with the same parameters;
that replaces the installed script, configuration, and computer task. To
completely reset a damaged or stale installation, run the **new deployment
copy** (not the copy under Program Files) from an elevated Windows PowerShell 5.1
session:

```powershell
& 'C:\Path\To\Current\Show-WDACToast.ps1' `
    -ResetInstallation `
    -AppId 'Contoso.WDACToast' `
    -DisplayName 'Contoso Security' `
    -SupportUri 'https://support.contoso.example/wdac-review' `
    -Verbose
```

Reset removes the configured Scheduled Task, installation directory, and state
for the account running reset, and then installs the current package. It reads
the previous installed JSON first so a renamed `TaskName` is also removed. The
script deliberately does not mount, enumerate, or modify other users' registry
hives; an existing per-user notification identity is inert and is safely
refreshed if that user later receives another toast. Do not combine
`-ResetInstallation` with `-EventRecordId`.

After upgrading, verify that the installed file exposes the parameter before
testing an event:

```powershell
$installed = "$env:ProgramFiles\Company\WDACToast\Show-WDACToast.ps1"
(Get-Command -Name $installed -CommandType ExternalScript).Parameters.ContainsKey('EventRecordId')
```

The result must be `True`. If it is `False`, the file at that exact path was not
replaced; do not retry the event command against it.

The production file must be signed before installation because the Scheduled Task invokes the installed copy with `AllSigned`. The signing certificate chain
must also be trusted on target devices and the signer must be allowed by the
deployed App Control policy. Sign the final file before packaging; modifying it
after signing invalidates the signature:

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
If several fields map to the same logical value, the first non-empty recognized
field is used.

The notification starts with a one-line security title, a two-line general
message, and the blocked filename. Its structured detail section then labels the
blocked application path, the calling application path, and the blocking policy
name and version. Missing event values are displayed as **Not provided**, so the
review format remains consistent across Code Integrity provider versions.
All of this static text, including **Unknown file**, **Not provided**, detail
labels, and built-in action labels, comes from the selected language entry.

The action row provides **More details**, **Dismiss**, and the configurable
**Request Review** action. **More details** opens the user-private JSON diagnostic
for the event, **Dismiss** closes the notification, and **Request Review** opens
the configured HTTPS `SupportUri`.
When those files are still available, Windows version metadata supplies the
description, product, publisher, and version for both the blocked file and its
caller. That metadata, the raw WDAC status, signing levels, hashes, activity ID,
provider, and event reference are written to the JSON diagnostic; they are not
additional fields in the toast. The toast detail group contains only the blocked
path, caller path, and policy name/version.

The notification does not apply application-side maximum lengths to event
values. It passes complete, XML-escaped values to wrapped adaptive text nodes so
the notification platform receives the full details. Windows still controls the
visual size and collapsed or expanded presentation of a toast.

The JSON diagnostics select additional event values for support workflows:
requested and validated signing levels, signing scenario, SHA-256/SHA-1 hashes,
and caller metadata. `RawEventData` still contains every named value emitted by
the installed Code Integrity provider, even when a provider version uses a field
the script does not recognize. The **Request review** action opens `SupportUri`.

Code Integrity commonly records paths in NT form, for example
`\Device\HarddiskVolume3\Program Files\Example\app.exe`. The script uses the
Windows `QueryDosDevice` API to map the device prefix to the machine's real drive
letter before showing or logging the selected path. It deliberately does not
assume that `HarddiskVolume3` is always `C:`. If a volume has no assigned drive
letter, the original NT path is retained. The diagnostics preserve both the
friendly path and the original value in `RawFilePath`/`RawProcessPath`.

## Diagnostics and duplicate suppression

Each event is written before the notification decision to:

```text
%LOCALAPPDATA%\Company\WDACToast\Logs\WDAC-<timestamp>-<record-id>.json
```

The JSON includes selected fields, all named `EventData` values, and the complete
event XML. The directory is created beneath the selected user's profile and uses
the profile's inherited ACL. The script does not set a custom ACL. JSON and text
logs have no automatic retention or size limit; manage them separately if your
support or privacy policy requires retention limits.

Operational activity and caught errors are appended to:

```text
%LOCALAPPDATA%\Company\WDACToast\Logs\WDACToast.log
```

Every invocation now logs its parameters and execution stages. Configuration checks report the installed script, per-user AppUserModelID values, Scheduled Task state/user/action, Code Integrity log, support URI, Windows PowerShell host, interactive session, notification preference and policy, and push-notification service. Passing `-Verbose` mirrors all `INFO` entries to the console; failed checks and duplicate suppression are both written to the file and shown as PowerShell warnings.

If the command reports installation success but no toast, check the warning immediately above it. An unset or empty `$recordId` converts to the default `EventRecordId` value of `0`; that mode only installs and validates the components. Confirm the value before invoking the script:

```powershell
$recordId
if ($recordId -le 0) { throw 'No WDAC Event ID 3077 record was found.' }
```

After a rendering attempt, the log explicitly distinguishes submission to the Windows notification platform from actual on-screen presentation. Windows may accept a toast and still hide it because of Do Not Disturb/Focus Assist or per-application notification settings.

The top-level error handler logs the failing installation or event-record context, exception message, and PowerShell source position, writes the original error to the Scheduled Task history, and exits with code `1`. If the log directory itself cannot be written, logging falls back to a warning without masking the original error.

An absent `ToastEnabled` or `DisableNotificationCenter` registry value means the
setting is not configured and is therefore allowed. The script checks for the
property before reading it; this avoids the `PSArgumentException` that
`Get-ItemPropertyValue` can raise when the Explorer policy key exists but its
`DisableNotificationCenter` value does not. These checks execute in the
Scheduled Task's interactive-user context, not the segregated administrator's
HKCU hive.

Notifications for the same lowercase file path are suppressed for five minutes
by default. The comparison uses the event timestamp, not the task start time. If
the event has no recognized file path, its record ID forms the key instead. Every
underlying event is still logged before suppression. Use
`-DuplicateCooldownMinutes 0` to disable suppression or supply a value up to 1440
minutes. Suppression state older than seven days is pruned after a successful
toast submission; this does not remove diagnostic JSON or the text log.

## Security properties

- Dynamic event values and configured action values are XML escaped before toast XML is created.
- The toast action accepts only a configured HTTPS URI.
- Event content is never used to construct a command or executable action.
- The state file is replaced atomically, and Scheduled Task instances are queued to prevent concurrent state updates.
- No execution-policy bypass is used.
- Raw status codes remain in diagnostics; unvalidated status-to-text mappings are not presented to users.

The task is queued rather than run concurrently, has a five-minute execution
limit, does not start missed events later (`StartWhenAvailable` is false), and
does not wake the device. The task and installed files are machine-wide; toast
identity, preferences, duplicate state, and diagnostics are per user. A toast is
best-effort UI, not proof that the user saw the block.

## Deploy with Microsoft Intune

Use a **Windows app (Win32)** for normal production deployment. It provides
install/uninstall commands, requirements, detection rules, assignments, and
supersedence. Microsoft documents the packaging flow in [Prepare Win32 app
content](https://learn.microsoft.com/intune/intune-service/apps/apps-win32-prepare)
and the available app settings in [Win32 app
management](https://learn.microsoft.com/intune/intune-service/apps/apps-win32-app-management).

### 1. Prepare the package

1. Customize `WDACToast.json`; do not leave the example support URL.
2. Code-sign `Show-WDACToast.ps1` with the production certificate after all
   edits are complete.
3. Put only `Show-WDACToast.ps1` and `WDACToast.json` in the source folder.
4. Run the Microsoft Win32 Content Prep Tool and select
   `Show-WDACToast.ps1` as the setup file. Upload the resulting `.intunewin`.

Do not package an already-installed copy or user-profile logs. Deploy the signer
trust and App Control allow policy before this app when those prerequisites are
not already present.

### 2. Configure the Win32 app

Use these values for the default names in this repository:

| Setting | Value |
| --- | --- |
| Install behavior | **System** |
| Device restart behavior | **No specific action** |
| Install command | `%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Show-WDACToast.ps1` |
| Uninstall command | See the command below |
| Architecture requirement | 64-bit Windows 10 or Windows 11 |

`Sysnative` makes the 32-bit Intune Management Extension start 64-bit Windows
PowerShell on a 64-bit device. The install must run as **System**, not as the
logged-on user, because it writes Program Files and registers a machine task.
The registered task itself still runs at `LeastPrivilege` in the interactive
user context; Intune's install context is not the toast's runtime context.

Use this uninstall command for the repository defaults (put it on one line in
Intune):

```text
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -Command "Unregister-ScheduledTask -TaskName 'Company WDAC Block Notification' -Confirm:$false -ErrorAction SilentlyContinue; Remove-Item -LiteralPath (Join-Path $env:ProgramFiles 'Company\WDACToast') -Recurse -Force -ErrorAction SilentlyContinue"
```

If `TaskName` or `InstallDirectory` is customized, change both literals. The
uninstall intentionally does not enumerate profiles or remove each user's HKCU
identity, logs, or duplicate state. Removing other users' data would require
additional privilege and profile-hive manipulation that this project avoids.

### 3. Detection rule

Use a **custom detection script**, run as 64-bit, so Intune checks both the file
and task instead of only the directory:

```powershell
$scriptPath = Join-Path $env:ProgramFiles 'Company\WDACToast\Show-WDACToast.ps1'
$task = Get-ScheduledTask -TaskName 'Company WDAC Block Notification' -ErrorAction SilentlyContinue

if ((Test-Path -LiteralPath $scriptPath -PathType Leaf) -and
    $null -ne $task -and
    $task.Principal.GroupId -eq 'S-1-5-4' -and
    $task.Principal.RunLevel -eq 'Limited' -and
    @($task.Actions).Count -eq 1 -and
    [string]$task.Actions[0].Arguments -like "*$scriptPath*" -and
    [string]$task.Actions[0].Arguments -like '*-ExecutionPolicy AllSigned*') {
    Write-Output 'WDAC toast is installed.'
    exit 0
}

exit 1
```

For an Intune custom detection rule, detection requires exit code `0` **and**
text on standard output. Update the names in the script when configuration uses
custom deployment settings.

### 4. Assign, update, and validate

- Assign the app to a pilot **device** group first, then broaden the required
  assignment after validation. Device assignment matches this machine-wide
  installation better than installing separately for every user.
- Use Win32 app supersedence or replace the package for updates. Keep the same
  `AppId`, task name, and installation directory unless intentionally migrating
  them.
- Validate installation status in Intune, then perform the standard-user test in
  [Windows test procedure](#windows-test-procedure). Installation by the Intune
  service cannot display a toast because it is not the interactive renderer.
- If the task is installed but never renders, verify that a standard user can
  read the Code Integrity Operational log and review the user's local log.

Microsoft also supports deploying PowerShell scripts through the [Intune
Management Extension](https://learn.microsoft.com/intune/intune-service/apps/intune-management-extension)
and documents its [PowerShell script
settings](https://learn.microsoft.com/intune/intune-service/apps/powershell-scripts).
That approach can install this project by running the signed script in the system
context with the 64-bit-host option enabled, but it has no Win32-app uninstall or
detection lifecycle and is therefore better suited to a pilot or one-time
bootstrap than ongoing application management.

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

The installed task deliberately launches 64-bit Windows PowerShell 5.1 under the INTERACTIVE group principal. A manual test launched in PowerShell 7 can therefore fail even though the task configuration is correct. Re-run it with `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` in the affected user's signed-in session. Windows Server Core and other systems without the Windows notification platform are not supported.

For comparison, the referenced [Toast Notification Script](https://github.com/imabdk/Toast-Notification-Script/blob/master/Remediate-ToastNotification.ps1) checks the workstation OS, the current user's push-notification setting, user context, application registration, and the notification service before loading the same WinRT types. This project keeps only the prerequisites relevant to its narrower WDAC renderer: the renderer owns its per-user AppUserModelID, the task selects an interactive Windows PowerShell host, and the renderer validates its host, session, user preference, and WinRT availability. It intentionally does **not** enable notifications, restart services, or change enterprise-managed settings on the user's behalf.

If users cannot read the event log, use a separate protected SYSTEM collector and a per-user renderer. Secure that handoff so standard users cannot inject notification text or actions.
