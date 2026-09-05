[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Administrator = New-Object System.Security.Principal.WindowsPrincipal(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Administrator.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Device-wide WDACToast data cleanup requires an elevated administrator or SYSTEM context.'
}

$ProfileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$RelativeStatePath = 'AppData\Local\Company\WDACToast'
$Failures = [System.Collections.Generic.List[string]]::new()

# ProfileImagePath is machine inventory. Deliberately do not load NTUSER.DAT or
# access HKEY_USERS: the per-user AppUserModelID is harmless after uninstall.
$ProfileDirectories = @(Get-ChildItem -LiteralPath $ProfileListPath -ErrorAction Stop |
    ForEach-Object {
        $Profile = Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue
        if ($null -ne $Profile -and -not [string]::IsNullOrWhiteSpace([string]$Profile.ProfileImagePath)) {
            [Environment]::ExpandEnvironmentVariables([string]$Profile.ProfileImagePath)
        }
    } |
    Sort-Object -Unique)

foreach ($ProfileDirectory in $ProfileDirectories) {
    try {
        $CanonicalProfileDirectory = [System.IO.Path]::GetFullPath($ProfileDirectory).TrimEnd('\')
        if (-not [System.IO.Path]::IsPathRooted($CanonicalProfileDirectory)) {
            throw "Profile path '$ProfileDirectory' is not rooted."
        }
        if ($CanonicalProfileDirectory.StartsWith('\\')) {
            throw "Profile path '$ProfileDirectory' is not local."
        }
        $StateDirectory = [System.IO.Path]::GetFullPath((Join-Path $CanonicalProfileDirectory $RelativeStatePath))
        $ExpectedStateDirectory = "$CanonicalProfileDirectory\$RelativeStatePath"
        if (-not [string]::Equals($StateDirectory, $ExpectedStateDirectory, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing unexpected cleanup path '$StateDirectory'."
        }
        $RemovalAttempted = (Test-Path -LiteralPath $StateDirectory) -and
            $PSCmdlet.ShouldProcess($StateDirectory, 'Remove WDACToast logs, diagnostics, review reports, and duplicate state')
        if ($RemovalAttempted) {
            Remove-Item -LiteralPath $StateDirectory -Recurse -Force -ErrorAction Stop
        }
        if ($RemovalAttempted -and (Test-Path -LiteralPath $StateDirectory)) {
            throw "State directory '$StateDirectory' still exists."
        }
    }
    catch {
        $Failures.Add("$ProfileDirectory`: $($_.Exception.Message)")
        Write-Warning $Failures[$Failures.Count - 1]
    }
}

if ($Failures.Count -gt 0) {
    throw "Device-wide WDACToast data cleanup completed with $($Failures.Count) failure(s)."
}
Write-Verbose "Checked $($ProfileDirectories.Count) profile path(s); only '$RelativeStatePath' targets were considered."
