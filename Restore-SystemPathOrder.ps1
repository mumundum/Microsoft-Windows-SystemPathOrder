<#
.SYNOPSIS
Restores the machine PATH from the latest local System PATH backup.

Run in 64-bit PowerShell as SYSTEM or an administrator.
Return: exits with code 0 on success and code 1 if restoration fails.
#>

$ErrorActionPreference = 'Stop'
$BackupDirectory = Join-Path $env:ProgramData 'SystemPathOrder\Backups'

try {
    if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
        throw ("Backup directory does not exist: {0}" -f $BackupDirectory)
    }

    $backup = Get-ChildItem -LiteralPath $BackupDirectory -Filter 'SystemPath-*.reg' -File |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $backup) {
        throw ("No System PATH backup was found in {0}." -f $BackupDirectory)
    }

    $regExe = Join-Path $env:windir 'System32\reg.exe'
    & $regExe import $backup.FullName
    if ($LASTEXITCODE -ne 0) {
        throw ("reg.exe import failed with exit code {0}." -f $LASTEXITCODE)
    }

    Write-Output ("Restored System PATH from {0}." -f $backup.FullName)
    exit 0
}
catch {
    Write-Output ("Restore failed: {0}" -f $_.Exception.Message)
    exit 1
}
