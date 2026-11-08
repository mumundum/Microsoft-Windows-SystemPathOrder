$ErrorActionPreference = 'Stop'

function Get-MachinePathValue {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        $false
    )
    if ($null -eq $key) {
        throw 'Unable to open the machine environment registry key.'
    }

    try {
        if ($null -eq $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) {
            throw 'The machine PATH registry value does not exist.'
        }
        return [string]$key.GetValue(
            'Path',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    finally {
        $key.Dispose()
    }
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Entry)

    $value = [Environment]::ExpandEnvironmentVariables($Entry.Trim().Trim('"')).Replace('/', '\')
    if ([string]::IsNullOrWhiteSpace($value)) {
        return ''
    }

    $value = $value.TrimEnd('\')
    if ($value -match '^[A-Za-z]:$') {
        $value += '\'
    }
    return $value
}

function Test-PathWritableByUsers {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '^\\\\' -or
        $Path -match '%' -or
        -not [System.IO.Path]::IsPathRooted($Path)) {
        return $true
    }

    $probe = $Path
    while (-not (Test-Path -LiteralPath $probe)) {
        $parent = ([System.IO.DirectoryInfo]::new($probe)).Parent
        if ($null -eq $parent -or $parent.FullName -eq $probe) {
            return $true
        }
        $probe = $parent.FullName
    }

    $item = Get-Item -LiteralPath $probe -Force
    if (-not $item.PSIsContainer) {
        $parent = ([System.IO.DirectoryInfo]::new($probe)).Parent
        if ($null -eq $parent) {
            return $true
        }
        $probe = $parent.FullName
    }

    $acl = Get-Acl -LiteralPath $probe
    $protectedSids = @(
        'S-1-5-18',
        'S-1-5-19',
        'S-1-5-20',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($protectedSids -notcontains $ownerSid) {
        return $true
    }

    $writeMask = [int](
        [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        0x50000000
    )
    $rules = $acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }

        if (([int]$rule.FileSystemRights -band $writeMask) -eq 0) {
            continue
        }

        $sid = $rule.IdentityReference.Value
        if ($protectedSids -notcontains $sid -and $sid -ne 'S-1-3-0') {
            return $true
        }
    }

    return $false
}

function Get-PathSortKey {
    param(
        [Parameter(Mandatory = $true)][string]$Entry,
        [Parameter(Mandatory = $true)][string]$WindowsRoot
    )

    $path = Get-NormalizedPath -Entry $Entry
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{ Group = 3; Rank = 0 }
    }

    if (Test-PathWritableByUsers -Path $path) {
        return [pscustomobject]@{ Group = 3; Rank = 0 }
    }

    $system32 = Join-Path $WindowsRoot 'System32'
    $defaults = @(
        $system32,
        $WindowsRoot,
        (Join-Path $system32 'Wbem'),
        (Join-Path $system32 'WindowsPowerShell\v1.0'),
        (Join-Path $system32 'OpenSSH')
    )
    for ($index = 0; $index -lt $defaults.Count; $index++) {
        if ([string]::Equals(
            $path.TrimEnd('\'),
            $defaults[$index].TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            return [pscustomobject]@{ Group = 0; Rank = $index }
        }
    }

    $normalizedWindowsRoot = $WindowsRoot.TrimEnd('\')
    if ($path.StartsWith(
        ($normalizedWindowsRoot + '\'),
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or [string]::Equals(
        $path,
        $normalizedWindowsRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        return [pscustomobject]@{ Group = 0; Rank = 100 }
    }

    $programRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($programRoot in $programRoots) {
        $normalizedRoot = (Get-NormalizedPath -Entry $programRoot).TrimEnd('\')
        if (-not $path.StartsWith(
            ($normalizedRoot + '\'),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            continue
        }

        $relativePath = $path.Substring($normalizedRoot.Length + 1)
        if ($relativePath -match '^(Microsoft[^\\]*|Windows Kits|dotnet|PowerShell|Windows Defender|WindowsApps|Azure CLI|Visual Studio)(\\|$)') {
            return [pscustomobject]@{ Group = 1; Rank = 0 }
        }
    }

    return [pscustomobject]@{ Group = 2; Rank = 0 }
}

function Get-OrderedPathEntries {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsRoot)) {
        throw 'Unable to determine the Windows directory.'
    }

    $entries = [regex]::Split($PathValue, ';')
    $sortable = for ($index = 0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $key = Get-PathSortKey -Entry $entry -WindowsRoot $windowsRoot
        [pscustomobject]@{
            Entry = $entry
            Group = $key.Group
            Rank = $key.Rank
            Index = $index
        }
    }

    return @($sortable | Sort-Object Group, Rank, Index | ForEach-Object { $_.Entry })
}

try {
    $pathValue = Get-MachinePathValue
    $entries = [regex]::Split($pathValue, ';')
    if ($entries | Where-Object { [string]::IsNullOrWhiteSpace($_) }) {
        Write-Output 'Noncompliant: machine PATH contains an empty entry.'
        exit 1
    }

    $ordered = Get-OrderedPathEntries -PathValue $pathValue
    $expected = [string]::Join(';', $ordered)
    if (-not [string]::Equals($pathValue, $expected, [System.StringComparison]::Ordinal)) {
        Write-Output 'Noncompliant: machine PATH entries are not in the required order.'
        exit 1
    }

    Write-Output 'Compliant: machine PATH entries are in the required order.'
    exit 0
}
catch {
    Write-Output ("Detection failed: {0}" -f $_.Exception.Message)
    exit 1
}
