# Intune machine PATH order remediation

These Windows PowerShell 5.1 scripts check and remediate the **machine** PATH
stored in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.
Deploy `Detect-MachinePathOrder.ps1` as the Intune detection script and
`Remediate-MachinePathOrder.ps1` as its remediation script. Run them in the
64-bit PowerShell host and configure the remediation to run as SYSTEM.

The scripts stably order existing entries as follows:

1. Windows paths, with the standard Windows directories prioritized in this
   order: `System32`, the Windows directory, `System32\Wbem`,
   `System32\WindowsPowerShell\v1.0`, and `System32\OpenSSH`.
2. Recognized Microsoft tool directories directly under Program Files,
   including Microsoft products, Windows Kits, .NET, PowerShell, Azure CLI,
   and Visual Studio.
3. Other existing entries, including third-party tools.
4. Paths considered user-writable, including UNC paths.

Writable paths take precedence over their vendor category. Existing entries
retain their original spelling and relative order within a category. The
remediation removes empty PATH entries (which can resolve to the current
directory); it does not add missing Windows defaults, remove duplicates, or
modify the per-user PATH. An unrecognized Microsoft tool directory is treated
as third-party and can be added to the classifier if needed.

The writable-path check is deliberately conservative: it inspects the ACL of
the path or its nearest existing parent, and treats non-system-owned paths or
write-capable allow rules for non-system principals as writable. ACL access
errors fail the script rather than silently treating a path as safe.

Detection exits `0` when compliant and `1` when remediation is needed or
detection fails. Remediation writes the original registry value type
(`REG_EXPAND_SZ` or `REG_SZ`) and exits nonzero on errors. The change applies
to newly created environment blocks; already-running processes may need to be
restarted.

Placing writable directories last is defense in depth, not a complete fix for
command path injection: applications may still search PATH when an expected
executable is absent. Prefer not to place user-writable directories in the
machine PATH, and ensure executable lookup is explicitly constrained where
possible.
