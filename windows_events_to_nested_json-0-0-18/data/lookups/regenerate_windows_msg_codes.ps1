<#
.SYNOPSIS
    Regenerates windows_msg_codes.csv from the message tables compiled into
    this Windows machine's DLLs.

.DESCRIPTION
    Windows event log %%NNNN placeholder codes are message-ID references
    into resource DLLs on the machine that generated the event. When the
    Splunk Universal Forwarder or Event Viewer renders an event, it loads
    the DLL and calls FormatMessage() to resolve %%NNNN → human-readable
    text. Different Windows versions ship different message tables, so a
    lookup table extracted from one build may miss codes present on another.

    This script uses the same mechanism Windows itself uses:
    LoadLibraryEx + FormatMessage via P/Invoke. It's read-only and makes
    no system changes.

    Run on an admin-elevated PowerShell session on a Windows Server host
    that represents the version you're collecting events from. The output
    CSV drops directly into a Cribl Pack at:
        <pack-root>/data/lookups/windows_msg_codes.csv

    Also update the sibling .yml (size and rows) so Cribl notices the change.

.PARAMETER OutputCsv
    Where to write the generated CSV. Defaults to .\windows_msg_codes.csv in
    the current directory.

.PARAMETER Dlls
    Which resource DLLs to extract from. Defaults to the five main sources
    of audit-field %%NNNN placeholder strings on modern Windows:
        adtschema.dll  - Security audit field values (most of %%1537-%%14646)
        msobjs.dll     - Object types (usually low-numbered %%N)
        authz.dll      - Authorization / access-check strings
        iasnap.dll     - IAS/NPS network policy strings
        wsecedit.dll   - Security policy strings

.PARAMETER MinMessageId, MaxMessageId
    Range of message IDs to probe. Defaults 1..30000 (covers everything
    known to appear in Windows Server 2016 through 2022). Fast — even a
    30k-iteration probe against 5 DLLs runs in under a minute.

.EXAMPLE
    .\regenerate_windows_msg_codes.ps1

    Writes .\windows_msg_codes.csv with every %%NNNN string this machine's
    DLLs can produce.

.EXAMPLE
    .\regenerate_windows_msg_codes.ps1 -OutputCsv C:\temp\codes.csv `
        -Dlls "$env:SystemRoot\System32\adtschema.dll"

    Restrict to adtschema.dll only (fastest — gets the audit-field codes
    but not the object-type codes from msobjs.dll).

.NOTES
    Requires PowerShell 5.1 or newer. No Splunk, Cribl, or third-party
    dependencies. Uses only kernel32.dll P/Invoke.

    Compatible with Windows Server 2012 R2 and newer. Windows 10 / 11
    Pro editions also work.
#>

[CmdletBinding()]
param(
    [string]$OutputCsv = '.\windows_msg_codes.csv',

    [string[]]$Dlls = @(
        "$env:SystemRoot\System32\adtschema.dll",
        "$env:SystemRoot\System32\msobjs.dll",
        "$env:SystemRoot\System32\authz.dll",
        "$env:SystemRoot\System32\iasnap.dll",
        "$env:SystemRoot\System32\wsecedit.dll"
    ),

    [int]$MinMessageId = 1,
    [int]$MaxMessageId = 30000
)

# ---------------------------------------------------------------------------
# P/Invoke shim — LoadLibraryEx + FormatMessage. Same call sequence Windows
# itself uses when Event Viewer renders %%NNNN placeholders.
# ---------------------------------------------------------------------------
if (-not ('Cribl.WinMsgTable' -as [type])) {
    Add-Type -Namespace 'Cribl' -Name 'WinMsgTable' -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern System.IntPtr LoadLibraryEx(string lpFileName, System.IntPtr hFile, uint dwFlags);

[DllImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool FreeLibrary(System.IntPtr hModule);

[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern uint FormatMessage(
    uint dwFlags,
    System.IntPtr lpSource,
    uint dwMessageId,
    uint dwLanguageId,
    System.Text.StringBuilder lpBuffer,
    uint nSize,
    System.IntPtr Arguments);
'@
}

$LOAD_LIBRARY_AS_DATAFILE      = 0x00000002
$FORMAT_MESSAGE_FROM_HMODULE   = 0x00000800
$FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

# ---------------------------------------------------------------------------
# Category derivation — maps a numeric %%NNNN code to the friendly category
# label the pack's shipping CSV uses. Ranges are documented in the Microsoft
# adtschema.dll message-table structure, cross-referenced against the
# authoritative nsacyber/Event-Forwarding-Guidance list. Codes outside these
# ranges are marked 'Other' and can be re-categorized manually.
# ---------------------------------------------------------------------------
function Get-CategoryForCode {
    param([int]$Code)
    if ($Code -eq 1536)                       { return 'Reserved / Unused' }
    if ($Code -ge 1537  -and $Code -le 1567)  { return 'Standard Access Rights' }
    if ($Code -eq 1601 -or ($Code -ge 1603 -and $Code -le 1624)) { return 'Privilege' }
    if ($Code -ge 1792  -and $Code -le 1799)  { return 'Audit Policy State' }
    if ($Code -eq 1800)                       { return 'Registry Value Notice' }
    if ($Code -ge 1801  -and $Code -le 1816)  { return 'Access Reason' }
    if ($Code -ge 1817  -and $Code -le 1823)  { return 'Value Type' }
    if ($Code -ge 1824  -and $Code -le 1826)  { return 'Boolean' }
    if ($Code -ge 1827  -and $Code -le 1829)  { return 'Value Status' }
    if ($Code -eq 1830)                       { return 'Access Reason' }
    if ($Code -ge 1831  -and $Code -le 1834)  { return 'Impersonation Level' }
    if ($Code -eq 1840)                       { return 'Impersonation Level' }
    if ($Code -eq 1841)                       { return 'Access Reason' }
    if ($Code -ge 1842  -and $Code -le 1843)  { return 'Boolean' }
    if ($Code -ge 1844  -and $Code -le 1849)  { return 'Setting Value' }
    if ($Code -eq 1856)                       { return 'Access Reason' }
    if ($Code -ge 1872  -and $Code -le 1883)  { return 'Registry Value Type' }
    if ($Code -ge 1904  -and $Code -le 1906)  { return 'Registry Action' }
    if ($Code -ge 1920  -and $Code -le 1926)  { return 'Day of Week' }
    if ($Code -ge 1936  -and $Code -le 1938)  { return 'Token Elevation Type' }
    if ($Code -ge 2048  -and $Code -le 2111)  { return 'User Account Control' }
    if ($Code -ge 2304  -and $Code -le 2315)  { return 'Logon Failure Reason' }
    if ($Code -ge 2432  -and $Code -le 2503)  { return 'Cryptographic Operation' }
    if ($Code -ge 4352  -and $Code -le 4367)  { return 'Device Access Rights' }
    if ($Code -ge 4368  -and $Code -le 4383)  { return 'Directory Access Rights' }
    if ($Code -ge 4384  -and $Code -le 4399)  { return 'Event Object Access Rights' }
    if ($Code -ge 4416  -and $Code -le 4431)  { return 'File Access Rights' }
    if ($Code -ge 4432  -and $Code -le 4447)  { return 'Registry Key Access Rights' }
    if ($Code -ge 4448  -and $Code -le 4463)  { return 'Mutant Access Rights' }
    if ($Code -ge 4464  -and $Code -le 4479)  { return 'Port Access Rights' }
    if ($Code -ge 4480  -and $Code -le 4495)  { return 'Process Access Rights' }
    if ($Code -ge 4496  -and $Code -le 4511)  { return 'Profile Access Rights' }
    if ($Code -ge 4512  -and $Code -le 4527)  { return 'Section Access Rights' }
    if ($Code -ge 4528  -and $Code -le 4543)  { return 'Semaphore Access Rights' }
    if ($Code -ge 4544  -and $Code -le 4559)  { return 'Symbolic Link Access Rights' }
    if ($Code -ge 4560  -and $Code -le 4575)  { return 'Thread Access Rights' }
    if ($Code -ge 4576  -and $Code -le 4591)  { return 'Timer Access Rights' }
    if ($Code -ge 4592  -and $Code -le 4607)  { return 'Token Access Rights' }
    if ($Code -ge 4608  -and $Code -le 4623)  { return 'Type Access Rights' }
    if ($Code -ge 4864  -and $Code -le 4865)  { return 'Object State' }
    if ($Code -ge 5120  -and $Code -le 5135)  { return 'Channel Access Rights' }
    if ($Code -ge 5136  -and $Code -le 5151)  { return 'Job Access Rights' }
    if ($Code -ge 5376  -and $Code -le 5391)  { return 'SAM Server Access Rights' }
    if ($Code -ge 5392  -and $Code -le 5407)  { return 'SAM Domain Access Rights' }
    if ($Code -ge 5408  -and $Code -le 5423)  { return 'SAM Group Access Rights' }
    if ($Code -ge 5424  -and $Code -le 5439)  { return 'SAM Alias Access Rights' }
    if ($Code -ge 5440  -and $Code -le 5455)  { return 'SAM User Access Rights' }
    if ($Code -ge 5632  -and $Code -le 5647)  { return 'LSA Policy Access Rights' }
    if ($Code -ge 5648  -and $Code -le 5663)  { return 'LSA Secret Access Rights' }
    if ($Code -ge 5664  -and $Code -le 5679)  { return 'LSA Trusted Domain Access Rights' }
    if ($Code -ge 5680  -and $Code -le 5695)  { return 'LSA Account Access Rights' }
    if ($Code -ge 5696  -and $Code -le 5711)  { return 'Keyed Event Access Rights' }
    if ($Code -ge 6656  -and $Code -le 6665)  { return 'Window Station Access Rights' }
    if ($Code -ge 6672  -and $Code -le 6680)  { return 'Desktop Access Rights' }
    if ($Code -ge 6912  -and $Code -le 6948)  { return 'Printer Access Rights' }
    if ($Code -ge 7168  -and $Code -le 7173)  { return 'Service Control Manager Access Rights' }
    if ($Code -ge 7184  -and $Code -le 7192)  { return 'Service Access Rights' }
    if ($Code -ge 7424  -and $Code -le 7433)  { return 'DDE Share Access Rights' }
    if ($Code -ge 7680  -and $Code -le 7695)  { return 'Directory Service Access Rights' }
    if ($Code -ge 7936  -and $Code -le 7942)  { return 'Audit Policy Access Rights' }
    if ($Code -ge 8064  -and $Code -le 8065)  { return 'Terminal Services Access Rights' }
    if ($Code -ge 8096  -and $Code -le 8103)  { return 'Credentials Access Rights' }
    if ($Code -ge 8192  -and $Code -le 8198)  { return 'IPsec Authentication Method' }
    if ($Code -ge 8199  -and $Code -le 8248)  { return 'IPsec / IKE State' }
    if ($Code -ge 8272  -and $Code -le 8280)  { return 'Audit Category' }
    if ($Code -ge 8448  -and $Code -le 8459)  { return 'Audit Policy Change' }
    if ($Code -ge 12288 -and $Code -le 14339) { return 'Audit Subcategory' }
    if ($Code -ge 14592 -and $Code -le 14604) { return 'WFP Direction' }
    if ($Code -ge 14608 -and $Code -le 14624) { return 'WFP Layer Name' }
    if ($Code -ge 14640 -and $Code -le 14642) { return 'WFP Layer Name' }
    if ($Code -eq 14672 -or $Code -eq 14673)  { return 'Value Representation' }
    if ($Code -ge 14674 -and $Code -le 14675) { return 'Directory Service Change Action' }
    if ($Code -ge 14676 -and $Code -le 14677) { return 'Directory Service Type' }
    if ($Code -ge 14678 -and $Code -le 14679) { return 'Boolean' }
    if ($Code -ge 14680 -and $Code -le 14688) { return 'Directory Service Change Action' }
    if ($Code -ge 16384 -and $Code -le 16416) { return 'IPsec Algorithm / Setting' }
    if ($Code -ge 16896 -and $Code -le 16905) { return 'WMI Operation' }
    return 'Other'
}

# Best-effort mapping of code range to the security event ID where it most
# commonly appears. Purely informational — the resolution logic in the pack
# doesn't consult this field. Blank for codes we don't have a canonical
# source event for.
function Get-SourceEventForCode {
    param([int]$Code)
    if ($Code -eq 279)                        { return '4656' }
    if ($Code -eq 1536)                       { return '' }
    if ($Code -ge 1537  -and $Code -le 1567)  { return '4656' }
    if ($Code -eq 1601 -or ($Code -ge 1603 -and $Code -le 1624)) { return '4672' }
    if ($Code -ge 1792  -and $Code -le 1799)  { return '4719' }
    if ($Code -eq 1800)                       { return '4657' }
    if ($Code -ge 1801  -and $Code -le 1816)  { return '4663' }
    if ($Code -ge 1817  -and $Code -le 1823)  { return '4657' }
    if ($Code -ge 1824  -and $Code -le 1826)  { return '5157' }
    if ($Code -ge 1827  -and $Code -le 1829)  { return '4663' }
    if ($Code -eq 1830)                       { return '4663' }
    if ($Code -ge 1831  -and $Code -le 1834)  { return '4624' }
    if ($Code -eq 1840)                       { return '4624' }
    if ($Code -eq 1841)                       { return '4663' }
    if ($Code -ge 1842  -and $Code -le 1843)  { return '4624' }
    if ($Code -ge 1844  -and $Code -le 1849)  { return '4719' }
    if ($Code -eq 1856)                       { return '4663' }
    if ($Code -ge 1872  -and $Code -le 1883)  { return '4657' }
    if ($Code -ge 1904  -and $Code -le 1906)  { return '4657' }
    if ($Code -ge 1920  -and $Code -le 1926)  { return '4739' }
    if ($Code -ge 1936  -and $Code -le 1938)  { return '4624' }
    if ($Code -ge 2048  -and $Code -le 2111)  { return '4720' }
    if ($Code -ge 2304  -and $Code -le 2315)  { return '4625' }
    if ($Code -ge 2432  -and $Code -le 2503)  { return '5061' }
    if ($Code -ge 4352  -and $Code -le 4623)  { return '4656' }
    if ($Code -ge 4416  -and $Code -le 4447)  { return '4663' }
    if ($Code -ge 4864  -and $Code -le 4865)  { return '4656' }
    if ($Code -ge 5120  -and $Code -le 5151)  { return '4656' }
    if ($Code -ge 5376  -and $Code -le 5455)  { return '4661' }
    if ($Code -ge 5632  -and $Code -le 5711)  { return '4661' }
    if ($Code -ge 6656  -and $Code -le 6680)  { return '4656' }
    if ($Code -ge 6912  -and $Code -le 6948)  { return '4656' }
    if ($Code -ge 7168  -and $Code -le 7192)  { return '4656' }
    if ($Code -ge 7424  -and $Code -le 7433)  { return '4656' }
    if ($Code -ge 7680  -and $Code -le 7695)  { return '4661' }
    if ($Code -ge 7936  -and $Code -le 7942)  { return '4719' }
    if ($Code -ge 8064  -and $Code -le 8065)  { return '4656' }
    if ($Code -ge 8096  -and $Code -le 8103)  { return '4661' }
    if ($Code -ge 8192  -and $Code -le 8198)  { return '4646' }
    if ($Code -ge 8199  -and $Code -le 8248)  { return '4650' }
    if ($Code -ge 8272  -and $Code -le 8280)  { return '4719' }
    if ($Code -ge 8448  -and $Code -le 8459)  { return '4719' }
    if ($Code -ge 12288 -and $Code -le 14339) { return '4719' }
    if ($Code -ge 14592 -and $Code -le 14642) { return '5157' }
    if ($Code -ge 14672 -and $Code -le 14688) { return '5136' }
    if ($Code -ge 16384 -and $Code -le 16416) { return '5040' }
    if ($Code -ge 16896 -and $Code -le 16905) { return '4671' }
    return ''
}

function Get-DllMessage {
    param([IntPtr]$Module, [int]$Code)
    $sb = New-Object System.Text.StringBuilder 4096
    $chars = [Cribl.WinMsgTable]::FormatMessage(
        [uint32]($FORMAT_MESSAGE_FROM_HMODULE -bor $FORMAT_MESSAGE_IGNORE_INSERTS),
        $Module,
        [uint32]$Code,
        [uint32]0,   # neutral language — falls back to whatever default the DLL exposes
        $sb,
        [uint32]$sb.Capacity,
        [IntPtr]::Zero)
    if ($chars -eq 0) { return $null }
    return $sb.ToString().TrimEnd([char[]]("`r","`n"," ","`t"))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host "Windows message-code extraction — $(Get-Date -Format 's')"
Write-Host "Host: $env:COMPUTERNAME  |  OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Host "Probing message IDs $MinMessageId..$MaxMessageId across $($Dlls.Count) DLL(s)"
Write-Host ''

$allRows = New-Object System.Collections.Generic.List[object]

foreach ($dll in $Dlls) {
    if (-not (Test-Path $dll)) {
        Write-Warning "DLL not found, skipping: $dll"
        continue
    }
    Write-Host "  $([IO.Path]::GetFileName($dll)) ..."
    $hModule = [Cribl.WinMsgTable]::LoadLibraryEx($dll, [IntPtr]::Zero, [uint32]$LOAD_LIBRARY_AS_DATAFILE)
    if ($hModule -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Warning "    LoadLibraryEx failed (Win32 error $err) — skipping"
        continue
    }
    try {
        $found = 0
        for ($id = $MinMessageId; $id -le $MaxMessageId; $id++) {
            $msg = Get-DllMessage -Module $hModule -Code $id
            if ($msg -and $msg.Trim().Length -gt 0) {
                $allRows.Add([PSCustomObject]@{
                    _codeInt = $id
                    code     = "%%$id"
                    value    = $msg
                    category = (Get-CategoryForCode $id)
                    microsoft_source_event = (Get-SourceEventForCode $id)
                    source_dll = [IO.Path]::GetFileName($dll)
                }) | Out-Null
                $found++
            }
        }
        Write-Host "    -> $found messages"
    }
    finally {
        [Cribl.WinMsgTable]::FreeLibrary($hModule) | Out-Null
    }
}

# Deduplicate on code — first DLL wins. adtschema.dll is listed first so its
# strings take precedence for any overlap with other DLLs.
$seen = @{}
$deduped = foreach ($r in ($allRows | Sort-Object _codeInt)) {
    if (-not $seen.ContainsKey($r.code)) {
        $seen[$r.code] = $true
        $r
    }
}

Write-Host ''
Write-Host "Extracted $($allRows.Count) messages ($($deduped.Count) unique)"

# Write CSV in the pack's schema — same 4 columns as the shipping lookup.
$deduped |
    Select-Object code, value, category, microsoft_source_event |
    Export-Csv -NoTypeInformation -Path $OutputCsv -Encoding UTF8

$sz = (Get-Item $OutputCsv).Length
Write-Host "Wrote $OutputCsv ($sz bytes)"
Write-Host ''
Write-Host "Next steps:"
Write-Host "  1. Copy $OutputCsv to <your-pack>/data/lookups/windows_msg_codes.csv"
Write-Host "  2. Update <your-pack>/data/lookups/windows_msg_codes.yml:"
Write-Host "        size: $sz"
Write-Host "        rows: $($deduped.Count)"
Write-Host "        version: v0-0-15-regenerated-$(Get-Date -Format 'yyyyMMdd')"
Write-Host "  3. Re-import the pack in Cribl or reload the pipeline"
Write-Host ''
Write-Host "Diff tip:"
Write-Host "    Compare-Object (Import-Csv .\windows_msg_codes.csv) ``"
Write-Host "                  (Import-Csv <your-pack>\data\lookups\windows_msg_codes.csv) ``"
Write-Host "                  -Property code,value"
Write-Host "  will show any codes your host has that the shipped lookup is missing."
