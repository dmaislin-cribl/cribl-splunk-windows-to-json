# [Feature] Native Windows message-file resolution (`%%NNNN` codes) in Cribl Edge Windows Event Log sources

**Type:** New Feature / Enhancement
**Component:** Cribl Edge — Windows Event Log source (WinEventLog / WEC / XML)
**Priority:** Medium-High *(blocks full Splunk UF replacement for Windows collection)*
**Labels:** `edge`, `windows`, `event-log`, `parity/uf`, `security`

---

## Summary

Cribl Edge's Windows Event Log sources emit event field values that still contain raw Windows message-file placeholder codes (`%%NNNN`, e.g. `%%14592`, `%%1826`), rather than the human-readable strings those codes represent (`Inbound`, `False`). The Splunk Universal Forwarder resolves these at collection time via the standard `FormatMessage()` Win32 API and its `WinEventLog` input's `renderedText=true` option. Edge should offer the same resolution natively so operators can migrate off the UF without downstream lookup gymnastics and without shipping snapshot CSVs that drift versus the real Windows DLLs.

---

## Problem Statement

When Windows generates a security or WFP event, several fields carry values that are references into a message table compiled into a resource DLL — not the string itself. A typical Event ID 5152 (WFP Packet Drop) collected today by Cribl Edge looks like this in `_raw`:

```xml
<EventData>
  <Data Name="ProcessId">10584</Data>
  <Data Name="Application">\device\harddiskvolume3\...\svchost.exe</Data>
  <Data Name="Direction">%%14592</Data>
  <Data Name="LayerName">%%14610</Data>
  <Data Name="IsLoopback">%%1826</Data>
</EventData>
```

What Event Viewer (and the Splunk UF with `renderedText=true`) show for the same event:

```
Direction:   Inbound
LayerName:   Receive/Accept
IsLoopback:  False
```

Downstream SIEMs, analytics platforms, and dashboards see the raw `%%NNNN` placeholders — every filter, correlation rule, and saved search that expects `Direction=Inbound` returns zero hits.

---

## Root Cause

Windows stores these string values in Message-Table resources compiled into resource DLLs on the collecting machine:

| DLL | Typical `%%NNNN` ranges | Used by |
|---|---|---|
| `adtschema.dll` | 1500–14700 | Security channel audit field values (Access Rights, Impersonation Level, UAC flags, Audit Categories & Subcategories, WFP Direction & Layer Name, Firewall Profile, …) |
| `msobjs.dll` | Low-numbered | Object types |
| `authz.dll` | Various | Authorization / access-check strings |
| `iasnap.dll` | Various | IAS/NPS network policy strings |
| `wsecedit.dll` | Various | Security policy strings |
| Provider-specific DLLs (Defender, PowerShell, TerminalServices, …) | Per-provider | Their own events |

Each `%%NNNN` is a message ID that any consumer must resolve via `FormatMessage()`. Windows Event Viewer does this. The Splunk UF does this. Cribl Edge does not — the raw placeholders flow through into `_raw`.

---

## Impact

1. **Not a drop-in UF replacement.** Organizations migrating from Splunk UF to Cribl Edge for Windows event collection cannot swap 1-for-1; their downstream searches and dashboards immediately start missing events they were finding before.
2. **Broken SIEM searches and dashboards.** `Direction=Inbound`, `Action=Allowed`, `LogonType=Interactive` — none of these hit because the raw field is `%%NNNN` in Edge's output.
3. **Downstream workarounds are structurally lossy.** Cribl Packs and Splunk TAs can ship lookup CSVs to translate the codes at pipeline or search time, but:
   - The CSV is always slightly stale versus the actual Windows DLLs (Microsoft adds codes with every feature update).
   - The resolution happens after XML/JSON parsing, so it costs extra pipeline work per event.
   - There's no clean way in Splunk `props.conf` to alias arbitrary nested fields against a lookup — you need one `LOOKUP-*` per field per stanza, which doesn't scale.
4. **Multi-language / regional installations get wrong strings.** A curated CSV is single-locale; the on-host DLL resolves correctly for the machine's installed language pack.

---

## Proposed Solution

Add a **"Resolve message-file codes"** option to the Cribl Edge Windows Event Log source (WinEventLog, WEC, XML rendering paths). When enabled — recommended default **on** — Edge performs the same `FormatMessage()` resolution the UF does, before emitting the event.

### Technical Approach

Use the standard Win32 API pattern:

```c
// Load the message-source DLL as a data file (no code execution)
HMODULE h = LoadLibraryExW(dllPath, NULL, LOAD_LIBRARY_AS_DATAFILE);

// Resolve the message
WCHAR buffer[4096];
DWORD chars = FormatMessageW(
    FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
    h,
    messageId,        // e.g. 14592
    0,                // default installed language
    buffer,
    ARRAYSIZE(buffer),
    NULL);

// buffer now holds "Inbound"
FreeLibrary(h);
```

Provider-to-DLL mapping lives in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Provider>` → `ProviderMessageFileName` (semicolon-separated list of DLL paths). Edge already parses the event's Provider element; the mapping lookup is one registry read per new provider seen.

The same APIs are exposed in .NET (`System.Diagnostics.Eventing.Reader.ProviderMetadata.LoadResources()` and `.FormatMessage()`) and via `syscall/js/win32` bindings for Go, so implementation is idiomatic regardless of Edge's underlying stack.

**Implementation notes:**

- **Cache DLL handles per provider.** DLLs don't change during an Edge session. One `LoadLibraryEx` + one registry lookup per unique provider observed, amortized across all events from that provider.
- **Language handling.** Passing `0` for `dwLanguageId` resolves to the DLL's default (host-installed) language, matching what Event Viewer and the UF do. Optionally expose a `Preferred language` field for advanced setups.
- **Fallback / graceful degradation.** If the DLL is missing, `FormatMessage` returns 0, or resolution otherwise fails, pass the raw `%%NNNN` through unchanged. Never drop the original value — a placeholder is always more useful than an empty field.
- **Applies to both XML and Classic rendering paths.** For classic (already-rendered) events, resolution has typically already happened server-side; only newly-collected XML needs this treatment. But the option should be uniform for consistency.
- **Metrics.** Emit `windows_msgcode_resolved_total` / `windows_msgcode_unresolved_total` counters so operators can see resolution health per source.

### Reference Implementation

The public Cribl pack [`windows_events_to_nested_json`](https://cribl.io/community/packs) ships a working PowerShell reference implementation at `data/lookups/regenerate_windows_msg_codes.ps1` (~200 lines, read-only, no dependencies beyond PowerShell 5.1+). It uses exactly the `LoadLibraryEx` + `FormatMessage` sequence described above against `adtschema.dll`, `msobjs.dll`, `authz.dll`, `iasnap.dll`, and `wsecedit.dll`. Cribl engineering can use it as a functional reference or test harness — feed it a list of `%%NNNN` codes and it will produce the resolved strings for whichever Windows build it's run against.

---

## Alternatives Considered

| Approach | Pros | Cons |
|---|---|---|
| **Native Edge resolution (this request)** | UF parity, correct per-host, no downstream burden, cached and fast | Requires Win32 API code in Edge |
| Pack-side JS walker + CSV lookup *(current workaround in `windows_events_to_nested_json` v0.0.17)* | Works today; user-updatable via CSV | CSV always slightly stale vs host DLLs; extra pipeline work; single-locale |
| Splunk-TA-side `LOOKUP-*` declarations | Purely declarative | Requires one `LOOKUP-*` per field per stanza across dozens of stanzas; doesn't scale as Microsoft adds new fields |
| Downstream analytics-tool resolution (SIEM search-time) | No collector change | Per-event, per-search cost; leaves raw event garbled; every SIEM needs its own copy of the table |

Only native Edge resolution matches UF's behavior, keeps the table current with the actual Windows DLLs on the collecting hosts, and imposes no downstream burden.

---

## Acceptance Criteria

1. Cribl Edge Windows Event Log source exposes a **"Resolve message-file codes"** boolean option in the UI and via API / CLI configuration. Recommended default: **on**.
2. When enabled: any `%%NNNN` in the emitted event's field values is replaced with the human-readable string resolved via `FormatMessage()` against the appropriate DLL for the event's provider.
3. When resolution fails (DLL missing, message ID unknown, `FormatMessage` returns 0 chars): the raw `%%NNNN` passes through unchanged. No data loss, no exceptions.
4. When disabled: current behavior preserved (raw `%%NNNN` in output) — no change for existing pipelines.
5. DLL handles are cached per provider for the lifetime of the Edge process; not opened per event.
6. Behavior matches Splunk UF's `WinEventLog` input with `renderedText=true` for the same events on the same host.
7. Per-source configuration (an operator can enable resolution on some sources and not others).
8. Prometheus / internal metrics for resolved vs unresolved code counts.
9. Documented in the Windows Event Log source configuration reference alongside the existing options.
10. Locale respected: resolution uses the DLL's default installed language, matching Event Viewer's rendering on the same host.

---

## Test Cases

| # | Event | Field with `%%NNNN` | Expected output |
|---|---|---|---|
| 1 | 5152 (WFP Packet Drop) | `Direction=%%14592` | `Direction=Inbound` |
| 2 | 5157 (WFP Connection) | `LayerName=%%14610` | `LayerName=Receive/Accept` |
| 3 | 5157 (WFP Connection) | `IsLoopback=%%1826` | `IsLoopback=False` |
| 4 | 5157 (WFP Connection) | `Direction=%%14593` | `Direction=Outbound` |
| 5 | 4624 (Successful Logon) | `ImpersonationLevel=%%1833` | `ImpersonationLevel=Impersonation` |
| 6 | 4624 (Successful Logon) | `ElevatedToken=%%1842` | `ElevatedToken=Yes` |
| 7 | 4720 (User Account Created) | UAC flags `%%2049`, `%%2050`, … | `'Home Directory Required' - Disabled`, `'Password Not Required' - Disabled`, … |
| 8 | 4672 (Special Privileges) | Privilege list containing `%%1620` | `Debug Privilege` |
| 9 | 4663 (Object Access) | AccessMask components e.g. `%%1537` | `DELETE` |
| 10 | 4719 (Audit Policy Change) | Subcategory `%%12544` | `Logon` |
| 11 | Unknown code `%%99999` (not in any DLL) | Raw passes through | `%%99999` unchanged, no error, unresolved counter increments |
| 12 | Toggle off | All above | Raw `%%NNNN` values preserved |
| 13 | Non-English locale (e.g. `de-DE` machine) | `Direction=%%14592` | German-language string for "Inbound" (whatever the localized DLL emits) |
| 14 | Provider not previously seen (cache miss) | Resolution succeeds on first event; cache populated | Resolved value; subsequent events from same provider use cached handle |

---

## Related

- **Public Cribl Pack:** [`windows_events_to_nested_json`](https://cribl.io/community/packs) v0.0.17 — currently implements this as a pipeline-level workaround using a shipped 979-row lookup CSV extracted from `adtschema.dll`. Ships a PowerShell regeneration script that demonstrates the target API sequence.
- **Splunk UF baseline:** `WinEventLog` input, `renderedText=true`. This is the behavior operators expect to preserve when migrating.
- **Microsoft documentation:**
  - [FormatMessage function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew)
  - [LoadLibraryEx function](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
  - [Message-Table Resources](https://learn.microsoft.com/en-us/windows/win32/menurc/message-table-resources)
- **Community references:**
  - [nsacyber/Event-Forwarding-Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) — maintained snapshot of `adtschema.dll` codes; used as the source for the pack's shipping CSV.

---

## Business Justification

Every Windows-events customer engagement currently requires either the workaround pack (extra ops overhead, drifts vs Windows updates) or a formal design conversation about why raw `%%NNNN` is in their data. This is a well-scoped feature with a clear reference implementation and Microsoft-supported API. Adding it moves Cribl Edge from "very close" to "true drop-in replacement" for the UF in Windows event collection scenarios, and eliminates a recurring class of support/consulting engagements.
