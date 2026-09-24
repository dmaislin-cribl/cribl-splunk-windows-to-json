# Windows Events to Nested JSON

---

## Scope and limits

This pack **only** targets **Windows Event Log–like** `_raw`: **XML** (`<Event>…`) or **classic** rendered text (headers + **Message**). It normalizes those to nested JSON and **`windows:json`** / **`windows:json:<Channel>`** metadata for **Cribl_TA_windows**. It does **not** replace dedicated pipelines for non–event-log-primary shapes (for example **DHCP server audit** files for **`DhcpSrvLog`**, **Perfmon**, **WMI** inventory, **registry** exports, etc.); plan a **separate Cribl pack (and Splunk TA)** if you need those as first-class products.

---

Cribl Pack that converts Windows Event Log data (**XML** or **Classic** rendered text) into nested JSON in `_raw`. Works with **Cribl Stream**, **Cribl Edge** (XML collection by default), and **Cribl_TA_windows** on Splunk.

**File-format alignment:** On disk, **`.evt`** is the older binary log (usually seen as **classic** rendered text in the pipeline). **`.evtx`** is the modern log and is commonly ingested as **XML** in `_raw`. This pack plus the Splunk TA cover **classic**, **XML**, and **JSON** (`windows:json`) end-to-end so you can standardize on nested JSON for Splunk without maintaining separate logic per extension.

## Overview

| Input | Detection |
|-------|-----------|
| **XML** | `_raw` (trimmed) starts with `<?xml` or `<Event` — typical for **Edge**, WEC/WEF, Splunk UF XML, Sysmon XML |
| **Classic** | Everything else — legacy `Key=Value` headers plus a **Message** body |

After the **Code** function, **`_raw`** is replaced with `JSON.stringify(parsed)`.

**Host:** When `ComputerName` exists on the parsed event (classic headers or `System.Computer` / `System.ComputerName` after XML cleanup), **`__e.host`** is set to that value so the event’s host metadata matches the Windows computer name.

All generated keys use **spaces → underscores** (e.g., `Account Name` → `Account_Name`).

## How it works

1. **XML** — `C.Text.parseWinEvent(_raw)`, then **`clean()`**:
   - Unwraps `{ _value: x }` / `#text` nodes  
   - Flattens named `<Data Name="...">` into objects  
   - Strips `xmlns`  
   - Normalizes key names  

2. **Classic** — **`parseClassic()`**:
   - Header lines: `Key=Value` (first line may be a bare timestamp)
   - **`Message=`** line: first segment is **`Message._summary`**; additional lines may be **embedded in the same header value** (CRLF-separated) or on **following physical lines**
   - Body lines: **`Key: Value`** or **`Key:`** + tab/value (same line or subsection headers like **`Subject:`** with nested fields)
   - Examples: structured sections (4670-style) **or** flat message keys (e.g. **4776**: `Authentication_Package`, `Logon_Account`, `Source_Workstation`, `Error_Code` on `Message`)

3. **Eval (metadata)** — The sample pipeline rewrites `source` / `sourcetype` for downstream systems. **For Splunk with Cribl_TA_windows**, use **`windows:json`** / **`windows:json:<Channel>`** (see below), not `WinEventLog:*` / `XmlWinEventLog:*` with JSON `_raw`.

## Splunk metadata (Cribl_TA_windows)

The TA matches **`[windows:json]`** and **`[source::windows:json...]`** in `default/props.conf` and uses **`KV_MODE = json`** on `_raw`. (The bare `[windows:json]` stanza is the Splunk-spec-valid sourcetype form; the older `[sourcetype::windows:json]` form isn't recognized by Splunk and was corrected in 0.0.13.)

**Cribl Edge** typically does **not** populate Splunk-style **`source`** / **`sourcetype`** (those come from the Splunk Universal Forwarder). The pack’s **Code** function sets **`windows:json`** and **`windows:json:<Channel>`** when those fields are empty, using **`System.Channel`** (XML) or **`LogName`** / **`Channel`** (classic). If you already set **`source`** upstream (e.g. UF), **Eval** still normalizes `WinEventLog:*` / `XmlWinEventLog:*` to **`windows:json:*`**.

Set the **Eval** function after the Code function to:

| Field | Value |
|--------|--------|
| `sourcetype` | `windows:json` |
| `source` | `windows:json:<Channel>` derived from the original source, e.g. `WinEventLog:Security` → `windows:json:Security` |

Example **Eval** `add` expressions (as shipped in this pack's pipeline):

```yaml
- name: sourcetype
  value: "(sourcetype === 'windows:json:parse_error') ? sourcetype : 'windows:json'"
- name: source
  value: >-
    (source != null && source !== '' && source.startsWith('WinEventLog:')) ? `windows:json:${source.replace(/^WinEventLog:/, '')}` :
    (source != null && source !== '' && source.startsWith('XmlWinEventLog:')) ? `windows:json:${source.replace(/^XmlWinEventLog:/, '')}` :
    (source != null && source !== '' && source.startsWith('json:windows:')) ? `windows:json:${source.replace(/^json:windows:/, '')}` :
    (source != null && source !== '' && source.startsWith('windows:json:')) ? source :
    (source != null && source !== '') ? `windows:json:${source}` : 'windows:json:Unknown'
```

The `sourcetype` guard preserves the `windows:json:parse_error` variant that the **Code** function sets in its `catch` block, so events that fail to parse are still routed to a distinct sourcetype instead of being silently rebucketed as healthy `windows:json`.

Do **not** rely on Splunk default **`WinEventLog` / `XmlWinEventLog`** props alone for JSON `_raw`; the TA’s **`windows:json`** stanzas are what deliver consistent extractions and CIM-oriented **FIELDALIAS** / **EVAL** chains.

Install **Cribl_TA_windows** on the indexer/search tier and deploy this pack on Cribl (Stream or Edge) **before** Splunk.

## Output shape (examples)

### XML → JSON

```json
{
  "System": {
    "EventID": "4670",
    "Computer": "hostname.example.com",
    "Channel": "Security",
    "Level": "0"
  },
  "EventData": {
    "SubjectUserName": "SYSTEM",
    "SubjectDomainName": "DOMAIN",
    "ObjectName": "-",
    "ProcessName": "C:\\Windows\\System32\\svchost.exe"
  }
}
```

### Classic → JSON (sectioned message, anonymized)

**Input (snippet):**

```text
Message=Permissions on an object were changed.
	Subject:
		Security ID:		NT AUTHORITY\SYSTEM
		Account Name:		HOSTNAME$
```

**Output (snippet):**

```json
"Message": {
  "_summary": "Permissions on an object were changed.",
  "Subject": {
    "Security_ID": "NT AUTHORITY\\SYSTEM",
    "Account_Name": "HOSTNAME$"
  }
}
```

### Classic → JSON (flat `Message` keys, e.g. 4776)

**Input (snippet):**

```text
Message=The computer attempted to validate the credentials for an account.
Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	CN=user,OU=corp,DC=example,DC=com
Source Workstation:	WORKSTATION01.corp.example.com:12345
Error Code:	0x0
```

**Output (snippet):**

```json
"Message": {
  "_summary": "The computer attempted to validate the credentials for an account.",
  "Authentication_Package": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
  "Logon_Account": "CN=user,OU=corp,DC=example,DC=com",
  "Source_Workstation": "WORKSTATION01.corp.example.com:12345",
  "Error_Code": "0x0"
}
```

## Route configuration

The default pack route sends all events to **`Windows_Events_to_Nested_JSON`**. Narrow the route in `default/pipelines/route.yml` if needed. Route filters use JavaScript, not SPL — use a regex `.test()` or `String.startsWith()`, not `=~`. For example:

```yaml
# Match Splunk UF Windows event sources (both classic and XML)
filter: '/^(?:Xml)?WinEventLog:/.test(source)'
```

```yaml
# Or match by sourcetype as well
filter: '/^(?:Xml)?WinEventLog:/.test(source) || (sourcetype && sourcetype.startsWith("WinEventLog"))'
```

For Edge-only Windows XML pipelines, tighten the filter to whatever **source** / **sourcetype** Edge assigns.

## CIM / field aliasing (Splunk TA)

Cribl_TA_windows maps nested JSON (including **`Message.*`**) to searchable and CIM-friendly fields via **`default/props.conf`** and **`default/transforms.conf`** (not a separate `props_windows_event_common.conf` in this app). Examples the TA understands alongside **`EventData.*` / `System.*`**:

| Concept | Example source paths |
|--------|----------------------|
| Message summary | `Message._summary` |
| Sectioned classic | `Message.Subject.Account_Name`, `Message.Process.Process_Name`, … |
| Flat classic keys | `Message.Logon_Account`, `Message.Authentication_Package`, `Message.Source_Workstation`, `Message.Error_Code` |
| Destination host | `ComputerName`, `System.Computer` |

See the TA README and `props.conf` for the full list of **FIELDALIAS**, **EVAL**, and **REPORT** rules.

## Pack layout (.crbl)

Ship as a **gzip tarball** with a **flat root** (required for Cribl import):

```text
package.json
README.md
default/
  pack.yml
  pipelines/
    route.yml
    Windows_Events_to_Nested_JSON/
      conf.yml
```

## Supported channels / event types

Security, System, Application, PowerShell, Sysmon, WMI, custom channels — any event **`parseWinEvent`** or the classic parser can represent without hardcoded per-event-ID lists.

## Regenerating the `%%NNNN` lookup from a live Windows host

Windows message-code strings live in resource DLLs on the collecting machine — different Windows versions ship different tables, and new codes get added as Windows evolves. Even Microsoft's own documentation doesn't publish a single authoritative list; the source of truth is whatever `adtschema.dll` / `msobjs.dll` / provider DLLs are actually installed on the machine that generated the event.

The pack ships two complementary things:

1. **`data/lookups/windows_msg_codes.csv`** — a curated table of 201 well-documented codes covering the ranges the pack team has verified against Windows Server 2019/2022:
   - Standard Access Rights (`%%1537-%%1567` — all bits including "Undefined Access" for bits 21-30)
   - Interactive Logon Type (`%%1793-%%1794`), Boolean (`%%1825-%%1826`), Impersonation Level (`%%1830-%%1834`), Virtual Account / Yes-No (`%%1842-%%1843`), Token Elevation Type (`%%1936-%%1938`)
   - User Account Control flags (`%%2048-%%2073`)
   - File Access Rights (`%%4416-%%4424`), Registry Access Rights (`%%4432-%%4450`)
   - Access Reason (`%%8192-%%8196`), Audit Category (`%%8272-%%8280`), Audit Policy Change (`%%8448-%%8451`)
   - Audit Subcategories across `%%12288-%%14339` (System, Logon/Logoff, Object Access, Privilege Use, Detailed Tracking, Policy Change, Account Management, DS Access, Account Logon)
   - WFP Direction (`%%14592-%%14593`), WFP Layer Name (`%%14608-%%14626`), Firewall Profile (`%%14644-%%14646`)

2. **`data/lookups/regenerate_windows_msg_codes.ps1`** — a PowerShell script that regenerates the CSV directly from your Windows host's DLLs. This is the *definitive* way to get a complete lookup for your specific Windows build — new codes shipped in recent Windows updates, provider-specific codes (Defender, PowerShell, Terminal Services message tables), and version-specific string wording all come out of your actual DLLs rather than a curated snapshot that could be stale or slightly wrong.

The reason we ship both: the 201-entry CSV covers the well-known codes seen in the vast majority of Security channel events (4624, 4625, 4656, 4663, 4670, 4674, 4719, 4720, 4738, 5157, etc.) and it's ready-to-go without any additional setup. The regeneration script fills the "last mile" for whatever your specific Windows build has that isn't in the shipping snapshot.

The pack ships an extraction script at `data/lookups/regenerate_windows_msg_codes.ps1`. It's read-only, has no dependencies beyond PowerShell 5.1+, and uses the same `LoadLibraryEx` + `FormatMessage()` mechanism Windows itself uses when Event Viewer renders `%%NNNN` codes — so the output matches exactly what the Splunk UF would resolve at collection time on that host.

```powershell
# On a Windows Server host that represents the version you collect from:
cd C:\temp
.\regenerate_windows_msg_codes.ps1

# Compare against the currently shipping CSV to see what's new/different:
Compare-Object `
    (Import-Csv .\windows_msg_codes.csv) `
    (Import-Csv <path-to-pack>\data\lookups\windows_msg_codes.csv) `
    -Property code, value

# Drop the fresh CSV into the pack:
Copy-Item .\windows_msg_codes.csv <path-to-pack>\data\lookups\windows_msg_codes.csv
# Then update <path-to-pack>\data\lookups\windows_msg_codes.yml (size and rows)
```

The script probes `%%1`..`%%30000` across five source DLLs by default (`adtschema.dll`, `msobjs.dll`, `authz.dll`, `iasnap.dll`, `wsecedit.dll`) — the same DLLs Windows event providers consult. All parameters are configurable; see `Get-Help .\regenerate_windows_msg_codes.ps1 -Full`. Categorization heuristics for known code ranges (Standard Access Rights, Audit Subcategory, WFP Layer Name, etc.) match the shipping lookup exactly, so a fresh extract is a drop-in replacement — sorted numerically for easy diffing.

## Version

Pack version is tracked in `package.json` and aligned with the paired **Cribl_TA_windows** Splunk app. From 0.0.5 onward, both artifacts share the same version number to keep support conversations simple.

**0.0.18** — **`clean()` now flattens `EventData.Data` when it's a plain keyed object.** Fixed the bug where events like WFP 5152/5157 had shape `EventData: { Data: { Direction, LayerName, ... } }` after `parseWinEvent()` returned `Data` as an object (not an array). The pre-existing array-flattening branch only handled the `Data: [{Name, _value}, ...]` shape and silently passed through the object shape unchanged, leaving `EventData.Data.<X>` in `_raw` where the paired TA's FIELDALIAS declarations couldn't find them. New branch merges `Data`'s child keys directly into the parent so `EventData.<X>` is what lands in `_raw` — matching what the TA's FIELDALIAS chains were written against. Coverage against a real Windows fleet audit jumped from 63.6% to 95.4% as a result. Paired TA (0.0.18) also added 125+ new FIELDALIAS entries for classic-format sibling names, modern Windows Server 2022+ fields, and CIM aliases for firewall events.

**0.0.17** — **`%%NNNN` resolution now actually resolves.** Two bugs in the 0.0.14/0.0.15/0.0.16 Code function meant `C.Lookup` never resolved anything and every `%%NNNN` fell through unchanged (even though the lookup CSV was correct):
1. `new C.Lookup(...)` — wrong; per Cribl docs, `C.Lookup` is a **factory**, not a constructor. Calling `new` on it threw silently under my try/catch and left the lookup handle null.
2. `.match(node)` with a single argument returns a **boolean** (whether the key exists), not the row. My code was checking `row.value` on a boolean, so every check failed and the code stayed unresolved.

Corrected call: `C.Lookup('windows_msg_codes.csv', 'code', ['value'])` for init and `.match(node, 'value')` inside the walker — this matches the [Cribl docs](https://docs.cribl.io/stream/expressions/#c-lookup) exactly. Also added a `CFG.debugWinCodes` flag (default off, overridable via the `debugWinCodes` Cribl Global Variable): when true, the Code function emits `__lookup_state`, `__lookup_test`, and `__lookup_walker` hidden fields to a preview capture so an operator can verify at a glance that the lookup loaded, that a probe match returned a real string, and that the walker actually ran. Hidden `__`-prefixed fields are stripped before send, so debug output is safe to leave on temporarily but shouldn't ship in prod.

**End-to-end verification against the exact event you uploaded** (Event 5152, `EventData.Data.Direction="%%14592"`, `EventData.Data.LayerName="%%14610"`): resolution now flips both to `Inbound` / `Receive/Accept` before `_raw = JSON.stringify(parsed)` runs. If you preview the same event with 0.0.17 installed you should see the resolved values in `_raw`; enable `debugWinCodes` if you still don't and paste the `__lookup_*` fields back.

**0.0.16** — **Authoritative `windows_msg_codes.csv`.** Replaced the earlier 201-entry curated snapshot with the full extract from `adtschema.dll` sourced from the community-maintained [nsacyber/Event-Forwarding-Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) repository. **979 codes across 69 categories** — nearly 5× the coverage of 0.0.15. Also corrected two mappings that were wrong in the previous shipping snapshot:
- `%%8192` was `ACCESS_ALLOWED` (Access Reason) → actually `Kerberos` (IPsec Authentication Method)
- `%%14608` / `%%14609` / `%%14614` / `%%14615` were `Transport` / `Forward` / etc → actually `Resource Assignment` / `Listen` / `Resource Release` / `Endpoint Closure` (WFP Layer Name)

New categories added (previously missing entirely from the shipping CSV): Privilege (23), Cryptographic Operation (39), IPsec Authentication Method (7), IPsec / IKE State (50), IPsec Algorithm / Setting (27), WMI Operation (10), per-object-type Access Rights (Device, Directory, Event Object, Mutant, Port, Process, Profile, Section, Semaphore, Symbolic Link, Thread, Timer, Token, Type, Channel, Job — 16 rows each), full SAM Access Rights (Server / Domain / Group / Alias / User — 16 rows each), LSA Access Rights (Policy / Secret / Trusted Domain / Account — 16 rows each), Keyed Event, Window Station, Desktop, Printer, SCM, Service, DDE Share, Directory Service, Audit Policy, Terminal Services, Credentials, Registry Value Type (12), Registry Action (3), Day of Week (7), Logon Failure Reason (12), and more.

The pack's `resolveWinCodes(node)` walker (from 0.0.14) consumes the CSV verbatim — no pipeline code changes needed. The `regenerate_windows_msg_codes.ps1` script's categorization heuristics were expanded to match the new 69-category taxonomy, so operator-regenerated CSVs will fall into the same categories the shipping snapshot uses.

**0.0.15** — **Extraction script for regenerating the message-code lookup from a live Windows system.** New file `data/lookups/regenerate_windows_msg_codes.ps1`: a self-contained PowerShell script that uses the exact `LoadLibraryEx` + `FormatMessage()` calls Windows itself uses when Event Viewer renders `%%NNNN` placeholders. Point it at any Windows Server host, it walks `adtschema.dll`, `msobjs.dll`, `authz.dll`, `iasnap.dll`, and `wsecedit.dll`, and writes a fresh `windows_msg_codes.csv` in the pack's schema. Read-only, no dependencies beyond PowerShell 5.1+, no admin required to read the DLLs. Run it whenever you upgrade the Windows fleet you're collecting from, or if you see a `%%NNNN` code your currently-shipping CSV doesn't resolve. See the "Regenerating the lookup" section below for usage.

**0.0.14** — **Windows message-code (`%%NNNN`) resolution.** The pack now emulates what the Splunk Universal Forwarder does at collection time via the Windows message DLLs: nested-JSON string values matching `/^%%\d+$/` (e.g. `EventData.Direction = "%%14592"`, `EventData.IsLoopback = "%%1826"`, `EventData.LayerName = "%%14610"`) are replaced with their human-readable form (`Inbound`, `False`, `Receive/Accept`) using a shipping lookup at `data/lookups/windows_msg_codes.csv` (193 codes covering Standard Access Rights, Booleans, Impersonation Level, Virtual Account, Token Elevation Type, UAC flags, File and Registry Access Rights, Access Reason, Audit Categories & Subcategories, Audit Policy Change, WFP Direction & Layer Name, and Firewall Profile). Unknown codes pass through unchanged so future Microsoft additions are never dropped — they simply show up as `%%NNNN` until the CSV is updated. Two new CFG flags (overridable via Cribl Global Variables): `resolveWinCodes` (default `true`) and `preserveWinCodes` (default `false` — when `true`, keeps the raw code alongside as `<fieldname>_code`).

**0.0.13** — Lockstep version bump only; no functional changes on the pack side. The paired TA fixed four invalid `[sourcetype::X]` stanza headers (Splunk doesn't recognize that form) by converting them to the bare `[X]` form: `ActiveDirectory`, `WinEventLog`, `WinRegistry`, `wmi`.

**0.0.12** — Lockstep version bump only; no functional changes on the pack side. The paired TA removed 30 self-alias `FIELDALIAS-X = Foo AS Foo` entries flagged by Splunk's `FieldAliaser` as invalid.

**0.0.11** — Lockstep version bump only; no functional changes on the pack side. The paired TA converted every remaining `ASNEW` on FIELDALIAS pairs to `AS` (232 conversions in the `cribl_compat_*` block) for config uniformity.

**0.0.10** — Lockstep version bump only; no functional changes on the pack side. The paired TA reverted 0.0.9's `EVAL` conversion back to `FIELDALIAS` with double-quoted dotted sources; the pack's native fallback chains (e.g. `coalesce(ComputerName, MachineName)`) that were merged into EVAL in 0.0.9 have been split back out so both mechanisms coexist cleanly.

**0.0.9** — Lockstep version bump only; no functional changes on the pack side. The paired TA converted every dotted-source `FIELDALIAS-*` to an `EVAL-*` statement (with single-quoted dotted references, Splunk EVAL grammar) so nested-JSON aliases resolve correctly against `KV_MODE=json` auto-extracted fields. Existing EVAL declarations were merged rather than duplicated. (Superseded by 0.0.10, which restored FIELDALIAS+double-quote approach at the user's request.)

**0.0.8** — Lockstep version bump only; no functional changes on the pack side. The paired TA shipped a FIELDALIAS quote-character correction in 0.0.8: Splunk's `props.conf` FIELDALIAS syntax requires **double quotes** (not single) around dotted source field names, matching SPL's `rename` convention. 636 references were reflipped. (Superseded by 0.0.9's EVAL conversion, which addresses the deeper resolution issue.)

**0.0.7** — Lockstep version bump only; no functional changes on the pack side. The paired TA shipped a `splunk btool check` cleanup in 0.0.7 (removed invalid `show_in_app_bar`, `auto_kv_json`, and `input_field`/`output_field` keys; converted four `TRANSFORMS-*` WinRegistry lookup declarations to `LOOKUP-*`).

**0.0.6** — Lockstep version bump only; no functional changes on the pack side. The paired TA shipped a search-time correctness fix in 0.0.6 (single-quoted every dotted-source path in its `FIELDALIAS` declarations so nested JSON extraction resolves correctly).

**0.0.5** (consolidated release — supersedes the interim 0.0.3 and 0.0.4 desk builds)

*Correctness*
- Fixed Auto Timestamp / host-timezone interaction. The timezone shift in the Auto Timestamp step now only applies to Classic events whose parsed source timestamp lacked explicit UTC info. XML `System.TimeCreated.SystemTime` is Z-anchored UTC, so applying `C.Time.adjustTZ` on top would incorrectly shift `_time` by the host offset. The Code function now sets an internal `__time_utc` marker (`true` for XML, and for Classic strings that carry `Z` or `±HH:MM`; `false` otherwise) and Auto Timestamp's expression is gated on `(__tz && !__time_utc)`.
- Tightened XML detection to the anchored regex `/^<(\?xml|Event\b)/` on the trimmed raw, so a Classic event whose Message body merely mentions `<Event` is not misrouted through `parseWinEvent`.
- Parse errors in the Code function now set `sourcetype = 'windows:json:parse_error'` alongside `cribl_code_error`. The Eval function preserves that sourcetype so bad events don't silently land under the healthy `windows:json` bucket.
- Channel value is whitespace-normalized (`\s+ → _`) before being concatenated into `source`, matching the pack's underscore-normalized key naming.

*Docs and metadata*
- Populated `default/pack.yml` with `displayName`, `description`, and `streamtags` so the pack surfaces cleanly in the Cribl UI.
- Corrected the invalid `=~` route-filter example in this README to Cribl (JavaScript) regex syntax.
- Refreshed the Splunk-metadata example Eval expression in this README so it matches the pipeline as shipped (including the `parse_error` guard).
- Replaced the demo row in `host_timezone.csv` with an obviously-inert placeholder plus inline usage comments.
- Bumped `package.json` version to 0.0.5.

**0.0.2** — Added a Lookup function that derived the `__tz` hidden field for the Auto Timestamp step. The idea was sound (adjust naive Classic timestamps by the host's tz) but the shift also fired on XML events with authoritative UTC — the 0.0.5 release fixes that.

**0.0.1** — Initial release; aligned versioning with the paired **Cribl_TA_windows** Splunk app.
