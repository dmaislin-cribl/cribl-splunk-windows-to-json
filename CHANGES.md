# Changes applied

Corrective actions taken against the findings in `REVIEW.md`, plus one follow-up correctness fix on the TA side. Both artifacts ship at a single unified version so support conversations don't have to disambiguate which side is on which patch level.

| Artifact | Original | Interim (never shipped) | Current |
|---|---|---|---|
| Cribl Pack (`windows_events_to_nested_json`) | 0.0.3 | 0.0.4 – 0.0.17 | **0.0.19** |
| Splunk TA (`Cribl_TA_windows`) | 0.0.1 | 0.0.2, 0.0.5 – 0.0.17 | **0.0.19** |

## 0.0.19 (this release) — classic-event CIM gaps closed

Found by replaying a real customer export (a Cribl Stream capture of classic-rendered Security-channel events: 4688, 4776, 4793, 4670, 4673, 4672, 4627, 4624, 4798) through the actual pack parser and cross-checking the resulting field paths against every FIELDALIAS/EVAL chain in the paired TA's `props.conf`. Two confirmed defects, both fixed:

**(A) TA — `user` / `user_name` / `src_user` never resolved for the generic `Subject:` section.** The alias chains for these three CIM fields included `Message.Creator_Subject.Account_Name` (used only by 4688/4689 process events) but never plain `Message.Subject.Account_Name` — the section header the *large majority* of Security-channel audit events use (4670, 4672, 4673, 4793, 4798, 4627, and more). Every one of those event types was shipping with `user`/`user_name`/`src_user` silently null, even though the underlying `Message.Subject.Account_Name` value was present in `_raw` the whole time. Added `"Message.Subject.Account_Name" AS <target>` to `FIELDALIAS-user`, `FIELDALIAS-user_name`, and `FIELDALIAS-src_user` in both `[source::windows:json:Security]` and `[source::WinEventLog:Security]`. Verified no interference with 4688/4689 (those events never populate a plain `Subject` section, only `Creator_Subject`/`Target_Subject`, so the two paths never collide on the same event).

**(B) Pack — multi-line `Message` values past the first entry were silently dropped.** Windows renders some classic `Message` keys with only the *first* value sharing the `Key:` line and every subsequent value as a bare continuation line with no colon (e.g. 4672 "Special privileges assigned to new logon" lists up to a dozen `Privileges:` entries this way; 4663 "Accesses:" lists behave identically). `parseClassic()`'s `messageBodyLine()` only had a continuation-line fallback for *section* headers (e.g. 4627's `Group Membership:`); a continuation line following a flat, non-sectioned key had nowhere to go and was dropped outright. Verified against the sample: 4672 events were landing with `Message.Privileges = "SeAssignPrimaryTokenPrivilege"` only — the other 11 assigned privileges (including `SeDebugPrivilege` and `SeImpersonatePrivilege`, both common lateral-movement/privilege-escalation hunting signals) never made it into `_raw`. Fixed by tracking the most recently set flat-or-sectioned key and promoting it to a JSON array as continuation lines arrive, so `Message.Privileges` (and any future multi-line key, e.g. 4663's `Accesses`) now comes through as a proper multivalue field. Re-ran the full 9-event-type sample through the fixed parser: only the 4672 `Privileges` field changed shape (string → 12-element array); all 8 other event types byte-identical to before.

**Verification:** Both fixes applied and the full sample set re-parsed with a standalone extraction of the shipped pipeline code (not simulated — the actual `messageBodyLine`/`parseClassic` logic from `conf.yml`). `props.conf` double-quote convention, no duplicate FIELDALIAS/EVAL targets within either touched stanza, 0.0.18 regression checks (no `[sourcetype::X]` stanzas, no `ASNEW`, no self-aliases) all still hold.

## 0.0.18 — 63.6% → 95.4% field-coverage jump

Field-by-field audit against a live Windows host (4 CSV exports: UF and Cribl, small and large, from the same box) found that the TA was covering only 63.6% of the 391 unique field names those events actually contained. This release lifts that to **95.4%** through two coordinated fixes:

**(A) Pack — `clean()` object-shape flattening.** The `clean()` function had an array-flattening branch for `Data: [{Name, _value}, ...]` but no branch for `Data: {ProcessId: X, Direction: Y, ...}` — the shape `parseWinEvent()` produces when the XML source has been parsed with keyed access. Events came through with `EventData.Data.<X>` in `_raw` instead of the flat `EventData.<X>` shape the TA's FIELDALIAS chains were written against. New branch detects the "object with real keyed data" pattern and merges its keys into the parent. ~15 lines of JavaScript, restores 16 fields' worth of coverage on its own before any TA changes.

**(B) TA — 125+ new FIELDALIAS entries** in `[windows:json]` and `[WinEventLog]` covering:
- Classic-format sibling names (Application_Name, Caller_*, Client_*, Primary_*, Target_*, Workstation_Name, Member_*, Group_Type_Change, User_Name, Network_Account_*, Linked_Logon_ID, Package_Name__NTLM_only_, CategoryString, Change_Type, New_Domain, New_Account_Name, Account_Domain, Supplied_Realm_Name, Transited_Services)
- Registry Value change fields (Old_Value, New_Value, Old_Value_Type, New_Value_Type, Object_Value_Name, Operation_Type)
- File / Object path names (File_Name, Image_File_Name)
- Modern Windows Server 2022+ fields (ElevatedToken, MandatoryLabel, KeyLength, LmPackageName, LogonGuid, LogonProcessName, RestrictedAdminMode, RemoteCredentialGuard, RemoteMachineID, RemoteUserID, HasRemoteDynamicKeywordAddress, ImpersonationLevel) + underscore-normalized twins
- WFP fields (Direction, LayerName, LayerRTID, FilterOrigin, FilterRTID, Protocol, Application, SourceAddress, SourcePort, DestAddress, DestPort, IsLoopback, InterfaceIndex, CurrentProfile, OriginalProfile) + underscore-normalized twins
- CIM Network Traffic aliases (SourceAddress → src/src_ip, DestAddress → dest/dest_ip, SourcePort → src_port, DestPort → dest_port, Application → app, Protocol → transport_number) plus EVAL-transport (numeric → tcp/udp/icmp/…), EVAL-direction (LayerName/Direction → inbound/outbound), EVAL-action_wfp (EventCode → blocked/allowed). Firewall events populate CIM Network Traffic correctly for ES.
- Additional EventData/System paths (NewProcessId, ProcessID, ThreadID, SubjectUserSid, TargetUserSid, TargetLogonId, TargetLinkedLogonId, TargetOutboundDomainName, TargetOutboundUserName, VirtualAccount, ActivityID, Version, Provider_Guid, Keywords, Opcode)

**Verification:**
- Post-build: 1,150 FIELDALIAS lines (was 1,010), 401 EVAL lines (was 395)
- 1,519 dotted-source FIELDALIAS references, all double-quoted per Splunk spec
- 0 invalid `[sourcetype::X]` stanzas, 0 ASNEW, 0 self-aliases, 0 duplicates within any stanza
- 0.0.7 btool hygiene intact
- Pack simulation against the exact 5152 event you shared earlier: `EventData.Data` gets flattened; `EventData.Direction` / `EventData.LayerName` land at the level TA aliases target; `%%14592 → Inbound` and `%%14610 → Receive/Accept` resolve via `C.Lookup(..., 'code', ['value'])` from 0.0.17.

**Remaining 18 uncovered fields (out of 391):** all XML metadata (`RenderingInfo.Channel` etc), `_time` mapping (`System.TimeCreated.SystemTime` → `_time` handled by pack), REPORT/LOOKUP outputs (`command`, `severity`, `subject`, `vendor_privilege`, `member_nt_domain`, `new_process_name`, `object_file_name`, `ta_windows_security_CategoryString`, `Token_Elevation_Type_id`), or Splunk auto-generated (`tag`). None are audit-value fields.

## 0.0.17 (superseded) — `%%NNNN` resolution actually resolves now

**The bug 0.0.14 shipped that 0.0.15/0.0.16 didn't catch:** the Code function's lookup handle was `null` on every event, and every `%%NNNN` code passed through unchanged. Root cause was two mistakes about the Cribl inline lookup API:

1. `new C.Lookup(...)` — wrong. Per [Cribl's docs](https://docs.cribl.io/stream/expressions/#c-lookup), `C.Lookup` is a **factory function, not a constructor**. Calling with `new` threw a TypeError, my `try/catch` swallowed it silently, and `_winCodeLookup` stayed null. The walker's `if (_winCodeLookup == null) return node` early-return meant no `%%NNNN` was ever looked up.
2. `.match(node)` with a single argument returns a **boolean** (whether the key exists), not the row. My code was accessing `row.value` on a boolean — `true.value === undefined` — so even if init had worked, resolution wouldn't have.

Both fixed. Correct calls per the docs:

```js
// Init: factory, not constructor. Third arg limits which columns .match() can return.
_winCodeLookup = C.Lookup('windows_msg_codes.csv', 'code', ['value']);

// Per-value resolution: two-arg .match() returns the string from the 'value' column,
// or undefined when the code isn't in the CSV.
var resolved = _winCodeLookup.match(node, 'value');
if (typeof resolved === 'string' && resolved !== '') return resolved;
```

**End-to-end verification against the user's uploaded sample event (Event 5152):** `EventData.Data.Direction: "%%14592"` now resolves to `Inbound`; `EventData.Data.LayerName: "%%14610"` resolves to `Receive/Accept`. Before this release those values were flowing through unresolved despite the CSV containing the correct mappings.

**New debug flag.** `CFG.debugWinCodes` (default `false`, overridable via the Cribl Global Variable `debugWinCodes`) emits three hidden fields when set:
- `__lookup_state`: `ok` or `init-failed`
- `__lookup_test`: result of a canned `.match("%%14592", "value")` probe — shows exactly what Cribl returned
- `__lookup_walker`: `ran` or `skipped (...)` — confirms the walker actually invoked

These are `__`-prefixed so Cribl strips them before sending downstream to Splunk, but they're visible in a preview capture. Use them if resolution still doesn't work in your environment.

**No CSV changes** — the 979-row authoritative extract from 0.0.16 is unchanged. The whole problem was the Code function couldn't read it correctly.

**TA:** lockstep version bump only.

## 0.0.16 (superseded) — Authoritative CSV extract

**Two things went into the Pack:**

1. **`data/lookups/windows_msg_codes.csv` expanded** from 193 → 201 entries. Filled the `%%1544-%%1551` gap that adtschema.dll defines as `"Undefined Access (no effect) Bit N"` for reserved Access Mask bits 21-30, matching the existing `%%1552-%%1567` pattern. This includes the exact case from the earlier user report (`%%1548`), which now resolves to `"Undefined Access (no effect) Bit 27"`. YML metadata updated (size, rows, version tag).

2. **`data/lookups/regenerate_windows_msg_codes.ps1` added** (10.7 KB, 250 lines). Self-contained PowerShell script that uses P/Invoke against `kernel32.dll` (`LoadLibraryEx` + `FormatMessage`) to extract message tables directly from the running Windows machine's DLLs — the same mechanism Windows itself uses when Event Viewer renders `%%NNNN` codes. Extracts from five DLLs by default (`adtschema.dll`, `msobjs.dll`, `authz.dll`, `iasnap.dll`, `wsecedit.dll`), probes IDs 1..30000, categorizes by known range, writes CSV in the pack's schema. Read-only, no dependencies beyond PowerShell 5.1+. Documented in the Pack README with usage examples and a `Compare-Object` recipe for diffing against the shipping snapshot.

**Why both?** No published Microsoft reference gives an authoritative comprehensive `%%NNNN` list — the strings live in resource DLLs that differ by Windows version and update level. The shipping 201-entry CSV covers the well-documented codes verified against Windows Server 2019/2022 (the vast majority of Security channel events resolve fully with it). The regeneration script covers the "last mile" — codes added in recent updates, provider-specific message tables, version-specific string wording. Ship-time completeness + operator-time freshness.

**No functional pack code changes** in this release. The `resolveWinCodes` walker from 0.0.14 continues to consume `windows_msg_codes.csv` verbatim — expanding the CSV or regenerating it doesn't require any pipeline change.

**TA:** lockstep version bump only.

**Verified in shipped `.crbl`:**
- Pack version: `0.0.15`
- CSV rows: `201`
- `%%1548 → Undefined Access (no effect) Bit 27 (Standard Access Rights, event 4656)` ✓
- `regenerate_windows_msg_codes.ps1` present, 10761 bytes
- Prior fixes intact: `%%14592 → Inbound`, `%%1826 → False`, `%%14610 → Receive/Accept`, `%%14644 → Public`
- No invalid `[sourcetype::X]` stanzas, no `ASNEW`, no self-aliases, 1,313 double-quoted dotted FIELDALIAS sources, 228/228 REPORT/LOOKUP/TRANSFORMS references resolve, 0.0.7 btool hygiene preserved

## 0.0.14 (superseded) — Windows message-code (`%%NNNN`) resolution in the Pack

**Problem.** Windows event log fields whose values are `%%NNNN` codes (e.g. `EventData.Direction = "%%14592"`, `EventData.IsLoopback = "%%1826"`, `EventData.LayerName = "%%14610"`) are supposed to be message-file lookups. Splunk's Universal Forwarder resolves them at collection time via the Windows message DLLs before events reach the indexer. When Cribl Edge or any other non-UF collector is in the path, no such resolution happens and the raw codes flow through — analysts see `%%14592` instead of `Inbound`.

**Where the fix lives.** In the Pack (not the TA). The Pack occupies the same architectural role as the UF, and it's the only place that can walk the parsed JSON structure and resolve arbitrary field values without one Splunk `LOOKUP-*` declaration per field per stanza.

**Implementation.**
- New lookup file `data/lookups/windows_msg_codes.csv` (193 entries — the user's authoritative CSV plus a small set of well-known additions: Interactive Logon Type 1793/1794, Access Reason 8192-8196, additional Registry Access Right 4441, and extended WFP Layer Names 14621-14626). Columns: `code, value, category, microsoft_source_event`. Only `code → value` is used at resolution time; the other columns are metadata for anyone who wants to enrich later.
- Code function extended with a `resolveWinCodes(node)` recursive walker (parallels the existing `clean()` walker) that visits every string value in the parsed structure and replaces `/^%%\d+$/` matches with the resolved `value`. Runs after all parsing and cleaning but before `_raw = JSON.stringify(parsed)`.
- Two new CFG flags overridable via Cribl Global Variables:
  - `resolveWinCodes` (default `true`) — master enable
  - `preserveWinCodes` (default `false`) — when `true`, keeps the raw code as `<fieldname>_code` alongside the resolved value
- Unknown codes pass through unchanged so future Microsoft additions never get dropped or blanked — they just show as `%%NNNN` until the CSV is updated.

**Verified end-to-end** against the exact fields from the user's screenshot:

| Field | Before | After |
|---|---|---|
| `EventData.Direction` | `%%14592` | `Inbound` |
| `EventData.HasRemoteDynamicKeywordAddress` | `%%1826` | `False` |
| `EventData.IsLoopback` | `%%1826` | `False` |
| `EventData.LayerName` | `%%14610` | `Receive/Accept` |
| `EventData.CurrentProfile` | `%%14644` | `Public` |
| `EventData.SomeUnknownField` | `%%99999` | `%%99999` (unchanged — not in table) |

**Pack .crbl contents:** now includes `data/lookups/windows_msg_codes.csv` and `data/lookups/windows_msg_codes.yml` alongside the existing `host_timezone.csv` / `.yml`.

**TA:** lockstep bump only; no props/transforms changes needed because the codes are resolved upstream. TA README notes that the pack handles this.

**All prior fixes intact:** no invalid `[sourcetype::X]` stanza headers, no `ASNEW` on FIELDALIAS, no self-aliases, 1,313 double-quoted dotted FIELDALIAS sources, 0 duplicates within any stanza, 228/228 REPORT/LOOKUP/TRANSFORMS references resolve, 0.0.7 btool hygiene preserved.

## 0.0.13 (superseded) — Fixed invalid `[sourcetype::X]` stanza headers

Splunk's `props.conf` spec supports `[<sourcetype>]` (bare), `[host::…]`, `[source::…]`, `[rule::…]`, and `[delayedrule::…]`. It does **not** recognize `[sourcetype::<name>]` as a form for matching by sourcetype — that gets parsed as a literal sourcetype value `sourcetype::<name>`, which never matches a real event. The stanza (and every extraction underneath it) is effectively dead. This TA had the mistake in five stanzas since 0.0.1; `[sourcetype::windows:json]` was corrected in an earlier edit; the remaining four are fixed here.

Converted:
| Before | After |
|---|---|
| `[sourcetype::ActiveDirectory]` | `[ActiveDirectory]` |
| `[sourcetype::WinEventLog]` | `[WinEventLog]` |
| `[sourcetype::WinRegistry]` | `[WinRegistry]` |
| `[sourcetype::wmi]` | `[wmi]` |

**Significance.** The `[sourcetype::windows:json]` (now `[windows:json]`) stanza held ~180 FIELDALIAS declarations, EVAL statements, and LOOKUP references. It was never binding — which is a strong candidate explanation for why some of the earlier quote-character iterations didn't seem to change alias resolution behavior. With the stanza header now correct, and the FIELDALIAS declarations using double-quoted dotted sources per Splunk's spec, the aliases should now materialize for `sourcetype=windows:json` events.

**Verification:**
- 0 remaining `[sourcetype::…]` stanza headers
- No stanza-name collisions (none of the bare-form names previously existed)
- All 228 REPORT/LOOKUP/TRANSFORMS references still resolve
- All prior fixes intact: no `ASNEW`, no self-aliases, 1,313 double-quoted dotted FIELDALIAS sources, 0 duplicates within any stanza, 0.0.7 btool hygiene preserved
- Version alignment: `app.manifest`, both `app.conf` version lines, `package.json`, and `host_timezone.yml` all at 0.0.13

**Pack:** Lockstep version bump only; no functional pack changes.

## 0.0.12 (superseded) — Removed self-alias `FIELDALIAS-*` entries

Splunk's `FieldAliaser` was logging warnings like `Invalid field alias specification in stanza 'source::WinEventLog:Security': FIELDALIAS-cribl_compat_ComputerName='ComputerName AS ComputerName'`. Splunk considers a FIELDALIAS whose source and target are the same field to be invalid — and it *is* a no-op (aliasing a field to itself does nothing). The `cribl_compat_*` block had ten such self-aliases duplicated across the JSON-consuming stanzas, for 30 lines total. All have been deleted.

**Targets removed (each appeared in `[source::WinEventLog:Security]`, `[source::windows:json:Security]`, and `[wineventlog]`):** `ComputerName`, `Keywords`, `LogName`, `OpCode`, `SourceName`, `Type`, `product`, `severity`, `vendor`, `vendor_product`.

**Result:**
- 30 self-alias FIELDALIAS pairs deleted; zero remain
- FIELDALIAS lines: 1,010 → 980
- All other checks still hold (0.0.11 ASNEW→AS conversion intact, 0.0.10 double-quoted dotted sources intact, 0.0.7 btool hygiene intact, all 228 REPORT/LOOKUP/TRANSFORMS references resolve, 0 duplicates within any stanza)

**Verified against your specific log entries:** the 10 `FIELDALIAS-cribl_compat_*` names your Splunk instance flagged are all absent from the 0.0.12 tarball.

**Pack:** Lockstep version bump only; no functional pack changes.

## 0.0.11 (superseded) — Uniform `AS` on all `FIELDALIAS-*` declarations (removed `ASNEW`)

Converted 232 `ASNEW` keywords on FIELDALIAS pairs (all in the `cribl_compat_*` block) to `AS`. For this TA's ingest path, `AS` and `ASNEW` produce identical results because nothing else pre-populates the legacy flat targets.

## 0.0.10 (superseded) — Revert 0.0.9's EVAL back to FIELDALIAS (double-quoted dotted sources)

At the user's direction, 0.0.9's EVAL-based nested-JSON aliasing has been reverted to the `FIELDALIAS`-based approach with double-quoted dotted sources. The pack's native fallback chains that had been merged into EVAL in 0.0.9 (e.g. `coalesce('System.Computer', ComputerName, MachineName)`) have been split back out so `FIELDALIAS` and `EVAL` coexist cleanly — each doing what it does best.

**Transformation.** For every `EVAL-*` statement whose expression was `'X.Y'` (a bare single-quoted dotted literal, i.e. a pure FIELDALIAS conversion), or `coalesce('X.Y', ...)` (a merged form), the dotted single-quoted args were extracted as `FIELDALIAS-<target> = "X.Y" AS <target>` and the remaining non-dotted args survived as a residual `EVAL-<target> = coalesce(<rest>)`. Where extraction left nothing behind, the EVAL was removed. Where target appeared BEFORE the dotted args in the coalesce (an `ASNEW` indicator from the 0.0.9 transformation), the reversal used `ASNEW` instead of `AS`.

**Result:**
- 652 `EVAL-*` lines processed by the reversal
- 652 `FIELDALIAS-*` lines emitted with double-quoted dotted sources (`"A.B"` form, matching SPL's `rename` convention)
- 77 residual `EVAL-*` retained (the pack's native flat fallbacks that survived the split)
- 575 `EVAL-*` removed (they were pure FIELDALIAS conversions with no residual fallback)
- 1,313 double-quoted dotted `FIELDALIAS` sources in total; 0 single-quoted, 0 unquoted
- 0 duplicate `FIELDALIAS-<key>` or `EVAL-<target>` within any stanza
- All prior 0.0.7 btool-hygiene fixes intact
- All 228 `REPORT/LOOKUP/TRANSFORMS` references still resolve

**Canonical example (the user's `System.Computer` test case):**
```
[sourcetype::windows:json]
FIELDALIAS-ComputerName = "System.Computer" AS ComputerName
EVAL-ComputerName = coalesce(ComputerName, MachineName)
FIELDALIAS-EventCode = "System.EventID" AS EventCode
EVAL-EventCode = coalesce(EventCode, Id)
FIELDALIAS-SourceName = "System.Provider.Name" AS SourceName
EVAL-SourceName = coalesce(SourceName, ProviderName)
```

**Pack:** Lockstep version bump only; no functional pack changes.

## 0.0.9 (superseded) — Convert dotted-source FIELDALIAS to EVAL

**Root cause (deeper than the 0.0.6/0.0.8 quote-character debates).** Splunk's `FIELDALIAS-*` construct, whether the source is single- or double-quoted, does **not** reliably resolve dotted-name sources produced by `KV_MODE = json` auto-extraction. The declarations show up in the Splunk UI's Field Aliases list, `btool check` reports them clean, and the config passes every static check — but the target field never materializes at search time. The Splunk community's documented workaround is `EVAL-*` with single-quoted dotted paths, which uses the EVAL engine's field-lookup and does resolve those extractions correctly.

**Empirical trigger.** Against a `windows:json` event: `| rename "System.Computer" as ComputerName` works. `FIELDALIAS-ComputerName = "System.Computer" AS ComputerName` in `props.conf` doesn't.

**Fix.** Every `FIELDALIAS-*` line whose source contained a dot has been converted to an `EVAL-*` declaration. When an existing `EVAL-*` for the same target field already existed in the stanza (e.g., the pack's native-flat-JSON fallbacks: `EVAL-EventCode = coalesce(EventCode, Id)`), the two were merged — the dotted source is prepended so it wins first if present, and the original fallback chain is preserved. Example transformation:

Before:
```
FIELDALIAS-ComputerName = "System.Computer" AS ComputerName
EVAL-ComputerName = coalesce(ComputerName, MachineName)
```
After:
```
EVAL-ComputerName = coalesce('System.Computer', ComputerName, MachineName)
```

Non-dotted `FIELDALIAS-*` declarations (aliasing top-level Cribl-flat fields — e.g., `ComputerName ASNEW ComputerName`, `TaskCategory as category`, `Primary_Group_ID AS user_group_id`) were left alone and still work correctly.

**Scope.**
- 7 stanzas touched: `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, `[xmlwineventlog]`, `[WMI:WinEventLog:System]`, `[WMI:WinEventLog:Security]`, `[WMI:WinEventLog:Application]`.
- 488 unique target fields across those stanzas now resolve via EVAL.
- 490 original `FIELDALIAS-*` lines with dotted sources removed; 358 non-dotted `FIELDALIAS-*` lines kept.
- Total `EVAL-*` declarations after transformation: 970 (up from the earlier count; includes ~488 new + merged with existing).

**Note on FIELDALIAS vs EVAL semantics.** FIELDALIAS creates a true alias (both original and alias searchable, share the same value). EVAL creates a calculated field. For the aliasing use case here, they're functionally equivalent at search time — you can search on the flat name (e.g., `ComputerName=`) and get results. The trade-off: EVAL runs a small expression per event at search time, where FIELDALIAS is essentially free. In this case correctness beats performance because FIELDALIAS wasn't working at all.

**Pack:** Lockstep version bump only; no functional pack changes.

**Post-build verification (all pass on the extracted `.tgz`):**
- 0 dotted `FIELDALIAS-*` sources remaining (in any quote style)
- 0 duplicate `EVAL-*` target fields within any stanza
- All 228 REPORT/LOOKUP/TRANSFORMS references still resolve
- All prior btool-hygiene fixes (0.0.7) still hold
- Version alignment: `app.manifest`, both `app.conf` version lines, `package.json`, and `host_timezone.yml` version tag all agree at 0.0.9

**Spot-check for the exact case the user reported:**
```
[sourcetype::windows:json]
EVAL-ComputerName = coalesce('System.Computer', ComputerName, MachineName)
```

## 0.0.8 (superseded) — FIELDALIAS quote character correction (single → double)

**Root cause.** Splunk's `props.conf` spec for `FIELDALIAS-<class>` requires **double quotes** around source field names that contain special characters (like the dots produced by auto-KV JSON extraction). 0.0.6 quoted them with single quotes, which parsed cleanly (no `btool` warnings — btool validates key names, not the quote character on values) but silently mis-resolved at search time. Users could verify empirically: `| rename "System.Computer" as ComputerName` works in SPL, and props.conf must use the same double-quote convention.

**Fix.** Every dotted `FIELDALIAS-*` source in `props.conf` — 636 references across 490 lines, the same set changed in 0.0.6 — has been reflipped from `'X.Y.Z'` to `"X.Y.Z"`. Affected stanzas include `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, `[xmlwineventlog]`, the `[WMI:WinEventLog:*]` stanzas, and every `cribl_compat_*` FIELDALIAS block.

**Not touched.** `EVAL-*` statements still use single quotes for dotted references (e.g. `coalesce('Message.Logon_Account', ...)`). Splunk's EVAL grammar requires single quotes for field references — the opposite convention from FIELDALIAS. Both grammars co-exist in the same file with different quote characters intentionally, and this release honors that split.

**Pack:** Lockstep version bump only; no functional pack changes.

**Post-build verification (all pass on the extracted .tgz):**
- 636 dotted FIELDALIAS sources double-quoted, 0 single-quoted, 0 unquoted
- 181 EVAL lines still using their (correct) single-quoted dotted paths
- All btool-hygiene fixes from 0.0.7 still hold (no `show_in_app_bar`, no `auto_kv_json`, no `input_field`/`output_field`, 4 `LOOKUP-*_for_WinRegistry` declarations present)
- All 228 REPORT/LOOKUP/TRANSFORMS references still resolve
- Version alignment: `app.manifest` `info.id.version` = 0.0.8, both `app.conf` version lines = 0.0.8, `package.json` = 0.0.8

## 0.0.7 (superseded) — `splunk btool check` cleanup

Fixed every schema error reported by `splunk btool check --app=Cribl_TA_windows`. All were pre-existing (present since 0.0.1) — the review focused on functional correctness, `btool` surfaces the strict conf-schema violations. None affect search results, but they cost you a set of warnings on every Splunk config reload and would fail Cloud AppInspect on the "Invalid key" checks.

**TA fixes:**
- `default/app.conf` — Removed `show_in_app_bar = true` from `[ui]`. Not a documented Splunk app.conf key; `is_visible` and `label` remain and are sufficient.
- `default/props.conf` — Removed the four `auto_kv_json = false` lines under `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, and `[xmlwineventlog]`. Not a valid props.conf key in either case (rejected by btool). `KV_MODE = json` on each stanza is the intended and supported control.
- `default/transforms.conf` — Removed `input_field` / `output_field` from four lookup stanzas (`[endpoint_change_status_lookup]`, `[endpoint_change_object_category_lookup]`, `[endpoint_change_vendor_action_lookup]`, `[endpoint_change_user_type_lookup]`). Splunk transforms.conf lookup stanzas do not support those keys — the field mapping lives in the props.conf `LOOKUP-*` declaration.
- `default/props.conf` — Rewrote the four corresponding declarations under `[sourcetype::WinRegistry]` from `TRANSFORMS-*_for_WinRegistry = <stanza>` to `LOOKUP-*_for_WinRegistry = <stanza> <input> OUTPUTNEW <output>`. Same input/output field pairs as the previous broken form; search-time behavior is preserved and now expressible in a form Splunk accepts.

**Pack:** Lockstep version bump only; no functional pack changes.

**Post-build verification (all pass):**
- No `show_in_app_bar` anywhere in `app.conf`
- No `auto_kv_json` anywhere in `props.conf`
- No `input_field` / `output_field` anywhere in `transforms.conf`
- 4 new `LOOKUP-*_for_WinRegistry` declarations present; zero ghost `TRANSFORMS-*_for_WinRegistry`
- FIELDALIAS quoting from 0.0.6 still clean
- All 228 REPORT/LOOKUP/TRANSFORMS references still resolve to defined transforms stanzas
- Manifest, `app.conf`, `package.json`, and `host_timezone.yml` version tag all agree at 0.0.7

## 0.0.6 (superseded)

**TA — nested-JSON FIELDALIAS quoting fix (correctness).** Splunk's `FIELDALIAS-*` statements treat unquoted dotted names as ambiguous — depending on the extraction path, `System.Provider.Name AS SourceName` could resolve to the literal auto-extracted JSON field `System.Provider.Name` **or** attempt an object-path traversal against a field named `System`. The safe, documented way is to single-quote the whole dotted source so Splunk resolves it as one field name. This TA had 490 `FIELDALIAS` lines with 636 dotted source references that were not quoted; every one has been fixed. `EVAL-*` statements were already using single quotes correctly and were not touched.

The fix touched `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, `[xmlwineventlog]`, the `[WMI:WinEventLog:*]` stanzas, and every `cribl_compat_*` FIELDALIAS block that mapped `Message.<Section>.<Field>` back to flat CIM names.

**Pack — lockstep bump.** No functional pack changes; `package.json` and `host_timezone.yml` version tag advanced to `0.0.6` so the paired-version convention holds.

---

## 0.0.5 (previous consolidated release)

Pack version is in `package.json`; TA version is in `default/app.conf` (both `[launcher]` and `[id]`) and `app.manifest` `info.id.version`. All references are consistent.

## Workspace layout (post-cleanup)

```
New_Windows_Pack_n_TA/
├── REVIEW.md                                    ← historical audit
├── CHANGES.md                                   ← this file
├── Cribl_TA_windows/                            ← TA source (0.0.5)
├── Cribl_TA_windows.tgz                         ← TA build (0.0.5)
├── windows_events_to_nested_json-0-0-18/         ← Pack source (0.0.5)
├── windows_events_to_nested_json-0-0-18.crbl     ← Pack build (0.0.5)
└── archive/
    ├── Cribl_TA_windows-0.0.18.tgz               ← versioned TA copy
    └── windows_events_to_nested_json-0-0-18.crbl ← versioned Pack copy
```

The pack folder was renamed from `windows_events_to_nested_json-0-0-18/` to `windows_events_to_nested_json-0-0-18/` so the directory name matches the shipping version. The fresh `.crbl` at the workspace root was built with the required flat root (files/directories at the top of the tarball — no wrapping directory prefix).

## Older versions removed

The following were superseded by 0.0.5 and have been deleted from `archive/`:

- `Cribl_TA_windows-0.0.1.tgz` — original TA reviewed in `REVIEW.md`.
- `Cribl_TA_windows-0.0.2.tgz` — interim on-desk build, never externally shipped.
- `Cribl_TA_windows-2.0.9.tgz` and `Cribl_TA_windows-2.0.9/` — earlier-generation TA with a different version scheme.
- `windows_events_to_nested_json-0-0-2.crbl` and `windows_events_to_nested_json-0-0-2/` — earlier-generation pack.

The stale `windows_events_to_nested_json-0-0-3.crbl` that was sitting at the workspace root (pre-0.0.5 pack build) was also removed.

---

## Pack changes (`windows_events_to_nested_json-0-0-18/`, version 0.0.5)

### `package.json`
- `version` bumped to `0.0.5`.
- Added `description` and meaningful `streamtags` (`windows`, `events`, `xml`, `json`, `splunk-ta`).

### `default/pack.yml`
- Was `{}`; now carries `displayName`, `description`, and `streamtags` so the pack surfaces properly in the Cribl UI.

### `data/lookups/host_timezone.csv` + `host_timezone.yml`
- Replaced the sample regex row (`.*regex_example_partial_hostname.*,America/Chicago` — technically matchable) with an obviously-inert placeholder `__DELETE_THIS_PLACEHOLDER_ROW__,UTC` plus inline usage comments explaining that the lookup only applies to Classic events without explicit tz info.
- Refreshed the `size` / `version` metadata in `host_timezone.yml` (`v0-0-5-inertsample`).

### `default/pipelines/Windows_Events_to_Nested_JSON/conf.yml` (P0 / P1 fixes)

**Code function**
- Tightened XML detection from `raw.charAt(0) === '<' || raw.indexOf('<Event') !== -1` to the anchored regex `/^<(\?xml|Event\b)/`. Classic events whose message body merely mentions "`<Event`" no longer get misrouted through `parseWinEvent`.
- Introduced `__e.__time_utc`, a hidden marker field:
  - `true` when `_time` came from an XML `System.TimeCreated.SystemTime` (always ISO-8601 UTC with `Z`).
  - `true` for Classic events only when the source timestamp string carries explicit UTC / tz info (`Z` or `±HH:MM`).
  - `false` otherwise (naive Classic timestamps).
- Channel value is whitespace-normalized (`.replace(/\s+/g, '_')`) before being concatenated into `source`.
- On parse failure the `catch` block sets `sourcetype = 'windows:json:parse_error'` alongside `cribl_code_error`. `_raw` is preserved for triage.

**Auto Timestamp function — the P1 timezone bug is fixed here**
- `timeExpression` is now `(__tz && !__time_utc) ? C.Time.adjustTZ(time.getTime(), 'UTC', __tz) / 1000 : time.getTime() / 1000`. The host-timezone shift no longer fires on events whose `_time` is already authoritatively UTC, eliminating the multi-hour drift that would have appeared as soon as anyone populated `host_timezone.csv` with real entries.

**Eval function**
- The `sourcetype` normalization preserves `windows:json:parse_error` set by the Code function's catch block, rather than clobbering it back to plain `windows:json`.

### `README.md`
- Rewrote the *Version* section as a single consolidated **0.0.5** entry (with a short *Correctness* and *Docs & metadata* split), plus preserved **0.0.2** and **0.0.1** entries. Dropped the interim **0.0.3** / **0.0.4** entries as they were never externally shipped.
- Updated the *Overview* detection row to reflect the anchored XML regex (`<?xml` or `<Event` after trimming, not "contains `<Event`").
- Refreshed the *Splunk metadata* example Eval `add` expressions to match what actually ships (including the `parse_error` guard on `sourcetype`).
- Fixed the invalid route filter example (`source=~"..."` → JavaScript regex).

---

## TA changes (`Cribl_TA_windows/`, version 0.0.5)

### `default/props.conf` (P0 fix)
Removed the dangling `REPORT-0MESSAGE = wel-message, wel-eq-kv, wel-col-kv` / `REPORT-MESSAGE =` lines from five stanzas — those transforms were never defined in `transforms.conf`:
- `[source::windows:json...]`
- `[source::(WMI:WinEventLog|WinEventLog)...]`
- `[WMI:WinEventLog:System]`
- `[WMI:WinEventLog:Security]`
- `[WMI:WinEventLog:Application]`

Each removal is replaced by a short explanatory comment so a future maintainer knows why the lines are absent. Also refreshed the stale explanatory comment above `[sourcetype::wmi]` (Section 10) so it no longer claims a REPORT is being merged.

**Impact:** No search-time behavior change for the happy Pack→TA path. `KV_MODE=json` continues to extract `Message.*` nested fields, and the `FIELDALIAS` matrix in `[sourcetype::windows:json]` maps them to the flat CIM names. What goes away is the "unresolvable REPORT" noise in `splunkd.log` on every config load.

### `app.manifest`
- `info.id.version` bumped to `0.0.5`.
- Set `platformRequirements` to `{"splunk": {"Enterprise": "8.0"}}`. The nested-JSON `FIELDALIAS` paths require Splunk 8.0+; this also helps Splunk AppInspect.

### `default/app.conf`
- Bumped both `version =` lines to `0.0.5` (`[launcher]` and `[id]`).

### `default/transforms.conf`
- Section 1 (Active Directory) header now carries an explanatory comment (userAccountPropertyFlag lives entirely in props.conf via `EVAL`, no Python) rather than sitting blank.

### `README.md`
- Compatibility table now reads `0.0.5` for both TA and Cribl pack, with a short note that the two share a single version number from 0.0.5 onward.
- Rewrote the Changelog as a single consolidated **0.0.5** entry (P0 fix + platformRequirements + cosmetic cleanups), plus **0.0.1**. Dropped the interim **0.0.2** entry as it was never externally shipped.
- Updated the "keep a fixed version" packaging example to use `0.0.5`.

---

## Verification performed

- **Pack pipeline YAML parses**; function order is `comment → code → lookup → auto_timestamp → eval`.
- **All pipeline behavior assertions pass**: `__time_utc` is set, parse-error sourcetype path is present, XML detection regex tightened, Auto Timestamp gated on `!__time_utc`, Eval preserves `parse_error`.
- **`pack.yml`, `package.json`, `route.yml` parse.**
- **`host_timezone.csv` has exactly one active row** (the inert placeholder) after comment stripping.
- **Every LOOKUP / REPORT / TRANSFORMS reference in `props.conf`** (228 unique references) resolves to a defined stanza in `transforms.conf`. No unresolved references remain.
- **Every `filename =` in `transforms.conf`** points to a CSV that ships in `lookups/`.
- **Rebuilt `Cribl_TA_windows.tgz`** contains all 54 source files, with no `.DS_Store`, `._*`, `build.sh`, `.git`, `appinspect_*`, `cribl_pack/`, or nested `.tgz` artifacts. Size: ~182 KB.
- **All version fields agree** at `0.0.5`: `app.manifest.info.id.version`, `app.conf` `[launcher] version`, `app.conf` `[id] version`, README compatibility table, and the paired pack's `package.json`.

---

## Items intentionally NOT changed

- **Classic `Date.parse` timestamp parsing.** Left as-is; the timezone fix removes the acute failure mode. A future change could switch to `C.Time.strptime` with an explicit format list, but that carries regression risk against real customer log formats and needs paired testing.
- **`workflow_actions.conf` external URLs** (`eventid.net`, `ultimatewindowssecurity.com`). Kept — customers can move them to `local/` if they need to run air-gapped.
- **Cloud-variant TA that omits `[source::WinEventLog...]` blocklisted stanzas.** Kept the current single-target build; the TA README already documents that Splunk Cloud may require exceptions for those stanzas.
- **App icons under `appserver/static/`.** Not added — no logo asset available.
(No open cleanup items remain — see "Older versions removed" above.)
