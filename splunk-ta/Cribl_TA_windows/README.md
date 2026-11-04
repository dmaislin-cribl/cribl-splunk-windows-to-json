# Cribl Windows TA for Splunk

**Universal, standalone** Splunk Add-on for Microsoft Windows. Handles all Windows event formats with **no dependency on Splunk_TA_windows**.

| Component | Version |
|-----------|---------|
| **Splunk app** (`default/app.conf`, `app.manifest`) | **0.0.19** |
| **Cribl pack** (`windows_events_to_json` / `cribl_pack/...`) | **0.0.19** |

The TA and its paired Cribl pack share a single version number from 0.0.5 onward so operators can talk about a single delivery without disambiguation.

## Changelog

**0.0.19** — `user`/`user_name`/`src_user` now resolve for plain `Subject:` events; paired pack fix for dropped multi-line `Message` values

Found by replaying a real customer's classic-event export (9 Security-channel event types: 4688, 4776, 4793, 4670, 4673, 4672, 4627, 4624, 4798) through the actual pack parser and cross-checking every resulting field path against this TA's FIELDALIAS/EVAL chains.

**TA fix** — `FIELDALIAS-user`, `FIELDALIAS-user_name`, and `FIELDALIAS-src_user` (in both `[source::windows:json:Security]` and `[source::WinEventLog:Security]`) included `Message.Creator_Subject.Account_Name` (the section name 4688/4689 process events use) but never plain `Message.Subject.Account_Name` — the section name the *majority* of other Security audit events use (4670, 4672, 4673, 4793, 4798, 4627, and more). Every one of those event types shipped with `user`/`user_name`/`src_user` silently null despite the value being present in `_raw` the whole time. Added `"Message.Subject.Account_Name" AS <target>` to all three aliases in both stanzas. No collision with 4688/4689: those events never populate a plain `Subject` section.

**Paired pack fix** — `parseClassic()` was silently dropping every value past the first in Windows' multi-line `Message` keys (e.g. 4672's `Privileges:` list, which can carry up to a dozen entries with only the first on the `Key:` line). A real 4672 sample was losing 11 of 12 assigned privileges, including `SeDebugPrivilege` and `SeImpersonatePrivilege`. Fixed upstream in the pack; see the pack's own changelog (0.0.19) for detail. No TA-side change needed — `Message.Privileges` now arrives as a proper JSON array, and `KV_MODE=json` extracts it as a multivalue field automatically.

**Verification:** Re-parsed the full 9-event-type sample with the fixed pack logic — only 4672's `Privileges` field changed shape (string → array); the other 8 event types were byte-identical to 0.0.18. `props.conf` double-quote convention, stanza hygiene (no duplicate FIELDALIAS/EVAL targets, no `ASNEW`, no self-aliases, no `[sourcetype::X]` stanzas) all still hold.

**0.0.18** — Coverage: **63.6% → 95.4%** on real Windows fleet audit

A field-by-field audit against a live Windows host (comparing 4 CSV exports — UF small/large and Cribl small/large from the same box) found the TA was covering only 63.6% of the 391 unique field names those events actually contained. This release lifts that to **95.4%** through two coordinated fixes across the pack and TA:

**Paired Pack fix (A)** — `clean()` now flattens `EventData.Data` when it's a *plain keyed object* (not just when it's an array of `{Name, _value}` pairs). Previously, events where `parseWinEvent` had already flattened `Data` internally were leaking through as `EventData.Data.<X>` in `_raw`, and the TA's FIELDALIAS chains were written against `EventData.<X>` — which never matched. Now `EventData.<X>` is what actually lands in `_raw`, so every existing TA alias fires. This single change adds ~16 fields' worth of coverage on its own.

**TA additions (B)** — 125+ new `FIELDALIAS` entries in `[windows:json]` and `[WinEventLog]` covering:

- **Classic-format sibling names** the UF's rendered-text output surfaces: `Application_Name`, `Caller_Machine_Name`, `Caller_Logon_ID`, `Client_Logon_ID`, `Client_Machine_Name`, `Client_User_Name`, `Client_Domain`, `Primary_Domain`, `Primary_User_Name`, `Supplied_Realm_Name`, `Target_Account_ID`, `Target_Process_Name`, `Transited_Services`, `Workstation_Name`, `Member_ID`, `Member_Name`, `Group_Type_Change`, `Change_Type`, `New_Domain`, `New_Account_Name`, `Account_Domain`, `CategoryString`, `User_Name`, `Network_Account_Domain`, `Network_Account_Name`, `Linked_Logon_ID`, `Package_Name__NTLM_only_`.
- **Registry Value change (event 4657) fields**: `Old_Value`, `New_Value`, `Old_Value_Type`, `New_Value_Type`, `Object_Value_Name`, `Operation_Type`.
- **File / Object path names**: `File_Name`, `Image_File_Name`.
- **Modern Windows Server 2022+ fields**: `ElevatedToken`, `MandatoryLabel`, `KeyLength`, `LmPackageName`, `LogonGuid`, `LogonProcessName`, `RestrictedAdminMode`, `RemoteCredentialGuard`, `RemoteMachineID`, `RemoteUserID`, `HasRemoteDynamicKeywordAddress`, `ImpersonationLevel` — plus their underscore-normalized twins.
- **Windows Filtering Platform (5152 / 5155-5159) fields**: `Direction`, `LayerName`, `LayerRTID`, `FilterOrigin`, `FilterRTID`, `Protocol`, `Application`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `IsLoopback`, `InterfaceIndex`, `CurrentProfile`, `OriginalProfile` — plus their underscore-normalized twins.
- **CIM aliases for Network Traffic data model**: `SourceAddress → src / src_ip`, `DestAddress → dest / dest_ip`, `SourcePort → src_port`, `DestPort → dest_port`, `Application → app`, `Protocol → transport_number`, plus `EVAL-transport` (numeric protocol → tcp/udp/icmp/etc), `EVAL-direction` (LayerName / Direction → inbound / outbound), and `EVAL-action_wfp` (EventCode → blocked / allowed). Firewall events will now populate the CIM Network Traffic datamodel correctly for Splunk ES.
- **Additional EventData / System paths**: `NewProcessId`, `ProcessID`, `ThreadID`, `SubjectUserSid`, `TargetUserSid`, `TargetLogonId`, `TargetLinkedLogonId`, `TargetOutboundDomainName`, `TargetOutboundUserName`, `VirtualAccount`, `ActivityID`, `Version`, `Provider_Guid`, `Keywords`, `Opcode`.

**Regression checks passed:** 0 invalid `[sourcetype::X]` stanzas, 0 ASNEW-form FIELDALIAS, 0 self-aliases, 0 duplicate FIELDALIAS keys or EVAL targets within any stanza, all 1,519 dotted-source FIELDALIAS references still double-quoted per Splunk spec, all REPORT/LOOKUP/TRANSFORMS references resolve, 0.0.7 btool-hygiene fixes intact.

**Verified in shipped tarball:**
- Pack `.crbl` version: 0.0.18
- TA `.tgz` version: 0.0.18
- FIELDALIAS lines: **1,150** (was 1,010 in 0.0.17)
- EVAL lines: **401** (was 395)
- Pack `resolveWinCodes` walker + `C.Lookup` call from 0.0.17 unchanged.

**0.0.17** — Paired Pack's `%%NNNN` resolution fixed

The paired Cribl pack's Code function had two bugs (`new C.Lookup` instead of the factory-call form, and single-arg `.match()` which returns a boolean instead of two-arg `.match(v, 'value')` which returns the resolved string). Both fixed in 0.0.17 per Cribl's Inline Lookup docs. No functional change on the TA side beyond the lockstep version bump; the shipped `.tgz` is byte-identical to 0.0.16 except for the version strings.

**0.0.16** — Authoritative `%%NNNN` lookup in the paired Pack

The paired Cribl pack replaced its 201-entry curated `windows_msg_codes.csv` with the full 979-entry authoritative extract from `adtschema.dll` (sourced from nsacyber/Event-Forwarding-Guidance). Two mappings in the earlier snapshot were also corrected — `%%8192` (was wrongly `ACCESS_ALLOWED`, correctly `Kerberos` IPsec auth method) and the `%%14608`/`%%14609`/`%%14614`/`%%14615` WFP Layer Names. No TA-side changes; lockstep version bump only.

**0.0.15** — Regeneration tool for `%%NNNN` lookup

The paired Cribl pack now ships a PowerShell script (`data/lookups/regenerate_windows_msg_codes.ps1`) that extracts message-code strings directly from a Windows host's resource DLLs using the same `LoadLibraryEx` + `FormatMessage()` calls Windows uses internally. Operators can regenerate `windows_msg_codes.csv` against their own Windows build whenever needed — covers codes that a shipped snapshot may not include. No functional change on the TA side beyond the lockstep version bump.

**0.0.14** — Windows message-code (`%%NNNN`) resolution moves upstream

The paired Cribl pack now resolves Windows message-file codes (`%%14592` → `Inbound`, `%%1826` → `False`, etc.) at collection time, emulating the Splunk Universal Forwarder's behavior. The TA sees fully-resolved values in fields like `EventData.Direction`, `EventData.IsLoopback`, `EventData.LayerName`, etc., so no TA-side `LOOKUP-*` declarations are needed for those codes. No functional change on the TA side beyond the lockstep version bump. The pack ships the resolution table as `data/lookups/windows_msg_codes.csv` (193 codes); users can extend it by adding rows.

**0.0.13** — Fixed invalid `[sourcetype::X]` stanza headers → bare `[X]`

Splunk's `props.conf` spec supports `[<sourcetype>]` (bare), `[host::…]`, `[source::…]`, `[rule::…]`, and `[delayedrule::…]`. It does **not** support `[sourcetype::<name>]` — that form is parsed as a literal sourcetype value `sourcetype::<name>`, which never matches a real event. The stanza (and every extraction under it) is effectively dead. Four stanzas in this TA had that mistake since 0.0.1 — the `[sourcetype::windows:json]` one likely explains why some of the earlier FIELDALIAS + double-quote experiments didn't seem to be materializing (the containing stanza wasn't binding to any events).

Converted:
| Before | After |
|---|---|
| `[sourcetype::ActiveDirectory]` | `[ActiveDirectory]` |
| `[sourcetype::WinEventLog]` | `[WinEventLog]` |
| `[sourcetype::WinRegistry]` | `[WinRegistry]` |
| `[sourcetype::wmi]` | `[wmi]` |

(`[sourcetype::windows:json]` had already been corrected to `[windows:json]` in an earlier edit — same fix, just already applied.)

**Verification:**
- 0 remaining `[sourcetype::…]` stanza headers
- All 228 REPORT/LOOKUP/TRANSFORMS references still resolve
- No collisions: none of the target bare-form stanza names (`[ActiveDirectory]`, `[WinEventLog]`, `[WinRegistry]`, `[wmi]`) previously existed elsewhere in the file
- All prior fixes intact: no `ASNEW` on FIELDALIAS, no self-aliases, 1,313 double-quoted dotted FIELDALIAS sources, 0 single-quoted or unquoted, 0 duplicates within any stanza, 0.0.7 btool hygiene preserved.

**Pack:** Lockstep version bump only; no functional pack changes.

**0.0.12** — Removed self-alias `FIELDALIAS-*` entries

Splunk's `FieldAliaser` logs "Invalid field alias specification" for any `FIELDALIAS-X = Foo AS Foo` (source and target being the same field). Those entries are no-ops — they alias a field to itself. The `cribl_compat_*` block had 30 such self-aliases (10 unique targets: `ComputerName`, `Keywords`, `LogName`, `OpCode`, `SourceName`, `Type`, `product`, `severity`, `vendor`, `vendor_product` — each duplicated across the JSON-consuming stanzas). All 30 have been deleted. Zero self-alias pairs remain.

**0.0.11** — Uniform `AS` on all `FIELDALIAS-*` declarations (removed `ASNEW`)

The `cribl_compat_*` FIELDALIAS block previously used `ASNEW` as a defensive measure to avoid clobbering legacy flat fields that might have been pre-populated by another TA. For this TA's actual ingest path (Cribl-normalized JSON via the paired pack, no other Windows TA layered on top), nothing else pre-populates those legacy flat names, so `AS` produces the same result and keeps the config uniform.

232 `ASNEW` keywords on FIELDALIAS pairs were converted to `AS`. `ASNEW` remains in narrative comments and commented-out sample lines only. No structural or behavioral changes for the current ingest path.

**0.0.10** — Revert dotted-source aliases from `EVAL` back to `FIELDALIAS` (with double-quoted dotted sources)

0.0.9 converted every dotted-source `FIELDALIAS-*` in the JSON-consuming stanzas to `EVAL-*` because of a suspected search-time resolution issue. This release reverses that: the community and Splunk-documented convention for aliasing nested-JSON auto-KV fields is `FIELDALIAS-<class> = "Nested.Path" AS <target>` with **double quotes**. Where FIELDALIAS is preferred (declarative, essentially free per event) over EVAL (per-event `coalesce()` expression evaluation), this release restores that.

**Scope of the revert.** 652 `EVAL-*` statements — every one that had been derived from a 0.0.6/0.0.9 FIELDALIAS transformation — were split back into `FIELDALIAS-*` declarations with double-quoted dotted sources. Where an `EVAL-*` had been merged with the pack's native fallback chain (e.g. `coalesce('System.Computer', ComputerName, MachineName)`), the transformation split cleanly: the dotted arg becomes `FIELDALIAS-<target> = "System.Computer" AS <target>` and the residual fallback survives as `EVAL-<target> = coalesce(ComputerName, MachineName)`. This is exactly the pre-0.0.9 structure, but with the correct double-quote convention (previously we had 0.0.6 single quotes, 0.0.8 double quotes, then 0.0.9 EVAL — now back to 0.0.8's double-quoted FIELDALIAS approach with the pack's native fallbacks intact).

**Result.**
- 1,010 `FIELDALIAS-*` lines (up from 358 in 0.0.9)
- 395 `EVAL-*` lines (down from 970 in 0.0.9 — 575 were pure FIELDALIAS conversions that got removed, 77 were merged and retained a non-dotted residual)
- 1,313 double-quoted dotted `FIELDALIAS` sources, 0 single-quoted, 0 unquoted
- 0 duplicate `FIELDALIAS-<key>` or `EVAL-<target>` within any stanza
- 0 changes to the 0.0.7 btool-hygiene fixes (still no `show_in_app_bar`, `auto_kv_json`, `input_field`/`output_field`; 4 `LOOKUP-*_for_WinRegistry` still present)

**Canonical example (the user's test case):**
```
[sourcetype::windows:json]
FIELDALIAS-ComputerName = "System.Computer" AS ComputerName
EVAL-ComputerName = coalesce(ComputerName, MachineName)
```

**Pack:** Lockstep version bump only; no functional pack changes.

**0.0.9** — Convert dotted-source `FIELDALIAS` to `EVAL` (nested-JSON alias resolution)

`FIELDALIAS-<class> = "A.B.C" AS X` parses cleanly and shows up in the Splunk UI's Field Aliases list, but **does not** materialize the aliased field at search time when the source is a nested-JSON path produced by `KV_MODE = json` auto-extraction. `btool` doesn't catch this because the config is syntactically valid — the failure is purely at resolution time. Empirical test that surfaced this: `| rename "System.Computer" as ComputerName` works in SPL against a `windows:json` event, but the equivalent `FIELDALIAS-ComputerName = "System.Computer" AS ComputerName` in props.conf does not produce a searchable `ComputerName` field.

Every `FIELDALIAS-*` declaration whose source contained a dot has been converted to an `EVAL-*` declaration using Splunk EVAL's single-quoted dotted-path grammar (which resolves auto-KV JSON extractions correctly). When an existing `EVAL-*` for the same target field already existed in the stanza, the two were merged so the pack's native-flat-JSON fallback chain (e.g. `coalesce(EventCode, Id)`) is preserved and the new dotted source is prepended: `coalesce('System.EventID', EventCode, Id)`.

Scope of the change: 7 stanzas touched (all the JSON-consuming ones — `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, `[xmlwineventlog]`, and the two `[WMI:WinEventLog:*]` stanzas that inherit similar semantics). 488 unique target fields across those stanzas now resolve via EVAL. Non-dotted `FIELDALIAS-*` declarations (aliasing top-level Cribl-flat fields like `ComputerName ASNEW ComputerName`, `TaskCategory as category`, etc.) were left as FIELDALIAS.

**Why EVAL instead of double-quoted FIELDALIAS (which 0.0.8 attempted):** Splunk's props.conf spec claims double quotes work for special-character field names in FIELDALIAS, and syntactically they parse. But for the specific case of auto-KV JSON dotted extractions, `FIELDALIAS` does not reliably resolve the source field at search time. Splunk EVAL with single-quoted dotted references, in contrast, is documented to work against those extractions and is the community-established workaround. This release accepts the small per-event EVAL cost in exchange for correct resolution.

**Not touched:** The 358 remaining `FIELDALIAS-*` declarations (all non-dotted-source) continue to work as-is. The pre-existing 0.0.7 `LOOKUP-*_for_WinRegistry` fixes and the 0.0.5 `platformRequirements` / `wel-message` cleanups are all still in place.

Version bumped to 0.0.9 to remain in lockstep with the paired Cribl pack (no functional pack changes).

**0.0.8** — FIELDALIAS quote character correction (single → double)

Splunk's `props.conf` spec for `FIELDALIAS-<class>` requires **double quotes** — not single — around source field names that contain special characters (including the dots produced by auto-KV JSON extraction). `btool check` doesn't validate quote characters on values, so this silently mis-parsed at search time even though the config loaded without warnings. Verification: `| rename "System.Computer" as ComputerName` works in SPL; the same field reference inside props.conf must use the same double-quote convention.

Every dotted `FIELDALIAS-*` source across `props.conf` (490 lines, 636 references — the same ones changed in 0.0.6, now with the correct quote character) has been reflipped from `'X.Y.Z'` to `"X.Y.Z"`. Affected stanzas: `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, `[xmlwineventlog]`, the `[WMI:WinEventLog:*]` stanzas, and every `cribl_compat_*` FIELDALIAS block.

`EVAL-*` statements were **not** touched — Splunk's EVAL grammar requires single quotes for dotted field references (e.g. `EVAL-user = coalesce('Message.Logon_Account', ...)`), which is the opposite convention from FIELDALIAS. The two grammars co-exist in the same file and use different quote characters intentionally.

Version bumped to 0.0.8 to remain in lockstep with the paired Cribl pack (no functional pack changes this release).

**0.0.7** — Splunk `btool check` cleanup

Fixed every schema error reported by `splunk btool check --app=Cribl_TA_windows` against this app's own conf files:
- **`default/app.conf`** — Removed `show_in_app_bar = true` from the `[ui]` stanza. `show_in_app_bar` is not a documented Splunk app.conf key; `is_visible` and `label` remain and are sufficient for the app to show up in the Splunk UI.
- **`default/props.conf`** — Removed the four `auto_kv_json = false` lines under `[sourcetype::WinEventLog]`, `[source::XmlWinEventLog...]`, `[wineventlog]`, and `[xmlwineventlog]`. `auto_kv_json` is not a valid props.conf key (btool rejects it in both cases). `KV_MODE = json` on each stanza is the intended control and stays.
- **`default/transforms.conf`** — Removed the invalid `input_field` / `output_field` keys from four lookup stanzas: `[endpoint_change_status_lookup]`, `[endpoint_change_object_category_lookup]`, `[endpoint_change_vendor_action_lookup]`, `[endpoint_change_user_type_lookup]`. Splunk transforms.conf lookup stanzas take `filename`, `case_sensitive_match`, `max_matches`, `min_matches`, `default_match`, `match_type` — the input/output field mapping must live in the props.conf `LOOKUP-*` declaration.
- **`default/props.conf`** — Rewrote the four corresponding declarations under `[sourcetype::WinRegistry]` from `TRANSFORMS-*_for_WinRegistry = <lookup_stanza>` to `LOOKUP-*_for_WinRegistry = <lookup_stanza> <input> OUTPUTNEW <output>` so the mapping is expressed in the Splunk-supported form. Search-time behavior is preserved (same input/output field pairs as before).

Version bumped to 0.0.7 to remain in lockstep with the paired Cribl pack (no functional pack changes this release; version bump only).

**0.0.6** — Correctness fix for nested-JSON `FIELDALIAS` resolution
- Single-quoted every dotted source path in `FIELDALIAS-*` declarations across `props.conf` (490 lines touched, 636 dotted references quoted). Without quotes, Splunk can misinterpret `A.B.C AS x` as a nested-object traversal instead of resolving the literal auto-extracted JSON path `A.B.C`. This affected `[sourcetype::windows:json]`, `[sourcetype::WinEventLog]`, `[wineventlog]`, `[xmlwineventlog]`, the `[WMI:WinEventLog:*]` stanzas, and every Cribl-compat FIELDALIAS block that mapped `Message.Section.Field` back to flat CIM names. `EVAL-*` statements were already using single quotes correctly and were not touched.
- Version bumped to 0.0.6 to remain in lockstep with the paired Cribl pack (no functional changes on the pack side for this release; version bump only).

**0.0.5** (consolidated release — supersedes the interim 0.0.2 desk build)
- **P0 fix.** Removed dangling `REPORT-0MESSAGE = wel-message, wel-eq-kv, wel-col-kv` and `REPORT-MESSAGE =` lines from five `props.conf` stanzas: `[source::windows:json...]`, `[source::(WMI:WinEventLog|WinEventLog)...]`, `[WMI:WinEventLog:System]`, `[WMI:WinEventLog:Security]`, `[WMI:WinEventLog:Application]`. Those transforms were never defined in `transforms.conf`, so Splunk emitted "unresolvable REPORT" warnings on every config load. Search-time Message-field extraction was already handled by `KV_MODE=json` plus the FIELDALIAS matrix in `[sourcetype::windows:json]`, so no user-visible behavior change — just quieter `splunkd.log`.
- Declared `platformRequirements.splunk.Enterprise = "8.0"` in `app.manifest`. Nested-JSON `FIELDALIAS` paths (`System.Provider.Name`, `Message.Subject.Account_Name`, `Message.Process.Process_Name`, and the entire `cribl_compat_*` matrix) require Splunk 8.0+; the declaration also unblocks a class of AppInspect checks.
- Populated the empty Section 1 (Active Directory) header in `transforms.conf` with an explanatory comment (userAccountPropertyFlag lives entirely in props via `EVAL` on `userAccountControl`, so no Python lookup ships).
- Refreshed the stale "REPORT-0MESSAGE is merged into [WMI:WinEventLog:*]" comment above `[sourcetype::wmi]` so it reflects the current state.
- Bumped `app.conf` and `app.manifest` versions to 0.0.5, matching the paired Cribl pack.

**0.0.1** — Initial standalone release.

## Compatibility: `.evt`, `.evtx`, and JSON

This TA (and the optional **Windows Events to Nested JSON** Cribl pack) are built for the shapes Windows events take in the pipeline—not the archive filename alone—but those line up with the usual file formats:

| Origin | What shows up in `_raw` | How this repo handles it |
|--------|-------------------------|---------------------------|
| **`.evt` (classic Event Log)** | Legacy binary logs are almost always **rendered as classic text** (`Key=Value` headers and a **Message** body) before Splunk or Cribl see them | **Classic** / **WinEventLog** props; the pack’s **classic** parser if you normalize through Cribl |
| **`.evtx` (modern Event Log)** | Typically **XML** (`<Event>…</Event>`) from WEC/WEF, Splunk Universal Forwarder (XML rendering), Edge, Sysmon XML exports, etc. | **XmlWinEventLog** props; the pack’s **XML** branch if you normalize through Cribl |
| **JSON** | Nested JSON (often after the pack, or from another converter) with Splunk-friendly **`source`/`sourcetype`** | **`windows:json`** and per-channel sources such as **`windows:json:Security`**, with **`KV_MODE=json`** |

You do not maintain one Splunk app per extension: configure **metadata and payload shape** (classic text vs XML vs JSON) to match the rows below.

## Supported formats

| Format | Sourcetype | Source | Description |
|--------|------------|--------|-------------|
| **Classic** | WinEventLog | WinEventLog:Security, etc. | Key=Value format (legacy Windows Event Log) |
| **XML** | XmlWinEventLog | XmlWinEventLog:Security, etc. | XML (WEC/WEF, Sysmon, modern collectors) |
| **JSON (recommended with Cribl pack)** | **windows:json** | **windows:json:Security**, etc. | Nested JSON in `_raw`; Splunk metadata matches JSON extraction (see **`cribl_pack/`** and **`windows_events_to_json/`**) |
| **JSON (legacy)** | WinEventLog / XmlWinEventLog | WinEventLog:… / XmlWinEventLog:… | Nested JSON in `_raw` but original metadata unchanged; TA still uses `KV_MODE=json` on those stanzas |

If you already emit **`source`/`sourcetype`** with a legacy **`json:windows:`** prefix, the sample pack **Eval** rewrites it to **`windows:json:`** so it aligns with this TA.

## Features

- **Cribl nested JSON + Splunk-oriented metadata** — Pack **`cribl_pack/Windows_Events_to_Nested_JSON`** (mirror: **`windows_events_to_json/`**) converts XML or classic rendered text to nested JSON and sets **`sourcetype=windows:json`** and **`source=windows:json:<Channel>`** so Splunk does not treat `_raw` as classic WinEventLog text.
- **Classic message body** — Parser and TA cover structured **`Message`** sections (tab-indented blocks) and **flat** classic keys such as **`Message.Authentication_Package`**, **`Message.Logon_Account`**, **`Message.Source_Workstation`**, **`Message.Error_Code`** (e.g. Security **4776**).
- **Host alignment** — When the pack parses **`ComputerName`** or XML **`System.Computer`** / **`System.ComputerName`**, it sets **`__e.host`** to that value for consistent host metadata downstream.
- **KV_MODE=json** — Extracts nested JSON from `_raw` (no `| spath` needed when props apply in the right app context).
- **Standalone** — No Splunk_TA_windows required. Lookups and transforms ship with the app.
- **CIM-oriented** — FIELDALIAS, EVAL, REPORT, and transforms map Windows and nested **`Message.*`** fields toward Authentication, Change, Endpoint, and related models.
- **Navigation** — Large config files include a **section index** at the top (see **`default/props.conf`** and **`default/transforms.conf`**).

## Repository layout

| Path | Purpose |
|------|---------|
| **`default/`**, **`lookups/`**, **`bin/`** | Splunk add-on core (what **`build.sh`** puts inside **`Cribl_TA_windows.tgz`**) |
| **`README.md`** | Shipped with the TA so installers have app context |
| **`app.manifest`** | Splunk package metadata at app root (**schemaVersion** 2.0.0); **`info.id.version`** stays aligned with **`app.conf`** when using **`build.sh`** |
| **`windows_events_to_json/`** | Cribl pack authoring copy (repo only; **not** inside **`Cribl_TA_windows.tgz`**) |
| **`cribl_pack/Windows_Events_to_Nested_JSON/`** | Same pack for Stream import (repo only; **not** inside the TA tarball) |
| **`PACK_AND_WINDOWS_EVENTS.md`** | Repo-only: how the two pack paths stay in sync and how to build a **`.crbl`** tarball (**not** in the Splunk app tarball) |
| **`build.sh`** | Version bump + Splunk app tarball (see **Packaging** for full exclude list) |
| **`run_appinspect.sh`**, **`appinspect_last_run.txt`**, **`appinspect_report.json`** | Repo-only: local **Splunk AppInspect** run + logs (**not** in the Splunk app tarball) |

## Cribl configuration

1. **Recommended:** Import the pack from **`cribl_pack/Windows_Events_to_Nested_JSON`** (see **`cribl_pack/README.md`**). The same pipeline lives at **`windows_events_to_json/`** for a focused workspace. Details: **`PACK_AND_WINDOWS_EVENTS.md`**. The pack sets **`sourcetype=windows:json`** and **`source=windows:json:<Channel>`**, matching **`props.conf`** stanzas **`[sourcetype::windows:json]`** and **`[source::windows:json...]`**.

2. **Legacy:** If you send nested JSON but **leave** `WinEventLog` / `XmlWinEventLog` metadata unchanged, the TA still applies **`KV_MODE=json`** on those sources.

*Note: Classic key=value or raw XML without going through the pack may need different **`KV_MODE`** / breaking.*

Do not introduce ad-hoc sourcetypes like `CriblJsonWinEventLog` unless you add matching **`props.conf`** yourself.

**If fields still require `| spath`:** Run searches from an app that includes this TA (for example Search & Reporting with **Cribl_TA_windows** as a dependency, or the TA app itself). Search-time props depend on app context. After deploy, restart Splunk or run `| rest /services/configs/conf-props reload=true`.

## Packaging

The build script expects the app directory to be named **`Cribl_TA_windows`** (typical Git clone layout). From the **parent** of that folder:

```bash
cd /path/to/parent
./Cribl_TA_windows/build.sh
```

This bumps the patch version in **`default/app.conf`** (all **`version =`** lines), updates **`app.manifest`** → **`info.id.version`** to match, and writes **`Cribl_TA_windows/Cribl_TA_windows.tgz`**.

**Files and directories omitted from the Splunk app tarball** (they stay in the Git repo for development only):

| Excluded | Reason |
|----------|--------|
| **`cribl_pack/`** | Cribl Stream pack (distributed separately as a **`.crbl`**) |
| **`windows_events_to_json/`** | Authoring copy of that pack—keeps the Splunk TA bundle free of pack assets |
| **`build.sh`** | Maintainer script |
| **`run_appinspect.sh`**, **`appinspect_last_run.txt`**, **`appinspect_report.json`** | AppInspect helper and output |
| **`PACK_AND_WINDOWS_EVENTS.md`** | Repo layout / pack-sync notes |
| **`.git`**, **`.gitignore`**, dotfiles / metadata junk | Not part of an app install |
| In-repo **`Cribl_TA_windows.tgz`** | Avoid nesting the previous build |

**Included** in the tarball: **`app.manifest`** (Splunk packaging metadata; version is kept in sync with **`default/app.conf`** when you run **`build.sh`**), **`README.md`**, **`default/`**, **`metadata/`** (e.g. **`default.meta`** at app root, sibling of **`default/`**), **`lookups/`**, **`bin/`** (if present). **Neither** the Cribl pack under **`cribl_pack/`** nor the **`windows_events_to_json/`** mirror is shipped inside the TA. If you change version without **`build.sh`**, update **`app.manifest`** → **`info.id.version`** to match **`app.conf`**.

To keep a fixed version (for example **0.0.18**) on both the Splunk app and the pack **`package.json`** values, edit **`default/app.conf`** (and both packs) after running **`build.sh`**, or tarball manually without **`build.sh`**.

Manual tarball example (same intent as **`build.sh`**, without a version bump):

```bash
cd /path/to/parent
APP=Cribl_TA_windows
COPYFILE_DISABLE=1 tar \
  --exclude='._*' --exclude='.DS_Store' --exclude='.git' --exclude='.gitignore' --exclude='.*' \
  --exclude="$APP/build.sh" --exclude="$APP/Cribl_TA_windows.tgz" \
  --exclude="$APP/cribl_pack" --exclude="$APP/windows_events_to_json" \
  --exclude="$APP/appinspect_last_run.txt" --exclude="$APP/appinspect_report.json" \
  --exclude="$APP/PACK_AND_WINDOWS_EVENTS.md" --exclude="$APP/run_appinspect.sh" \
  -czf "$APP/Cribl_TA_windows.tgz" "$APP"
```

### Splunk Cloud and AppInspect

`precert` validation can still report **warnings** when **`failure: 0`**. This TA ships **`app.manifest`** so packaging checks like **`check_for_valid_package_id`** run instead of **skipped**. It also targets **fixable** in-repo issues (for example pretrained **`WindowsUpdateLog`** handling uses sourcetype **`Cribl_TA_windows_WindowsUpdateLog`** in **`props.conf`**, duplicate **`EVAL-*`** keys are avoided for **`check_config_file_parsing`**, and **`bin/*.py`** is not shipped—**`userAccountPropertyFlag`** for Active Directory is implemented in **`props.conf`** so **`check_for_python_script_existence`** does not fire).

You may still see Splunk-platform warnings such as **`[source::WinEventLog...]`** blocklists for Cloud Operation checks while a full Windows TA still relies on those patterns for classic forwarded events; **exceptions or review** may be required for those.

From the app directory, **`./run_appinspect.sh`** builds a **temporary** tarball using the **same omit list** as **`build.sh`**, runs **`splunk-appinspect inspect … --mode precert`**, and appends a short summary to **`appinspect_last_run.txt`**.

## Installation

1. Deploy **`Cribl_TA_windows`** to **`$SPLUNK_HOME/etc/apps/`**
2. Restart Splunk or reload the app
3. **Optional:** Remove Splunk_TA_windows if this TA fully replaces it for your use case

## Contents (Splunk app)

| File / directory | Purpose |
|------------------|---------|
| **`app.manifest`** | App package metadata (**schemaVersion** 2.0.0; **`info.id`** aligns with **`app.conf`** **[package]** / **[id]**) |
| **`default/app.conf`** | Install, UI, launcher, package id, version |
| **`metadata/default.meta`** | Export permissions for knowledge objects in **`default/`** (app root **`metadata/`**, not under **`default/`**) |
| **`default/props.conf`** | Field extraction, aliases, lookups — by sourcetype/source (section index at top) |
| **`default/transforms.conf`** | REGEX, LOOKUP, REPORT transforms (section index at top) |
| **`default/eventtypes.conf`** | Windows event type definitions |
| **`default/tags.conf`** | CIM tags |
| **`default/macros.conf`** | Search macros |
| **`lookups/`** | CSV lookups (signatures, severities, actions, privileges, etc.) |
| **`bin/`** | Optional; may be empty. Active Directory **`userAccountPropertyFlag`** is derived from **`userAccountControl`** via **`EVAL`** on **`[sourcetype::ActiveDirectory]`** (no Python lookup shipped) |

## CIM data models

Aligned with common Splunk CIM usage for:

- Authentication  
- Change / Change Audit  
- Endpoint (processes, services, registry, port)  
- Account management  
- Event signatures  
