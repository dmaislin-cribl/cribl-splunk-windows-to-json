# Review: `windows_events_to_nested_json` Pack (0.0.3) + `Cribl_TA_windows` (0.0.1)

Reviewer: Cribl Emerging Products SE
Date: 2026-08-18
Scope: Full technical + integration + best-practices review of both artifacts and how they line up end-to-end.

---

## TL;DR

The Pack does what it advertises for both XML and Classic Windows events and lands cleanly on `sourcetype=windows:json`, `source=windows:json:<Channel>` — which is exactly what the TA's `[sourcetype::windows:json]` and `[source::windows:json...]` stanzas expect. Field paths (`System.*`, `EventData.*`, `Message.*`) match on both sides, and the TA's `cribl_compat_*` FIELDALIASes are impressively thorough.

There are, however, three issues that will bite in production:

- **P0 — TA references three transforms that don't exist**: `wel-message`, `wel-eq-kv`, `wel-col-kv` are named in `REPORT-0MESSAGE` in five props stanzas including `[source::windows:json...]`, but no `[wel-message]` (etc.) stanza is defined in `transforms.conf`. Splunk will log parse errors and the intended Message post-processing for `windows:json` sources doesn't run.
- **P1 — Timezone lookup + Auto-Timestamp double-shifts UTC**: The pipeline sets `_time` from an already-UTC XML `SystemTime`, then the Auto-Timestamp step calls `C.Time.adjustTZ(..., 'UTC', __tz)`, which for XML events shifts a correct UTC epoch by the host's offset. The default `host_timezone.csv` masks this (the sample regex won't match real hosts) but the moment someone populates real entries, XML `_time` drifts by hours.
- **P1 — Version + docs drift**: `package.json` is `0.0.3`; the Pack README's "Version" section only documents `0.0.1` / `0.0.2` (plus a typo and stray `**`). The TA README table claims the Cribl pack is `0.0.1`. This is a shipping-hygiene problem — every consumer will be confused about what's actually inside.

The rest is a mix of readability, hardening, and appinspect-adjacent cleanup.

---

## What was reviewed

| Artifact | Path | Version |
|---|---|---|
| Cribl Pack | `windows_events_to_nested_json-0-0-3/` | `package.json` 0.0.3 (README says 0.0.2) |
| Splunk TA | `Cribl_TA_windows.tgz` → `Cribl_TA_windows/` | `app.conf` / `app.manifest` 0.0.1 |

Read in full: Pack README, `package.json`, `pack.yml`, `route.yml`, `Windows_Events_to_Nested_JSON/conf.yml`, `data/lookups/host_timezone.{csv,yml}`, TA README, `app.manifest`, `app.conf`, `transforms.conf`, `eventtypes.conf`, `tags.conf`, `macros.conf`, `workflow_actions.conf`, `metadata/default.meta`, plus the `[sourcetype::windows:json]`, `[source::windows:json:*]`, `[source::WinEventLog:*]`, `[wineventlog]`, and structural sections of `props.conf` (3,884 lines — sampled around all 176 stanzas).

---

## Findings — Pack

### P0 / P1

**F-P1 — Version/docs drift (P1).** `package.json` = `0.0.3` but the Pack README's *Version* section ends at `0.0.2` with a garbled line: `**0.0.2** — added Lookup function for to create __tz timezone hidden field to be used in the Advanced section of the Auto Timestamp function**.` — reads awkwardly and has a stray `**`. There is no 0.0.3 entry. The TA README's compatibility table says "Cribl pack ... 0.0.1", also wrong. Fix: bump README, add 0.0.3 changelog entry, correct the 0.0.2 line, and update the TA README's table (see also F-T5).

**F-P2 — Timezone adjust applied to already-UTC `_time` (P1, latent).** In `conf.yml`, the `code` function sets `__e._time = Date.parse(ts) / 1000` where `ts` comes from `System.TimeCreated.SystemTime` (ISO-8601 with `Z`) or Classic `_eventTime` / `TimeGenerated`. Then `auto_timestamp` receives `srcField: _time` and applies:
```
timeExpression: "__tz ? C.Time.adjustTZ(time.getTime(), 'UTC', __tz) / 1000 : time.getTime() / 1000"
```
`C.Time.adjustTZ(ms, 'UTC', <tz>)` shifts the epoch by the offset between UTC and `<tz>`. For XML events, `_time` is already correct UTC seconds — shifting it produces the wrong wall-clock. Today the default `host_timezone.csv` ships a regex (`.*regex_example_partial_hostname.*`) that won't match real hosts, so the branch is dormant. But this is a trap: the first customer who actually populates the lookup for hosts sending XML will see all their XML events land at the wrong `_time`.
Options:
- Only apply the adjustment on the Classic branch (where `TimeGenerated`/`_eventTime` may lack tz info) — split into two Auto-Timestamp functions with different filters, or gate the expression by a field like `parsed_format`.
- Or drop the `Date.parse` in the code function and let Auto-Timestamp do all parsing with the source string; the branching logic then lives in one place.
- Or simplest short-term: strip `C.Time.adjustTZ` from the expression and rely on `defaultTimezone: utc`, documenting that Classic events without tz info are assumed UTC.

### P2 / P3

**F-P3 — README suggests invalid filter syntax.** The route-narrowing example is `filter: 'source=~"WinEventLog.*" || source=~"XmlWinEventLog.*"'`. Cribl filters are JS, not SPL — `=~` doesn't parse. Fix to something like:
```yaml
filter: '/^(?:Xml)?WinEventLog/.test(source)'
```

**F-P4 — XML detection is loose.** `raw.charAt(0) === '<' || raw.indexOf('<Event') !== -1` flips into the XML branch on any Classic event whose Message body mentions "`<Event`" (rare but real, e.g., help text or template dumps). Tighten to something anchored:
```js
/^\s*<(\?xml|Event\b)/.test(raw)
```

**F-P5 — Classic `Date.parse` is engine/locale sensitive.** Windows Classic timestamps like `01/15/2024 3:00:00 PM` are outside the ECMAScript-required grammar — Node's V8 accepts many of them, but this is documented as implementation-defined. Two safer options: `C.Time.strptime(ts, '%m/%d/%Y %I:%M:%S %p')` in the code function, or defer time parsing entirely to Auto-Timestamp with an explicit `timestamps:` regex+strptime list.

**F-P6 — `pack.yml` is `{}`.** Legal, but the pack shows up in the UI with no description/tags. Fill in `displayName`, `description`, `streamtags` for discoverability. (`package.json` already has `displayName` — mirror it here.)

**F-P7 — Sample lookup regex could match real hosts.** `host_timezone.csv` ships:
```
.*regex_example_partial_hostname.*,America/Chicago
```
Extremely unlikely to hit anything, but a host literally containing `regex_example_partial_hostname` matches. Use something impossible-by-construction and comment the file:
```
# Comment: one row per host regex → IANA tz. Delete this sample.
__DELETE_THIS_ROW__,UTC
```

**F-P8 — Code function overlap with the final Eval function.** The code function sets `sourcetype`/`source` only when unset; the Eval function then unconditionally sets `sourcetype='windows:json'` and normalizes `source`. Not wrong — defense in depth — but two places to reason about. Consider: either drop the Eval-side `sourcetype` add (Code already handles it) or drop the Code-side assignment and let Eval own the metadata. Whichever direction, comment the intent so a future maintainer doesn't "clean up" one and break the other.

**F-P9 — Channel value not sanitized when placed into `source`.** `source = 'windows:json:' + channel` uses whatever the raw channel string is. Windows shipping channels don't contain spaces, but custom channels can. Consider `String(channel).replace(/\s+/g, '_')` (or `%20`, whichever downstream tolerates). Splunk source strings with spaces work but are inconsistent with the underscore-normalized keys elsewhere in the pack.

**F-P10 — Failure mode drops JSON assumption but keeps sourcetype.** In the `catch`, `_raw` is left untouched but `sourcetype` is still set to `windows:json` (from the Eval function that runs afterwards, since the Code function's assignments only execute if we reached line ~348 before throwing — but the Eval function fires unconditionally). The event lands at Splunk as `sourcetype=windows:json` with a non-JSON `_raw`. `KV_MODE=json` will produce warnings but no fields. Consider one of:
- Route errored events to a dead-letter destination or drop them.
- Set `sourcetype='windows:json:parse_error'` in the `catch` so they're greppable and don't cost the CIM pipeline anything.

**F-P11 — Positive notes (keep doing).** The Code function is well-organized: comments describe every branch, the global-variable override mechanism is clean, `sKey()` normalization is applied consistently in all output paths, and the `attachMessage` backwards-compat mode preserves legacy searches. The `filter: "true"` on every function is idiomatic for a linear pipeline. The Comment function at the head is a very useful in-UI orientation for readers.

---

## Findings — TA

### P0 / P1

**F-T1 — Missing transforms referenced by REPORT (P0).** `props.conf` contains `REPORT-0MESSAGE = wel-message, wel-eq-kv, wel-col-kv` in five stanzas:

| Line | Stanza |
|---|---|
| 446 | `[source::windows:json...]` |
| 1176 | `[source::(WMI:WinEventLog\|WinEventLog)...]` |
| 2776 | `[WMI:WinEventLog:System]` |
| 2829 | `[WMI:WinEventLog:Security]` |
| 2939 | `[WMI:WinEventLog:Application]` |

`transforms.conf` contains *no* `[wel-message]`, `[wel-eq-kv]`, or `[wel-col-kv]` stanzas (verified with `grep -E '^\[wel-'`). Splunk will:
- Log a warning for each unresolvable REPORT on config reload.
- Silently skip the REPORT (no Message parse from these transforms).

For `windows:json` sources this is mostly cosmetic because your `Message.*` sub-fields come from the Pack — KV_MODE=json extracts them and the `FIELDALIAS-Message = ... Message._summary AS Message` chain works. But: the stanza is broken, appinspect will flag it, and any customer coming in through the classic WEL / WMI:WEL sources loses the intended REPORT. Fix: either define the three transforms in `transforms.conf` or remove the `REPORT-0MESSAGE`/`REPORT-MESSAGE` lines from those stanzas.

**F-T2 — `REPORT-MESSAGE =` explicit empty (P2).** Same five stanzas have `REPORT-MESSAGE =` right after `REPORT-0MESSAGE`. Presumably meant to disable an inherited default named `MESSAGE`. If nothing was ever defining `MESSAGE` this is a no-op; if something was, it's undocumented. Add a one-line comment explaining intent, or delete.

**F-T3 — `app.manifest` lacks `platformRequirements` (P2).** `"platformRequirements": null`. Field extractions on nested JSON paths (`EventData.SubjectUserName`, `System.Provider.Name`, `Message.Subject.Account_Name`) depend on Splunk's JSON-path FIELDALIAS support, which is 8.0+ (and improves through 9.x). Declare a minimum:
```json
"platformRequirements": { "splunk": { "Enterprise": "8.0" } }
```
This also helps AppInspect.

**F-T4 — Cloud/AppInspect blocklist stanzas (P2, documented).** The TA README already acknowledges that `[source::WinEventLog...]` and similar patterns are blocklisted for Splunk Cloud. That's honest, but customers doing Cloud will need to either fork the TA to strip those stanzas or file an exception. Consider offering a Cloud variant that omits `[source::WinEventLog...]`, `[source::XmlWinEventLog...]`, and `[host::...]` stanzas and relies on `[sourcetype::…]` alone.

**F-T5 — Version metadata inconsistencies (P1, cross-artifact).**
- Pack `package.json` = `0.0.3`.
- Pack README changelog stops at `0.0.2`.
- TA README compatibility table says `Cribl pack ... 0.0.1`.
- TA `app.conf` = `0.0.1` in three places, `app.manifest` `info.id.version` = `0.0.1`. That pair is internally consistent, which is good.

If the TA and Pack are supposed to track together, either lock the Pack at `0.0.1` and update its README, or roll the TA forward as the Pack has advanced (and update the TA README). Whichever direction, `build.sh` should keep them in sync going forward.

### P2 / P3

**F-T6 — Section 1 (Active Directory) in `transforms.conf` is empty.** Header + comment but no stanzas. Fine to keep as a placeholder if AD-specific transforms are coming, otherwise delete for cleanliness.

**F-T7 — Redundant XML-block regex transforms.** `system_xml_block`, `eventdata_xml_data`, `msdns_eventdata_pairs`, `msdns_system_tags`, `msdns_other_tags`, `logfilecleared_xml_block`, `updatelist_from_user_data`, `updatetitle_from_user_data`, `extract_systemtime`, and friends operate on `_raw` looking for XML. When the Pack has run, `_raw` is JSON and these never match. Harmless but they're evaluated at search time on every matching event. Leave them if they still serve the classic-XML pass-through use case; otherwise scope them explicitly to `[source::XmlWinEventLog...]` (they are already, in most cases, but a few live under `[wineventlog]` etc.).

**F-T8 — Thin `[source::windows:json:Application]`.** Only a single `EVAL-dest`. The base `[sourcetype::windows:json]` stanza does the heavy lifting, so per-channel Application handling is essentially inherited. This is probably fine, but note that per-source stanzas in Splunk merge with sourcetype stanzas, not override — so if you add more Application-specific EVALs later they'll compose. Worth a comment stating that intent so a maintainer doesn't try to re-duplicate the parent block.

**F-T9 — `FIELDALIAS-Message` self-reference risk.** `FIELDALIAS-Message = RenderingInfo.Message AS Message, EventData.Message AS Message, Message._summary AS Message`. When KV_MODE=json extracts, `Message` starts as an object (has `_summary` and structured children). The FIELDALIAS then aliases `Message._summary` back to `Message`. In Splunk 9.x this collapses `Message` to the summary string at search-time (last write wins). If you rely on the `Message` field being the JSON *object* for other props (`FIELDALIAS-body_for_windows_security = Message AS body`), you'll get the summary string as `body`, which is likely what you want but subtle. Document this expectation.

**F-T10 — `EVAL-user`, `EVAL-object`, and friends reference dotted paths in coalesce.** e.g. `EVAL-user_group = coalesce('Message.Changed_Attributes.Display_Name', 'Message.Group.Group_Name', ...)`. Splunk requires the single-quoted-dotted-path form to reference nested JSON fields at search time (which you've done correctly). Just verify with a real Security 4720/4732/4740 event before shipping — this is the sort of thing that will silently return `null` if any node in the chain doesn't exist.

**F-T11 — `metadata/default.meta`** grants read = `*`, write = `admin, sc_admin, power`. Reasonable but note that TAs sometimes ship read-only knowledge objects (`access = read : [ * ]` only) to prevent accidental in-place edits at the customer. Choose intentionally.

**F-T12 — External workflow actions.** `workflow_actions.conf` links to `eventid.net` and `ultimatewindowssecurity.com`. Air-gapped customers will see broken links. Consider making the workflow actions opt-in (in `local/`) or documenting them explicitly in the README.

**F-T13 — No `appIcon*.png` under `appserver/static/`.** Splunk AppInspect will typically emit warnings. Not a bug, but easy polish before customer packaging.

**F-T14 — Positive notes (keep doing).**
- Section index at top of both `props.conf` and `transforms.conf` — extremely useful for a file of this size.
- Cribl-compat FIELDALIASes with `ASNEW` — right pattern (won't clobber existing values).
- `KV_MODE=json` + `auto_kv_json=false` — correct configuration for pre-parsed JSON in `_raw`.
- Standalone (no Splunk_TA_windows dependency) — big win for portability.
- CIM coverage across Authentication, Change, Endpoint, Account management — the FIELDALIAS matrix is comprehensive.
- Explicit `EVAL-userAccountPropertyFlag` implemented in props (no Python) — avoids `check_for_python_script_existence` failures for AppInspect.

---

## Findings — Pack ↔ TA integration

**F-I1 — Field paths line up cleanly.** Pack outputs `System.Channel`, `System.EventID`, `System.Computer`, `EventData.<name>` (via named-Data flattening), and `Message._summary` + subsections. TA's `[sourcetype::windows:json]` and `[source::windows:json:*]` FIELDALIASes exactly match those paths. No renaming drift found.

**F-I2 — Sourcetype/source routing is coherent.** Pack sets `sourcetype=windows:json` and `source=windows:json:<Channel>`. TA has `[sourcetype::windows:json]` (heavy lifting) plus `[source::windows:json...]` and per-channel `[source::windows:json:System|Application|Security]` overrides. Splunk merges these correctly. `eventtypes.conf` also references `source=windows:json:<Channel>` in all three `wineventlog_{application,system,security}` eventtypes — so CIM tags applied via `tags.conf` will fire.

**F-I3 — `Message.*` mapping is thorough.** The TA's `cribl_compat_*` FIELDALIAS block (76 direct aliases + 65 EVAL-based aliases) maps essentially every nested `Message.<Section>.<Field>` back to the flat name that CIM-oriented searches, dashboards, and data models expect. This is the strongest part of the whole delivery.

**F-I4 — Classic `Message._summary` becomes `Message` via FIELDALIAS.** For a Classic 4776 event, the Pack outputs:
```json
"Message": {"_summary": "The computer attempted...", "Authentication_Package": "..."}
```
The TA's `FIELDALIAS-Message = ... Message._summary AS Message` overrides the field `Message` at search time with the summary string. Downstream `FIELDALIAS-body_for_windows_security = Message AS body` then puts the summary in `body`. This is likely intended — but verify the exact search-time value of `Message` matches your CIM/ES expectations, since the pre-alias value (the JSON object) is what `Message.<subfield>` paths resolve against.

**F-I5 — Legacy `WinEventLog:*` and `XmlWinEventLog:*` still supported by TA.** The Pack's Eval function rewrites `WinEventLog:Security` → `windows:json:Security` etc. before Splunk sees it, so those legacy source stanzas mostly apply only when the Pack isn't in the path or is running in pass-through. TA README covers this explicitly (good).

**F-I6 — `wel-message` transforms would break integration if enabled.** See F-T1. For the Pack→TA happy path this is not a data-loss issue because the pack's `Message.<subfield>` structure already provides parsed values via KV_MODE=json + FIELDALIAS. But the broken REPORT will surface in `splunkd.log` and worry customers doing production reviews.

---

## Priority-ranked punch list

| # | Where | Fix | Priority |
|---|---|---|---|
| 1 | TA `transforms.conf` | Define `[wel-message]`, `[wel-eq-kv]`, `[wel-col-kv]` **or** remove `REPORT-0MESSAGE`/`REPORT-MESSAGE` from the 5 props stanzas. | **P0** |
| 2 | Pack `conf.yml` (auto_timestamp) | Don't `adjustTZ` an already-UTC `_time`. Either only run on the Classic branch or drop the tz shift and rely on parsing-time tz. | **P1** |
| 3 | Pack README + TA README | Update version tables and Pack changelog to reflect actual `0.0.3`; fix garbled `0.0.2` line. | **P1** |
| 4 | Pack README | Fix filter example (`=~` → JS regex). | P2 |
| 5 | Pack `conf.yml` (code) | Tighten XML detection: `/^\s*<(\?xml\|Event\b)/`. | P2 |
| 6 | Pack `conf.yml` (code) | Replace `Date.parse` for Classic with explicit `C.Time.strptime`. | P2 |
| 7 | Pack `conf.yml` (code) | On parse error, set `sourcetype='windows:json:parse_error'` (or route to dead-letter). | P2 |
| 8 | TA `app.manifest` | Set `platformRequirements` to Splunk 8.0+. | P2 |
| 9 | Pack `pack.yml` | Populate description/streamtags. | P3 |
| 10 | Pack `host_timezone.csv` | Replace sample regex with an obviously-inert placeholder + comment. | P3 |
| 11 | Pack `conf.yml` (code) | Sanitize channel value before concatenating into `source`. | P3 |
| 12 | TA `transforms.conf` | Remove empty AD section or add planned stanzas. | P3 |
| 13 | TA | Add `appserver/static/appIcon*.png` for AppInspect. | P3 |
| 14 | TA | Consider a Cloud-variant build target that omits blocklisted `[source::…]` stanzas. | P3 |

---

## Suggested quick wins (a customer-facing SE could ship in one afternoon)

1. Delete `REPORT-0MESSAGE`/`REPORT-MESSAGE` lines from the five broken stanzas — restores a clean load with zero risk of behavior change for `windows:json`. (~5 minutes.)
2. Update `version` in Pack README and TA README to say `0.0.3` for the Pack. Add a two-line changelog entry. (~10 minutes.)
3. Fix the `filter` example in the Pack README to use JS regex. (~2 minutes.)
4. Change `host_timezone.csv` sample row to a documented no-match placeholder. (~2 minutes.)
5. Add a `platformRequirements` block to `app.manifest`. (~2 minutes.)

Total: under half an hour of edits, addresses P0 + most P1s + several P2/P3 items, and dramatically improves the AppInspect + shipping-hygiene story.
