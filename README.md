# Cribl Splunk Windows → JSON

A matched pair of artifacts for collecting Windows Event Log data through **Cribl Stream / Edge** and landing it cleanly in **Splunk** — plus an OCSF pipeline for everyone else.

| | |
|---|---|
| **Cribl Pack** | [`cribl-pack/windows_events_to_nested_json-0-0-21/`](cribl-pack/windows_events_to_nested_json-0-0-21/) |
| **Splunk TA** | [`splunk-ta/Cribl_TA_windows/`](splunk-ta/Cribl_TA_windows/) |
| **Version** | 0.0.21 (both artifacts, shared in lockstep from 0.0.5 onward) |
| **Author** | David Maislin ([david@cribl.io](mailto:david@cribl.io)) |

## What this is

Windows Event Log data shows up in wildly different shapes depending on how it was collected — `.evt` classic rendered text, `.evtx` XML, or whatever a Splunk Universal Forwarder or Cribl Edge happened to normalize it to. This repo standardizes all of that into one of two structured outputs:

- **Nested JSON** (`Windows_Events_to_Nested_JSON` pipeline) → `sourcetype=windows:json` in Splunk, where the paired **Cribl_TA_windows** add-on does CIM-compliant field extraction, aliasing, and tagging — no dependency on `Splunk_TA_windows`.
- **OCSF 1.4.0** (`Windows_Events_to_OCSF` pipeline, ships disabled) → a single `__ocsf` object per event, mapped across 17 OCSF classes (authentication, account/group changes, process, network, DNS, file, registry, module, driver, scheduled job, service, event log, script), for destinations like Amazon Security Lake, Cribl Lake, Parquet, or any OCSF-speaking SIEM.

Both pipelines share the same underlying Windows Event Log parser (XML detection, `%%NNNN` message-code resolution, Classic `Message` tokenizing), so a given event maps identically regardless of which output you pick.

## Repository structure

```text
cribl-pack/
  windows_events_to_nested_json-0-0-21/   # pack source (import this into Cribl, or build the .crbl)
  windows_events_to_nested_json-0-0-21.crbl  # pre-built pack tarball
splunk-ta/
  Cribl_TA_windows/                       # Splunk app source
  Cribl_TA_windows.tgz                    # pre-built Splunk app tarball
CHANGES.md                                # full fix/version history for both artifacts
REVIEW.md                                 # original technical review (pack 0.0.3 / TA 0.0.1)
JIRA_edge_message_resolution.md           # upstream feature request: native %%NNNN resolution in Cribl Edge
```

Each component ships its own detailed README — read those for configuration, field-mapping tables, and version-by-version changelogs:

- [Cribl Pack README](cribl-pack/windows_events_to_nested_json-0-0-21/README.md) — pipeline internals, Splunk metadata conventions, OCSF class mapping, `%%NNNN` lookup regeneration.
- [Splunk TA README](splunk-ta/Cribl_TA_windows/README.md) — CIM coverage, packaging, AppInspect notes, compatibility matrix for `.evt`/`.evtx`/JSON.

## Quick start

1. **Deploy the TA first.** Copy `splunk-ta/Cribl_TA_windows.tgz` to `$SPLUNK_HOME/etc/apps/`, extract, restart Splunk (or reload apps).
2. **Import the pack.** In Cribl Stream or Edge, import `cribl-pack/windows_events_to_nested_json-0-0-21.crbl`.
3. **Route your Windows sources** to the `Windows_Events_to_Nested_JSON` pipeline (the default route). Leave `Windows_Events_to_OCSF` disabled unless you specifically want OCSF output instead.
4. Confirm events land in Splunk as `sourcetype=windows:json`, `source=windows:json:<Channel>` with CIM-aliased fields populated.

See the component READMEs for route-filter examples, pack variables, and the full Event ID → field mapping.

## Status

Both artifacts have been through a full technical review (`REVIEW.md`), a multi-release fix cycle against real Windows fleet data (`CHANGES.md` — coverage went from 63.6% → 95.4% on a live audit), and a merged community contribution adding the OCSF pipeline. Current coverage spans Security, System, Application, PowerShell, Sysmon, and WMI channels across both Classic and XML collection.
