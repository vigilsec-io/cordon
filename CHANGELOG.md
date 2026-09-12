# Changelog

## 0.4.1

### Fixed

- **SARIF now identifies the tool correctly.** Output declared
  `tool.driver.name: "vigil"` and `tool.driver.version: "0.1.0"` regardless of the
  installed release, because the version was hardcoded and never passed by the CLI.
  It is now read from package metadata.

  **If you upload Valca's SARIF to GitHub code scanning:** alerts created before
  0.4.1 are recorded against the tool name `vigil`. GitHub groups alerts by tool
  name, so alerts from 0.4.1 onwards appear under `valca` and the older ones will
  not be closed automatically by new runs. Delete the old analyses, or dismiss the
  stale alerts once, and subsequent runs stay consistent.

## 0.4.0

### Changed

- **The project is now Valca.** The package, module and primary command are
  `valca`. The package was previously published as `vigilsec`.

Nothing from the previous name was removed. All of the following still work and
are expected to keep working:

| Previous | Current | Status |
|---|---|---|
| `vigil` command | `valca` | Both installed; `vigil` retained until at least 1.0 |
| `# vigil: ignore` | `# valca: ignore` | Both honoured permanently |
| `.vigilrc` | `.valcarc` | Both read; `.valcarc` takes precedence |
| `VIGIL_NO_TELEMETRY` | `VALCA_NO_TELEMETRY` | Both honoured |
| `~/.vigil/events.jsonl` | `~/.valca/events.jsonl` | Existing history migrated automatically on first run |

Rule IDs keep the `VGL-` prefix. They appear in user configuration, SARIF output
and published references, so renaming them would break suppressions and orphan
citations for no benefit.

### Fixed

- **The hook could silently stop scanning.** It accepted any executable file as
  the scanner. An entry-point script left behind by an earlier install remains
  executable but fails to import, so the hook exited non-zero and the write was
  allowed through. Each candidate must now prove it runs, the current command is
  searched first, and when nothing runnable is found the hook reports that on
  stderr rather than exiting quietly.
- The published hook gained the path-boundary check, file size limit and scan
  timeout that previously existed only in development.
- Running the project's own test suite no longer writes events into the
  developer's telemetry store.

## 0.3.2

### Fixed

- **Corrected the published rule count from 36 to 102.** The listings understated
  the engine by 66 rules across 17 undocumented categories. The rule catalogue is
  now generated from the rule registry and asserted against it, so it cannot drift.
- Documented `valca log` and `valca stats`, which shipped undocumented.
- Documented the three rules that make outbound network requests
  (`api.osv.dev`, `pypi.org`, `registry.npmjs.org`) and how to disable them.

## 0.3.1

### Fixed

- The demo image on the package page used a relative path and did not render.

## 0.3.0

### Changed

- First release under the name `valca`.

### Fixed

- The telemetry event log is now created with owner-only permissions (`0600`).
  It was previously created with the default umask.
