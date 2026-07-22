# Unified Binary Design

## Goal

Replace the two public executables with a single `powermap` executable while
allowing existing server and client installations to upgrade in place.

## Runtime Model

`powermap` loads one configuration containing optional `[expose]` and
`[access]` sections. `expose` is the former server capability and `access` is
the former client capability. A process may run either role or both. Both
roles receive the same cancellation token; an exit signal cancels both and a
role failure stops the other role before the process returns the error.

The A-to-B iroh protocol, credential format, identity key format, mapping
format, and allowlist semantics remain unchanged. In particular, an empty
forward allowlist remains allow-all, while an empty reverse allowlist remains
deny-all.

## Automatic Migration

The default configuration path is `powermap.toml` in the existing PowerMap
configuration directory. On startup:

1. If the new configuration exists, parse and validate it.
2. Otherwise, look for `powermap-server.toml` and `powermap-client.toml` in
   the same directory.
3. Parse every old file that exists, convert `BConfig` to `[expose]` and
   `AConfig` to `[access]`, combine them, and validate the combined config.
4. Atomically write `powermap.toml`.
5. Delete every legacy configuration file that was successfully incorporated.

No legacy file is deleted until all input parsing, conversion, validation, and
the atomic new-config write have completed. If any step fails, the new
configuration is not considered migrated and all legacy files remain.

For `--config PATH`, a new-format configuration at `PATH` is used directly.
If `PATH` contains one old top-level format, PowerMap converts it, writes
`powermap.toml` next to `PATH`, and deletes `PATH` only after the new file is
durably written. File-name inference selects server for names containing
`server`, client for names containing `client`; other old-format files require
an explicit `powermap expose --config PATH` or `powermap access --config PATH`.

## Command Line and Distribution

The only binary target is `powermap`. Its default mode loads roles from the
configuration. `powermap expose` and `powermap access` are compatibility
selectors for migrating an explicitly supplied legacy file and for starting a
single configured role. The old `powermap-server` and `powermap-client`
targets, release assets, installers, container commands, deployment templates,
and documentation are removed.

## Verification

Tests cover new-format round trips, migration of each legacy configuration,
combined migration, explicit-path migration, and failure atomicity. Existing
role tests continue to validate protocol interoperability and tunnel behavior.
The release workflow validates the one executable in every archive.
