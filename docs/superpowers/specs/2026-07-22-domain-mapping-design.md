# Domain Mapping Design

## Goal

Let an access node use an HTTPS domain such as
`https://ai-router.dl-aiot.com` without changing application URLs. PowerMap
will direct the domain to a local listener and tunnel the original TLS stream
to the same domain resolved from the expose network.

## User Experience

The console gains a top-level `Domain mappings` item in the left navigation.
Creating a mapping requires only a domain name. PowerMap defaults to remote
port `443`; an advanced field may override it for nonstandard HTTPS services.

Before enabling a mapping, the console verifies that the expose node can
resolve and dial the domain on the configured port, that its policy permits the
resolved destination, and that the local loopback listener is available. The
mapping list shows the domain, remote resolved address, port, status, last
probe, and enable/disable controls.

## Data Flow

1. The access node asks the expose node to resolve and dial the configured
   domain. Resolution occurs on the expose network so split DNS works.
2. On approval, a local privileged helper binds `127.0.0.1:443` and adds the
   exact domain to the system hosts file as a PowerMap-managed entry.
3. The access process receives accepted local TCP streams and opens ordinary
   TCP tunnels to the domain and port through expose.
4. The TLS stream passes through unchanged. The browser continues to send the
   original hostname as SNI and validates the certificate presented by the
   remote HTTPS endpoint.

The feature does not terminate TLS, inspect HTTP, issue certificates, install a
general-purpose DNS resolver, or affect unrelated domains.

## Privilege Boundary

PowerMap's main process remains unprivileged. Enabling a domain mapping invokes
a narrowly scoped, platform-specific helper through the system administrator
authorization mechanism. The helper may only:

- bind the requested loopback port;
- create, update, and remove hosts entries marked as PowerMap-managed; and
- return the bound listener to the unprivileged runtime through a local IPC
  channel.

It must reject wildcard domains, non-loopback bind addresses, and hosts entries
without its ownership marker. Disabling, deleting, or recovering a mapping only
removes the exact entry written by PowerMap. A visible `Restore hosts` action
removes all PowerMap-managed entries after explicit confirmation.

## Failure Handling

- If privilege is denied, the mapping remains disabled and no hosts entry is
  changed.
- If port 443 is occupied, the mapping remains disabled and identifies the
  blocked address.
- If DNS resolution, policy validation, or remote dialing fails, hosts are not
  changed.
- If the helper or access runtime exits unexpectedly, the next startup detects
  stale marked entries and offers safe cleanup before enabling the mapping.

## Compatibility And Verification

Existing mapping configuration and APIs remain unchanged. Domain mappings use a
separate configuration collection and API surface. Tests cover domain syntax,
hosts ownership and rollback, privilege-denied behavior, listener conflicts,
split-DNS resolution through expose, transparent TLS forwarding, and restart
recovery. Manual acceptance tests cover macOS, Windows, and Linux administrator
authorization flows.
