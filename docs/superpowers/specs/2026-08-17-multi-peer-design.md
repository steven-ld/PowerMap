# Multi-Peer Access Design

## Goal

PowerMap v0.9.0 has one access-side credential and one shared Iroh connection. This design adds
multiple named peers so one access node can map services from several remote private networks
without a mapping silently using the wrong remote endpoint. Each peer has independent relay
settings and connection state.

The design also handles accidental self-connections and gives an operator an explicit warning
before accepting a target that may create a forwarding loop.

## Terms

- **Peer**: a named access-side connection target. It has an immutable ID, credential, published
  targets, relay settings, and runtime connection state.
- **Peer name**: a required, operator-facing, unique name. It is not the mapping key.
- **Mapping ownership**: the immutable peer ID stored by every port and domain mapping.
- **Connection cycle**: a forwarding path that returns traffic to the same PowerMap listener or
  node and can recursively forward it.

These terms are also recorded in `CONTEXT.md`.

## Chosen Architecture

Each peer owns a `PeerLink` containing all state that cannot safely be shared:

- an Iroh `Endpoint` built from that peer's relay configuration;
- its cached QUIC connection and reconnect watchdog;
- relay fallback state, current transport path, connection timing, and per-peer diagnostics.

An access-side `PeerManager` indexes `PeerLink` instances by immutable peer ID. A port mapping
or domain mapping resolves its owning link through that manager before opening a tunnel stream.
No mapping holds a fallback or global peer reference.

This is intentionally not a shared-Endpoint design. An Iroh relay map and the forced-relay
transport setting belong to an Endpoint. Changing either on a shared Endpoint would change the
route for unrelated peers. A child-process-per-peer design would isolate that state too, but is
unnecessarily expensive and would complicate lifecycle, recovery, and diagnostics.

### Connection Lifecycle

Peers with no enabled port or domain mapping are persisted but disconnected. Adding, enabling,
or preflighting a mapping creates or uses that peer's link. An enabled mapping keeps its peer
warm through the existing watchdog and bounded exponential backoff.

Changing a peer's credential or relay settings affects only that peer. A forced-relay change
creates a replacement Endpoint for the selected peer; new streams use it while existing streams
finish on the old connection. Other peers are not reconnected or interrupted.

The local expose capability remains a single endpoint. Its relay settings are separate from
access peers. The legacy root `[relay]` configuration remains the expose-endpoint setting for
configuration compatibility; access peers never read it after migration.

## Persistent Model and Migration

`AConfig` gains a peer collection and moves its current connection data into each peer:

```toml
[access]
web_bind = "127.0.0.1:8088"

[[access.peers]]
id = "peer_01J..."
name = "Office NAS"
node_id = "..."
token = "..."

[[access.peers.relay.relays]]
url = "https://relay.example.com"
auth_token = "..."

[[access.mappings]]
local = "127.0.0.1:6379"
host = "10.0.0.12"
port = 6379
peer_id = "peer_01J..."
```

`PeerConfig` contains:

- opaque immutable `id` generated on peer creation;
- `name`, trimmed, nonempty, no more than 60 characters, and unique within the access node;
- `node_id`, `token`, `published_targets`, and `relay`;
- no shared mutable connection state.

`Mapping` and `DomainMapping` gain a required `peer_id`. Existing identity fields on `AConfig`
(`node_id`, `token`, and `published_targets`) remain read-compatible only for v0.9.0 migration;
new writes use `access.peers` exclusively.

On loading a v0.9.0 access configuration with a credential or a mapping, PowerMap creates one
peer named `默认对端`, copies the old credential, published targets, and root relay settings into
it, and assigns its ID to every existing port and domain mapping. If the same file has an expose
configuration, the root relay settings continue to configure that expose endpoint as before. An
empty v0.9.0 access configuration creates no peer; the first peer must be named by the operator.

The migration is persisted atomically with the next successful configuration save. Import accepts
both the old single-credential payload and the new peer collection. Export and diagnostic data
redact every peer token and every relay token unless the user explicitly requests credentials.

## API Contract

The access API gains peer CRUD endpoints:

- `GET /api/peers`: peer ID, name, configuration presence, mapping count, connection state,
  selected path, and sanitized errors.
- `POST /api/peers`: create a named peer with a credential and optional relay settings.
- `PUT /api/peers/{id}`: edit the selected peer only.
- `DELETE /api/peers/{id}`: reject with `409 Conflict` and the referencing mapping list while
  any port or domain mapping still belongs to that peer.

If an imported credential contains relay settings, those settings apply only to the peer being
created or edited. Existing manual relay settings are replaced only after an explicit operator
choice; no credential operation can change another peer.

Port and domain mapping create, update, preflight, list, import, and health responses include
`peer_id`. List and diagnostic responses also resolve a non-authoritative `peer_name` for display.
Create and update require `peer_id` in the new API contract.

For a narrow v0.9.0 automation compatibility path, a request that omits `peer_id` is accepted
only when exactly one migrated default peer exists. Once there are multiple peers, the API returns
a validation error and never guesses the destination.

Mapping preflight returns a structured loop-risk result. If the result needs acknowledgement,
create or update must include `acknowledge_loop_risk: true`; otherwise it is rejected. This check
is performed again during save, so a direct API caller cannot bypass the user-interface warning.

## Management UI

The existing Connection page becomes a Peers page:

- the peer list shows the required name, connection status, direct-or-relay path, active relay,
  enabled mapping count, and actions to edit or delete;
- the create and edit form requires a unique name before credentials can be saved;
- relay controls are rendered inside each peer editor, never as a global access setting;
- credential import affects the peer currently being edited and prompts before replacing its
  manual relay configuration.

The port-mapping table receives a Peer column. Its create and edit form has a required peer-name
selector that submits the selected immutable peer ID. The domain-mapping flow uses the same
selector. Mapping rows, events, health checks, and diagnostic reports include the peer name so
operators can distinguish identical private addresses at different sites.

Trying to delete an in-use peer lists the mappings that must be migrated or removed first. The UI
does not offer an automatic rebind action.

## Loop and Network Safety

PowerMap rejects a peer whose endpoint ID is the local persistent expose identity. This prevents a
deterministic self-connection before any mapping is created. It also rejects any directly proven
closed path derived from that identity check.

Some targets are ambiguous. A remote loopback service is often valid, but can point back to a
PowerMap listener on a machine that runs both capabilities. During preflight, the expose-side DNS
resolution identifies loopback results (`127.0.0.0/8` and `::1`) and returns a loop-risk warning.
The mapping may proceed only after explicit acknowledgement, which is recorded in the request
that saves it.

Generic TCP forwarding cannot reliably identify an arbitrary loop that passes through another
machine's ordinary listener: the original tunnel metadata does not survive after a normal TCP
accept and reconnect. The product must not claim to detect every such topology. Instead it blocks
provable self-connections, requires acknowledgement for known-risk targets, shows the peer on
every mapping, and records peer-scoped errors to make an operator-visible cycle diagnosable.

NAT hairpin behavior is not itself a forwarding cycle. Iroh may select a direct path or relay
fallback as network conditions require; this does not trigger a loop rejection.

## Failure Handling and Atomicity

Peer creation, update, import, and relay replacement validate the complete target configuration
before publishing runtime changes. Persistent saves use the existing atomic write path. If a save
fails after a runtime change, PowerMap restores the previous peer state and keeps unrelated peers
untouched.

Invalid or deleted peer references prevent a mapping from starting and leave its saved definition
visible with an actionable error. A peer cannot be deleted while referenced, so normally this state
only arises from a rejected import or a corrupted external edit.

All events and diagnostics include peer name and peer ID where useful, but never tokens or relay
bearer values. Reconnect backoff, endpoint failure, fallback relay activation, and stream counters
are maintained independently per peer.

## Test Strategy

Tests will cover:

- v0.9.0 configuration and backup migration into one default peer, including mappings and relay
  copying;
- validation of peer IDs, mandatory unique names, mapping ownership, and redacted export;
- peer CRUD, delete conflict reporting, and legacy missing-`peer_id` API behavior;
- two peers with independent endpoint/relay state and concurrent active mappings;
- peer renaming without mapping rebinding and explicit mapping migration;
- port and domain mappings selecting the correct peer;
- idle peers not creating persistent connections;
- a peer-only forced-relay or credential update leaving another peer's connection alive;
- deterministic self-peer rejection, loopback risk acknowledgement, and NAT-hairpin non-rejection;
- import rollback and runtime rollback when persistence fails.

Documentation will update the quick-start flow, configuration reference, API examples, screenshots,
release notes, and the domain glossary.
