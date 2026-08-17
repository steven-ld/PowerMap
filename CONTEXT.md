# PowerMap

PowerMap provides authenticated, point-to-point access from a local machine to services in a
remote private network. It uses iroh to establish a direct encrypted path where possible.

## Connectivity

**Peer**:
A named access-side connection target owning its endpoint credential and relay settings; every
port or domain mapping stores its immutable peer identifier, so it cannot silently use another
remote private network. Its name is required and unique for operator selection, while renaming
does not change mappings; an in-use peer cannot be deleted until its mappings are migrated or
removed.
_Avoid_: connection, remote node, server

**Connection cycle**:
A mapping path that returns traffic to the same PowerMap listener or node and can recursively
forward it; proven self-connections are rejected, while a potentially cyclic target requires an
explicit warning because a peer's loopback service can also be legitimate.
_Avoid_: NAT hairpin, relay fallback

**Expose node**:
The PowerMap capability that accepts authenticated tunnel requests and dials an allowed service
in its local private network.
_Avoid_: server, tunnel server

**Access node**:
The PowerMap capability that maps a service from an expose node onto a local listener.
_Avoid_: client, tunnel client

**Relay**:
An iroh-compatible service that forwards encrypted traffic only while a direct path is
unavailable and helps endpoints establish that direct path.
_Avoid_: proxy, VPN server

**Relay deployment**:
An operator-supplied relay instance for deployments that need a private primary relay set.
It is distinct from the official relay and can be shared explicitly with paired nodes.
_Avoid_: proxy, VPN server

**Official relay**:
The PowerMap-operated public relay that an unconfigured installation uses after direct
connectivity is unavailable. iroh's default relays are its resilience fallback.
_Avoid_: private relay, service endpoint

**Official relay client identifier**:
The embedded relay bearer value carried by released PowerMap clients to identify permitted
official-relay traffic. It is intentionally public and never grants access to a private service.
_Avoid_: secret token, access credential

**Relay settings**:
The endpoint-level choice of relay entries and forced-relay behavior; each peer and the expose
node own independent settings, so changing one peer never changes another peer's route. A private
relay override does not automatically add iroh fallback relays, and its values are copied into a
node credential only when the operator explicitly opts in.
_Avoid_: global connection setting, access token, relay server configuration

**Relay entry**:
One configured private relay HTTPS address and its own optional bearer token. Entries may share a
token, but do not inherit credentials from one another.
_Avoid_: relay list item, global relay token

**Relay latency probe**:
An explicit management-page check of a relay entry's DNS, TLS, and HTTPS reachability and elapsed
time. It is a control-plane measurement, not an active tunnel's end-to-end latency.
_Avoid_: tunnel speed test, connection quality
