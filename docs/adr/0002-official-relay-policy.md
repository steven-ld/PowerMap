# Operate an official relay with iroh resilience fallback

PowerMap v0.9 ships a public official relay URL and client identifier so an unconfigured
installation can use it whenever direct P2P connectivity is unavailable. The identifier is an
intentionally public traffic label, not a private-service credential; the application starts with
the official relay only and dynamically adds iroh's default relay map after it cannot register or
loses its registration, preserving both operator control and an independent continuity path.

Private relay overrides are represented as independent relay entries, each with its own optional
bearer token. They are an explicit topology override, so they do not implicitly add iroh relays.
This prevents credentials for one relay from being sent to another relay and keeps explicit relay
sharing faithful to the configured topology. The control plane can probe each configured relay's
`/ping` endpoint for DNS, TLS, and HTTP latency without opening a tunnel or sending its bearer
token; this does not validate relay admission because admission happens only on a relay connection.
