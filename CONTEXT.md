# PowerMap

PowerMap provides authenticated, point-to-point access from a local machine to services in a
remote private network. It uses iroh to establish a direct encrypted path where possible.

## Connectivity

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
A separately operated relay instance supplied alongside a PowerMap installation when its
networks require fallback connectivity. It is not a public relay service.
_Avoid_: shared PowerMap relay, public relay

**Relay settings**:
The root `powermap.toml` setting shared by both capabilities. It contains an ordered set of
customer relay HTTPS URLs and an optional relay bearer token; an empty URL set means iroh's
default relay map. The bearer token is sensitive and is only copied into a node credential when
the operator explicitly opts in.
_Avoid_: access token, relay server configuration
