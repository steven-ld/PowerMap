# Use Peer-Specific Endpoints

Each access peer owns its own Iroh Endpoint rather than sharing one endpoint. Iroh binds relay
selection and forced-relay transport policy to an Endpoint, so this preserves the required
per-peer isolation when a relay or credential changes; endpoints are created only for peers with
enabled mappings to limit the resource cost.
