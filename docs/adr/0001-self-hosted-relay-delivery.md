# Ship the Iroh relay as a separate PowerMap delivery artifact

PowerMap keeps its single application binary and packages the upstream `iroh-relay` binary,
Docker image, deployment template, and checksum independently. A relay has a different public
network, TLS, bandwidth, and upgrade boundary from a private-network node; embedding it in the
application image would force every deployment to expose that operational surface. The artifact
is pinned to the iroh version resolved by the application and must be compatibility-tested when
that dependency changes.
