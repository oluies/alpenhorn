# Neverlur

> Norwegian / Sami birch-bark shepherd's horn — the Nordic call across the
> mountains.

Neverlur is a friend-discovery service for metadata-private messaging: a
post-quantum fork of [Alpenhorn](https://github.com/vuvuzela/alpenhorn). It is
the companion piece to [gjallarhorn](https://github.com/oluies/gjallarhorn)
(post-quantum fork of [Vuvuzela](https://github.com/vuvuzela/vuvuzela)) — once
two users have bootstrapped a shared secret through Neverlur, they can hold
conversations through Gjallarhorn without ever revealing who they are talking
to, even to a powerful nation-state adversary with future quantum capability.

This fork tracks the upstream Alpenhorn design (see the OSDI 2016
[paper](https://davidlazar.org/papers/alpenhorn.pdf) for the threat model and
the friend-discovery primitive) and migrates the classical primitives toward
**hybrid X25519 + ML-KEM-768** for key agreement and **hybrid Ed25519 +
ML-DSA-65** for signed configuration chains and friend-request handshakes. The
migration plan is tracked alongside the gjallarhorn migration plan; see the
companion fork for the cross-system roadmap.

In short, Neverlur works well for bootstrapping conversations in Gjallarhorn.
Users can start chatting without having to exchange keys in person or over
some less secure channel.

## Lineage

Neverlur is a fork of `github.com/vuvuzela/alpenhorn`, originally written by
**David Lazar** with contributions from collaborators at MIT CSAIL. All
upstream code retains its original copyright notices and the AGPL-3.0
license. See [NOTICE](NOTICE) for the complete lineage and attribution.

## Acknowledgements

Upstream Alpenhorn is the work of David Lazar and collaborators at MIT CSAIL.
This fork exists to evolve the friend-discovery layer with post-quantum
primitives while preserving the original design, threat model, and license.

## See also

- [gjallarhorn](https://github.com/oluies/gjallarhorn) — paired post-quantum
  fork of Vuvuzela (mixnet conversations)
- [Alpenhorn](https://github.com/vuvuzela/alpenhorn) — upstream
- [Vuvuzela](https://github.com/vuvuzela/vuvuzela) — upstream conversation
  mixnet
