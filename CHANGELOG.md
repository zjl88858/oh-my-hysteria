# Changelog

## v1.2.0 (release preparation)

- Add opt-in Mariner: password-compiled nonlinear byte relations, interleaving,
  direction-separated authenticated envelopes and balanced two-fragment delivery.
  Include bounded authenticated graph caches, configuration and share URIs.
- Use Go1.26.10 for candidate builds, including the Windows runtime preemption fix.
  Make certificate-loader tests use the standard loopback and an ephemeral port.

- Add opt-in Tasman short-block Cauchy erasure containers, bounded carrier queues,
  explicit data/repair reservations, counted tiny exceptions and finite cover.
  Integrate configuration/share URIs and conservative QUIC wire reservations.
  Recovery feedback is budget-limited; this is not exact outer loss/ECN control.

- Add opt-in Servo: password-derived cross-datagram containers, a two-container
  fragmentation reservation, bounded asynchronous admission and fair peer scheduling.
  Integrate client/server configuration, share URIs, failure notification and statistics.
- Observe original QUIC send timestamps, RTT/PTO and loss snapshots for asynchronous
  PacketConns without changing existing congestion-control accounting or defaults.

Application version: v1.2.0. See [release notes](docs/release-v1.2.0.md),
[Servo](docs/servo.md), [Tasman](docs/tasman.md) and [Mariner](docs/mariner.md).
Tag and Release are not yet published.

## v1.1.0

- Add Carakan target-spectrum shaping with a configurable 1.00..7.50 bits/byte
  target, compact 52-byte authenticated framing, cyclic interleaving, and bounded
  Cauchy GF(256) erasure repair. Handshake and data use the same fragmentation path.
  Only wire v3 is supported; update both endpoints together from development builds.
- Add Trident: a password-compiled 64-instruction bytecode dialect with Byte-Split
  Packing and independently authenticated fragments.
- Add Presto: password-derived Markov packet lengths, prelude, fragmentation and
  burst pacing, with bounded authenticated framing and reassembly.
- Reorganize the three protocol guides around configuration, design, overhead and
  validation. Consolidate deployment/security guidance and keep development records
  separate from the current protocol documentation.
- Align application, build tooling, lockfile and container examples on v1.1.0.

Protocol details and deployment guidance: [obfuscation guide](docs/obfuscation.md).
Release preparation: [v1.1.0 notes](docs/release-v1.1.0.md).

## v1.0.0

- Add opt-in Blink L4 UDP framing: direction-separated XChaCha20-Poly1305,
  bounded client prelude, session-varied padding and optional fragmentation.
- Bound verification CPU, authenticated session admission and reassembly
  resources; keep QUIC at 1200 bytes on framed paths without changing other
  transports. Document MTU/overhead/replay and unproven DPI-resistance limits.

- Add opt-in experimental Geodesic (KCC/UCP-derived) with round-based G1/G2/G3,
  bounded ProbeBW, byte-correct sampling/aggregation and QUIC lifecycle hooks.
- Preserve KCC's selected BSD license option and UCP's MIT notices; explicitly
  document estimator ambiguities, short-path lock and non-equivalence to UCP.

- Add opt-in experimental COPA based on the pinned TQUIC reference, with bounded
  delay filters, velocity/pacing, rich QUIC lifecycle hooks, loss guard and CE.
- Preserve TQUIC Apache-2.0 attribution and ship its license with binaries/images;
  document differences from the paper, including incomplete TCP competition mode.

- Add independent BBRv3 `conservative` / `standard` / `aggressive` probing profiles;
  preserve standard defaults, loss / CE handling, lifecycle bounds and ProbeRTT.
- Add profile lifecycle / gain / safety tests and three-profile Gecko integration;
  extend isolated stress scenarios and add metered-traffic accounting test helpers.

- Add independent experimental `congestion.type: bbr3`, targeting draft-ietf-ccwg-bbr-06,
  with bounded delivery sampling, path models, Startup / Drain / ProbeBW / ProbeRTT,
  pacing, CE response, conservative spurious-loss undo, and optional model snapshots.
- Version the pinned local `third_party/quic-go` transport with opt-in rich congestion
  events, packet retirement, application-limited detection and advanced-controller path reset.
- Add controller / transport / Gecko integration regression tests, bounded fuzz and Linux race CI;
  keep legacy BBR as the default and unchanged Brutal bandwidth-negotiation priority.

- Add `congestion.type: cubic` on both client and server.
- Add opt-in `congestion.slowStart: hystart++` (RFC 9406) for CUBIC and Reno,
  preserving `legacy` slow start as the default fallback.

- Initialize oh-my-hysteria from Hysteria 2 master at
  `fb25dc852ebbc70658e67889f411887a82b7c281`.
- Rename the CLI, build artifacts, container entrypoint and configuration paths.
- Use a fork-owned version file instead of upstream release tags.
- Archive the upstream MIT license as a third-party notice.
- Remove upstream publishing, deployment, installer and update-service bindings.
- License fork-specific additions and modifications under MIT-0; retain upstream MIT notices.
- Migrate Go modules and build metadata to `github.com/zjl88858/oh-my-hysteria`.
- Credit GPT-6.1 Sol (OpenAI) as an AI Co-Developer in the README.

Upstream history: https://hysteria.network/docs/Changelog/
