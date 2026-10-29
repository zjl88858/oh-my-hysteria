# Changelog

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
