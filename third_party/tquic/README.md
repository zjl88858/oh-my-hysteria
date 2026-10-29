# TQUIC COPA reference and license

Reference: `Tencent/tquic`, commit `d648bbe8cdd34d559cb542f1c83284432de67c0b`,
`src/congestion_control/copa.rs` (last COPA source change as checked 2026-10-29).

https://github.com/Tencent/tquic/blob/d648bbe8cdd34d559cb542f1c83284432de67c0b/src/congestion_control/copa.rs

`LICENSE` is the complete, unmodified upstream license, including its dependency
notices; including those notices does not mean those Rust dependencies are built
or vendored here. The pinned upstream root has no separate NOTICE file.

Only the COPA policy in `core/internal/congestion/copa/sender.go` is adapted.
It retains Apache-2.0 attribution. The Go QUIC adapter, bounded filters/pacer,
tests and original changes are MIT-0. Changes and deliberate differences from
both TQUIC and the NSDI 2018 paper are documented in `docs/copa.md`.
There is no Rust build dependency. This is not an upstream-endorsed release.
