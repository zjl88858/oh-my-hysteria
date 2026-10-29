# Third-party licenses

## Hysteria 2 — MIT License

Source: https://github.com/HyNetworks/hysteria

The following is the original upstream license, preserved without changing its terms.

Copyright 2023 Toby

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## quic-go CUBIC / legacy HyStart / pacing — MIT License

Source: https://github.com/apernet/quic-go

Version: `v0.63.1-0.20261004180939-a10df75c260c`.
The CUBIC sender, growth function, legacy slow start and pacer under
`core/internal/congestion/cubic/` are adapted from quic-go's internal congestion
implementation. HyStart++ is a new implementation based on RFC 9406, not the
upstream legacy HyStart. Fork-specific original changes use MIT-0; the following
license continues to apply to inherited quic-go portions.

MIT License

Copyright (c) 2016 the quic-go authors & Google, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Other third-party code

### Blink design reference (no imported AmneziaWG code)

Blink's new Go framing, budgets and tests are original MIT-0 code. Its design
research cites `amnezia-vpn/amneziawg-go` at
`b5928efb6ca19f0153958460c3d141f04abc5c2e`; no AmneziaWG/WireGuard source,
packet structs, protocol implementation or dependency is copied or compiled.
Existing standard-library and `golang.org/x/crypto` license obligations remain
unchanged. See `docs/blink.md` for the distinct wire format and limitations.

### TQUIC COPA — Apache License 2.0

The COPA equations, startup and velocity policy in
`core/internal/congestion/copa/sender.go` are adapted from Tencent/TQUIC
`src/congestion_control/copa.rs` at
`d648bbe8cdd34d559cb542f1c83284432de67c0b`.

Copyright (c) 2023 The TQUIC Authors.
Copyright (C) 2023 THL A29 Limited, a Tencent company. All rights reserved.

The complete original license is preserved in `third_party/tquic/LICENSE` and
distributed alongside binaries as `LICENSE-tquic.txt`. Modified files carry
prominent change notices. Inherited portions remain Apache-2.0; original Go
transport/filter/pacing additions and tests use MIT-0. No Rust dependencies are
compiled. See `third_party/tquic/README.md` and `docs/copa.md` for provenance.

### Geodesic — KCC BSD option / UCP MIT

The policy under `core/internal/congestion/geodesic/estimator.go` and `model.go`
is adapted from `liulilittle/kcc` at `c8bead4638c9257c98760c386a0a5cf4fe2e3d20`
and `liulilittle/ucp` at `927cb83bb509f293a44bd26be52edd34dae09863`.

Copyright (c) 2017 ~ 2035 PPP PRIVATE NETWORK(TM) X
Copyright (c) 2026 PPP PRIVATE NETWORK™ X

KCC's root license explicitly offers BSD or GPL; this project elects its
two-clause BSD option for the adapted policy. UCP portions retain MIT terms.
The complete unmodified license files are preserved in `third_party/geodesic/`
and shipped with binaries as `LICENSE-geodesic-kcc.txt` and
`LICENSE-geodesic-ucp.txt`. Original Go changes and tests are MIT-0.
No kernel module or Linux/Google BBR C source is imported or compiled.
See `third_party/geodesic/README.md` and `docs/geodesic.md` for modifications.

### Local QUIC transport and independent BBRv3

The complete pinned apernet/quic-go module is included under
`third_party/quic-go/`, including its original `LICENSE` and file-level notices.
The MIT text above applies to this local transport copy as well as the adapted
CUBIC files. `third_party/quic-go/OHMY-FORK.md` documents the opt-in advanced
congestion hooks, the Windows test signature fix, and AI-assisted changes.
The independently written BBRv3 controller, pacer, sampler and new tests use
MIT-0; no Linux, QUICHE or TQUIC controller source was imported or translated.

Dependencies retain their own licenses. See the `go.mod` and `go.sum` files in
`app/`, `core/`, `extras/`, and `third_party/quic-go/` for dependency versions, and the corresponding
dependency source distributions for their copyright and license notices.
Existing file-level notices also remain applicable. This file does not replace
those licenses or claim to be a complete dependency license inventory.
