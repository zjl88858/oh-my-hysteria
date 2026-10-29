# Geodesic references and applicable licenses

Pinned references checked 2026-10-29:

- `liulilittle/kcc` at `c8bead4638c9257c98760c386a0a5cf4fe2e3d20`,
  `tcp_kcc.c`: https://github.com/liulilittle/kcc/tree/c8bead4638c9257c98760c386a0a5cf4fe2e3d20
- `liulilittle/ucp` at `927cb83bb509f293a44bd26be52edd34dae09863`,
  `cpp/src/ucp_cc.cpp`, constants and C# cross-reference:
  https://github.com/liulilittle/ucp/tree/927cb83bb509f293a44bd26be52edd34dae09863

`LICENSE-kcc` and `LICENSE-ucp` are complete, unmodified upstream license files.
For adapted KCC policy we elect the **BSD two-clause option** expressly offered
by its Dual BSD/GPL license; retaining the complete license does not elect GPL.
UCP-adapted policy remains MIT. Copyright and prominent adaptation notices are
retained in the mixed-origin Go estimator/model files. Original Go transport,
sampling, pacing, diagnostics and tests are MIT-0. The sampler/pacer are local
copies of our independently written BBRv3 infrastructure, not the legacy BBR
sampler, and the existing BBRv3 package is not modified.

No Linux/Google BBR C file, kernel headers, UCP FEC/transport, cross-connection KF,
or upstream test program is compiled, loaded or executed. This is an opt-in QUIC
adaptation, not the original kernel module or an upstream-endorsed distribution.
Differences and unverified claims are documented in `docs/geodesic.md`.
