# Local transport adaptation

Base: github.com/apernet/quic-go
`v0.63.1-0.20261004180939-a10df75c260c` (a10df75c260c).
Original MIT license is retained in LICENSE. This dependency copy is versioned
with oh-my-hysteria; do not edit the Go module cache. The three application
modules replace this module with this directory, including outside go.work.

Fork changes add opt-in rich congestion events: packet space and MTU-probe
metadata, authoritative application flight accounting, explicit packet removal,
spurious ACK / loss-history retirement, application-idle notifications, and path
reset. Legacy controllers keep their original callback path. The richer API is
local and not claimed to be available upstream.

The two Windows newConn tests were updated to pass the existing third argument
(disableGSO); the pinned upstream tests otherwise did not compile on Windows.
Rich event / retirement / idle / migration regression tests are included.

These modifications were AI-assisted using OpenCode / GPT-6.1 Sol (OpenAI).
Fork-specific original additions are MIT-0; adapted upstream files retain MIT.
