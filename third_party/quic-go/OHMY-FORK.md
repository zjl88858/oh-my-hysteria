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

Servo development adds an opt-in asynchronous PacketConn observation path:
the original SentPacket timestamp is retained through the send queue and can be
passed to WriteToWithQUICSendTime on a basic (non-OOB/GSO/ECN) PacketConn. RTT/PTO
and loss snapshots can also be observed. These hooks do not move SentPacket,
rewrite congestion accounting, or change legacy socket behavior. Their tests
cover exact timestamp propagation and unchanged queue fallback behavior.

Tasman development adds an explicit, opt-in conservative wire reservation:
2*inner QUIC packet bytes + 62 are charged to the selected controller's flight,
ACK/loss accounting and pacing. An admitted datagram receives a bounded permit;
deadlines, cover and tiny exceptions cannot mint permits. This is a ceiling, not
exact outer ACK attribution. Authenticated, budget-limited FEC recovery reports
add a separate RTT-sized pacing guard (PTO probes retain their exception).
Original inner send timestamps and actual carrier completion times remain
distinct. ECN/GSO/OOB remain disabled for this framing; legacy paths are unchanged.

These modifications were AI-assisted using OpenCode / GPT-6.1 Sol (OpenAI).
Fork-specific original additions are MIT-0; adapted upstream files retain MIT.
