# Local transport adaptation

Base: github.com/apernet/quic-go
`v0.65.1-0.20261109005002-2895f039137a` (`2895f039137a405a34cffbcb27510ad31717d89a`),
the v0.65.0-based revision used by Hysteria `app/v2.14.0` (`c2b181e0`).
OMHY v1.2.1 merges the delta from `a10df75c260c` into the existing local fork.
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

v0.65 uses a shared sent-packet history: flight and key/PTO removal notifications
use the stored packet's encryption level. Spurious ACKs still reach advanced
controllers after loss processing, including ACKs for packets no longer in flight.
The synchronous initial-MTU check uses the same timestamp / reservation writer
as queued data and returns write errors to upstream's MTU fallback logic.

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
