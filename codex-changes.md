# CloudCastX — Testing Branch Handoff

**Branch:** `testing`
**Repo:** https://github.com/shamair28/CloudCastX
**Last updated:** 2026-07-08 (second session)
**Status:** Mirroring data path rewritten from UDP/RTP to the correct TCP header-framed protocol; timing negotiation defaults corrected to NTP (matching our advertised features); RTSP body-read truncation fixed. Build passes. Needs on-device verification.

---

## 2026-07-08 (sixth session) — Fresh receiver identity (suspected stale sender cache)

The txtAirPlay qualifier fix was confirmed working in the wire log, but iOS
still closed at exactly the same point (after SETUP #1 + one NTP exchange).
Three different SETUP #1 response variants have now produced an identical
abort, which points away from response content and toward sender-side state.
Telling detail: the phone NEVER sends POST /pair-setup — with our feature bits
a first-contact client should pair-setup before pair-verify. It is skipping it
because it has CACHED state for this receiver identity, which has been constant
(persisted in LocalSettings) across weeks of incompatible protocol iterations —
including an era when pair-setup was a completely different HAP/TLV8
implementation.

Changes:
- `AirPlayConfig.IdentityVersion` (now 2): bumping it regenerates the full
  receiver identity — MAC/deviceID, Ed25519 pair, pairing ID — and the device
  name is now derived from the MAC (`CloudCast-XXXXXX`) so the phone sees a
  brand-new device in the picker.
- NTP transmit timestamps now carry full sub-second precision (was
  millisecond-truncated via `DateTimeOffset.Millisecond`).

Test notes: reboot the iPhone (or toggle Wi-Fi) before testing to flush its
AirPlay discovery cache. Expect the picker to show `CloudCast-XXXXXX`. Watch
whether the phone now sends POST /pair-setup before pair-verify — if it does,
the stale-cache theory is confirmed.

If the abort STILL reproduces identically with a fresh identity, next step is
empirical: build/run UxPlay on this PC (MSYS2) and diff its wire exchange with
the same phone against ours, request by request.

---

## 2026-07-08 (fifth session) — /info qualifier must return the raw TXT record

eventPort=0 + Audio-Jack-Status did not change the abort point: iOS still
closed right after the SETUP #1 response. With SETUP #1 now byte-equivalent to
UxPlay's, the remaining divergence was found in `/info`: iOS's FIRST GET /info
carries a plist body `{qualifier: ["txtAirPlay"]}` asking for the receiver's
raw mDNS TXT record over unicast. UxPlay's `raop_handler_info` responds to that
request with ONLY `{txtAirPlay: <raw TXT bytes>}` and returns the full device
dict only for the body-less GET /info. We were sending the full device dict
(with no txtAirPlay key) to the qualifier request.

Changes:
- `MdnsAdvertiser` now owns the TXT key/value pairs as a single source of truth
  (`GetAirPlayTxtPairs` / `GetRaopTxtPairs`) used by both the mDNS registration
  and the new `BuildTxtRecordBytes` DNS-wire-format encoder.
- `HandleInfo` distinguishes the two request forms: body with qualifier →
  respond with only the requested TXT record(s); no body → full device dict.

---

## 2026-07-08 (fourth session) — eventPort must be 0 for NTP mirroring

Retest with firewall rules in place failed identically: iOS closed the RTSP
connection immediately after the SETUP #1 response and never attempted an event
connection — so the firewall was NOT the blocker. Checked the actual UxPlay
source (`lib/raop_handlers.h`, actively maintained against iOS 17/18): **the
event channel is not used at all in NTP mirror/audio mode**. UxPlay returns
`eventPort=0`, binds no event listener, and iOS proceeds straight to SETUP #2.
The "event channel must be open or RTSP won't continue" rule from the
emanuelecozzi docs applies to the modern PTP/HAP flow only. Our real, unused
event port (7001) was a deviation from every working receiver in the exact
response iOS aborted on.

Changes (aligning byte-for-byte with UxPlay's behavior):
- SETUP #1 (NTP): return `eventPort=0`, bind no event listener. The dedicated
  event listener + firewall warning now exist only in the PTP branch.
- Every RTSP response except RECORD now includes
  `Audio-Jack-Status: connected; type=digital` (UxPlay does this).
- NTP polling now continues every 3 s for the life of the timing socket
  (was: stopped after ~25 s).

Also confirmed from UxPlay source while there: our mirror-stream key derivation
matches theirs — aeskey = SHA-512(fairplay-decrypted-key ‖ ecdh-secret)[0..16],
stream key/IV = SHA-512("AirPlayStreamKey"/"AirPlayStreamIV" + unsigned-connID ‖
aeskey)[0..16] — so the decryption path should be sound once SETUP #2 happens.

---

## 2026-07-08 (third session) — Fixed service ports; firewall is the current blocker

On-device test after the TCP rewrite got much further: pairing, fp-setup, and
SETUP #1 all succeeded and the NTP timing exchange worked (sender replied to our
timing request). iOS then closed the RTSP connection without ever opening its
event connection — the receiver had advertised an ephemeral event port (6535),
and the only firewall rule on the machine allows inbound TCP 7000. Outbound-
initiated traffic (NTP) got through; inbound-initiated (event TCP) was dropped,
and per the spec iOS will not continue past SETUP #1 without the event channel.

Changes:
- All service sockets now bind FIXED ports (falling back to OS-assigned if
  taken): event **7001/TCP**, timing **7002/UDP**, mirror data **7100/TCP**,
  audio data **6000/UDP**, audio control **6001/UDP** (`AirPlayConfig` consts).
  Fixed ports also keep us out of the Xbox-blocked 57344+ ephemeral range.
- SETUP #1 now logs a WARNING if no event connection arrives within 3 s,
  pointing at the firewall.

**Required one-time setup (elevated PowerShell):**
```powershell
New-NetFirewallRule -DisplayName "CloudCast AirPlay TCP" -Direction Inbound -Protocol TCP -LocalPort 5000,7000,7001,7100 -Action Allow
New-NetFirewallRule -DisplayName "CloudCast AirPlay UDP" -Direction Inbound -Protocol UDP -LocalPort 6000,6001,7002 -Action Allow
```

---

## 2026-07-08 (later) — Mirror stream moved to TCP; timing + framing fixes

The previous session fixed SETUP response *shapes* but three deeper bugs remained.
This session's audit against SteeBono/airplayreceiver, RPiPlay, and UxPlay found
and fixed them all (build verified, not yet tested on-device):

### 1. Screen-mirroring data is TCP, not UDP/RTP — `MirroringSession.cs` rewritten
`MirroringSession` bound a **UDP** socket and parsed **RTP (RFC 6184)**. But for
stream type 110 the sender opens a **TCP connection** to `dataPort` and sends
`[128-byte header][payload]` packets (header: payloadSize u32 LE @0, payloadType
u16 LE @4, NTP timestamp u64 LE @8). That is how every working receiver
(SteeBono, RPiPlay, UxPlay) implements it. Consequences of the old design: iOS's
TCP connect to our UDP port was refused → the session aborted right after
SETUP #2 ("Unable to connect"), and no video could ever have rendered.

The rewrite implements:
- TCP `StreamSocketListener` bound at SETUP #2; its port returned as `dataPort`.
- Payload type 0: AES-128-CTR decrypt with a **byte-continuous keystream across
  packets** (the old code reset the counter every packet), then AVCC→Annex B
  conversion (4-byte BE NALU lengths → start codes).
- Payload type 1: unencrypted avcC record; SPS/PPS extracted, converted to
  Annex B, and prepended to the next video frame (marked as key frame).
- PTS derived from the NTP timestamp in the packet header; monotonicity enforced.
- Frame queue bounded at 120 frames (drop-oldest) so a stalled decoder can't
  balloon memory.
- Decryption is configured at SETUP #2 time (KeyMsg from fp-setup, ekey from
  SETUP #1, ECDH secret from pair-verify, streamConnectionID from the stream
  dict) instead of waiting for a `/stream` request that never comes in this flow.

### 2. Absent `timingProtocol` means NTP, not PTP — `AirPlayControlServer.cs`
Our advertised features (`0x1E5A7FFFF7`) do **not** include the PTP bit, so iOS
uses legacy NTP timing and typically omits `timingProtocol` from SETUP #1. The
code defaulted to PTP, returned `timingPort=0`, and never drove NTP — the sender
stalled waiting for timing sync. Default is now NTP; PTP is honoured only when
explicitly requested.

### 3. RTSP request bodies could be silently truncated — `AirPlayControlServer.cs`
`ReadRequestAsync` did a single `LoadAsync(contentLength)` with
`InputStreamOptions.Partial`, which may return fewer bytes than requested when a
body spans TCP segments; `ReadBytes` then threw and killed the connection.
Intermittent "Unable to connect" depending on packet boundaries. Now loops until
the full body is buffered.

### Smaller fixes
- `streamConnectionID` is now also read from *inside* the stream dict in
  SETUP #2 (it is not top-level there), and formatted as an **unsigned** decimal
  string for `AirPlayStreamKey`/`AirPlayStreamIV` derivation (our plist decoder
  returns signed longs; RPiPlay/UxPlay format with `%llu`).
- `TEARDOWN` now has an explicit handler. Its plist body (which contains a
  `streams` key) previously fell through to the default handler and was
  misparsed as a SETUP #2, re-binding sockets mid-teardown.
- SETUP #2 response for type 110 now contains only `{type, dataPort}` (matching
  UxPlay); the bogus UDP "video control" socket is gone. Audio streams still get
  `{type, dataPort, controlPort}`.
- `RECORD` response now includes `Audio-Latency: 0`.
- `StreamingStarted` now fires when the sender actually opens the mirror data
  connection instead of on a 500 ms timer.

### How to verify on-device
Watch the debug log for this sequence: pairing → fp-setup (2 phases) →
SETUP #1 (`eventPort=<ephemeral> timingPort=<udp port>` for NTP) → SETUP #2
(`type=110 dataPort=<tcp port>`) → RECORD → `[Mirroring] Sender connected` →
`[Mirroring] Codec data: SPS/PPS updated` → video frames. If the sender
connects but no frames decode, suspect the AES-CTR key derivation
(`streamConnectionID` signedness) first.

---

## 2026-07-08 — SETUP handshake corrected against the AirPlay 2 spec

The prior notes (below) were written before several rounds of trial-and-error on
`eventPort`/`timingPort`, visible in git history (`4228629`, `eeceb7c`,
`1c4f7cb`, `7af7758`, `3b57064`, …). That churn never converged because the
`SETUP` responses didn't match what iOS actually requires. This session fixed
that by aligning `AirPlayControlServer.HandleSetupPlistAsync` with the
authoritative reference:

> Emanuele Cozzi, *AirPlay 2 Internals — RTSP*: https://emanuelecozzi.net/docs/airplay2/rtsp/

The AirPlay 2 `SETUP` is **two** requests, each with a distinct response shape:

**SETUP #1 — "info and event"** (body has `deviceID`, `ekey`, `eiv`, `timingProtocol`; no `streams`)
- Must return a **dedicated event TCP port**. The spec is explicit: *"The event channel must be open or the RTSP won't continue."* The old code returned the control port `7000`, so iOS opened its event channel straight into the RTSP server — the handshake stalled and the phone showed "Unable to connect."
- Must honour `timingProtocol`. Modern iOS/macOS send `timingProtocol=PTP`, in which case the response is `timingPort=0` plus a `timingPeerInfo` dict; **no NTP timing is used**. The old code always returned `timingPort=7000` and drove NTP, which a PTP sender ignores.

**SETUP #2 — "control and data"** (body has `streams`)
- Response is `streams:[{ type, dataPort, controlPort }]` and nothing else. The old code omitted `controlPort` and wrongly re-sent `eventPort`/`timingPort` (those belong only to SETUP #1).

### Fixes applied (`Services/AirPlayControlServer.cs`)
1. `HandleInitialSetupAsync(plist)` — reads `timingProtocol`; opens a dedicated event TCP listener via `EnsureEventSocketAsync()` and returns **its** port; returns `timingPort=0` + `timingPeerInfo` for PTP, or a real UDP timing port + NTP for legacy NTP senders. The receiver's own IP (`_localAddress`) is captured on the control connection for `timingPeerInfo`.
2. `HandleStreamSetupAsync(plist)` — now returns `{ type, dataPort, controlPort }` per stream and no longer leaks `eventPort`/`timingPort`. A UDP control socket is bound per stream (`_videoControlSocket` / `_audioControlSocket`) via the new `BindEphemeralUdpAsync` helper (a `ref`-free binder, since async methods can't take `ref`).
3. `/info` `statusFlags` is now a **constant** `0x04`. It previously flipped to `0x20004` once a session started; because iOS issues a second `GET /info` mid-handshake, that change signalled "password required" and could abort the connection.

### Prior outstanding issues — status
- **Issue A (2nd SETUP tears down session → COMException):** already resolved in earlier commits — `HandleStreamSetupAsync` only creates a `MirroringSession` when none exists, and `MirroringSession.StartAsync` dispatches `_player.Source` to the UI thread. Verified still correct.
- **Issue B (echo stream `type`):** already resolved — the request `type` is parsed and echoed. Verified.
- **Issue C (`pair-setup` rejects `state=0`):** no longer applicable — pairing was rewritten to SteeBono raw-byte style (`HapPairing.HandlePairSetupAsync` returns the 32-byte Ed25519 pk regardless of body), so there is no TLV8 state guard to trip.

### Remaining known gap
Modern senders negotiate **PTP** (IEEE 1588) for timing. We now *declare* PTP correctly (timingPort=0 + timingPeerInfo), but we do not yet run a PTP clock responder (UDP 319/320). Depending on the sender, screen frames may not begin flowing until a minimal PTP responder exists. That is the next milestone; the RTSP handshake itself should now complete rather than failing at SETUP. (Legacy NTP senders use the NTP path, which is implemented.)

---

## (Historical notes — pre-2026-07-08, retained for context)

**Status at the time:** FairPlay + SETUP negotiation reaching `dataPort` assignment. Second SETUP (audio stream) throws `COMException` — fix identified but not yet pushed.

---

## Project Summary

CloudCastX is a UWP AirPlay 2 screen mirroring receiver targeting Xbox consoles. It advertises itself over mDNS as an AirPlay device, performs HAP (HomeKit Accessory Protocol) transient pairing with iOS, negotiates FairPlay stream encryption, and renders the incoming H.264 RTP stream via `MediaStreamSource` + `MediaPlayerElement`.

The codebase integrates SteeBono's FairPlay/OmgHax decryption tables (MIT licensed) for AES key unwrapping.

---

## Current State of Handshake (as of last test run)

The following log represents the furthest the handshake has progressed:

```
[mDNS] _airplay._tcp: features=0x427FFFF7,0x0E sf=0x4 pk=4a2a4971…  ← correct
[AirPlay] GET /info                                                    ← correct
[AirPlay] POST /fp-setup  → FairPlay Phase 1 (mode 1)                 ← correct
[AirPlay] POST /fp-setup  → FairPlay Phase 2 — key message stored     ← correct
[AirPlay] SETUP rtsp://…  → ekey (72B), eiv (16B), dataPort=52234     ← correct
[AirPlay] POST /fp-setup  → FairPlay Phase 1 (mode 3)  ← second stream (audio)
[AirPlay] POST /fp-setup  → FairPlay Phase 2 — key message stored
[AirPlay] SETUP rtsp://…  ← second SETUP throws COMException          ← FAILING
```

iOS shows **"Unable to connect"** after the second SETUP fails.

---

## Changes Made This Session

### 1. `AirPlayConfig.cs` — Authentication4 bit corrected
**Commits:** [`f7ae005`](https://github.com/shamair28/CloudCastX/commit/f7ae00543f4af5c4a2172bab8cd090f5fad5725a), [`a9b5298`](https://github.com/shamair28/CloudCastX/commit/a9b52985df1e293e0c867be6824cbfe911227847)

Authentication4 is **bit 27** (`0x08000000`) of the features dword, not bit 3. A prior attempt cleared bits 3–4 (`0x18`) which had zero effect on iOS PIN prompting.

| | Value | Authentication4 set? |
|---|---|---|
| Original | `0x0E4A7FFFF7` | ✅ Yes — PIN required |
| Wrong fix | `0x0E4A7FFFEF` | ✅ Yes — PIN still required |
| **Correct fix** | `0x0E427FFFF7` | ❌ No — transient, no PIN |

`FeaturesHex` in the mDNS TXT record updated to match: `"0x427FFFF7,0x0E"`.

---

### 2. `HapPairing.cs` — `pair-setup` TLV8 encoding + state guard
**Commit:** [`3245e32`](https://github.com/shamair28/CloudCastX/commit/3245e325bfb15e6e00bf965af4fb6c25443514a6)

- `pair-setup` response now TLV8-encoded with state tag `0x06 = 0x02` (M2) and public key tag `0x03`. Previously returned raw bytes which iOS rejected silently.
- Guard added: only respond to `state=1` (M1). Any other state returns null → HTTP 470.
- **Remaining:** `state=0` (empty body transient probe from iOS) also needs to be accepted as equivalent to `state=1`. Currently it is rejected with `unexpected state 0` — needs a one-line fix: `if (state != 1 && state != 0)`.

---

### 3. `AirPlayControlServer.cs` — `/info` pk as raw bytes, port separation, SETUP streams array
**Commits:** [`3245e32`](https://github.com/shamair28/CloudCastX/commit/3245e325bfb15e6e00bf965af4fb6c25443514a6), [`bc41ae4`](https://github.com/shamair28/CloudCastX/commit/bc41ae4c5e19dbe4da1a5846363740f969237fb9)

- `/info` now sends `pk` as `byte[]` (binary plist data type `0x4x`) instead of a hex string. iOS compares this against the M2 key — a type mismatch caused silent drop.
- `statusFlags` set to `0x04` (transient pairing supported). `0x00` told iOS the device was already fully paired, contradicting the FairPlay flow.
- `TimingPort = 7001`, `EventPort = 7002`, `VideoPort = 7100` separated from `ControlPort = 7000` to avoid port conflict.
- SETUP response now includes a `streams` array with `type` and `dataPort`.

---

### 4. `MirroringSession.cs` — Early UDP bind, FU-A reassembly
**Commit:** [`a1ac7e9`](https://github.com/shamair28/CloudCastX/commit/a1ac7e9f5ec807bae03076f482de13e63c2a620b)

- `BindUdpAsync()` added: binds the UDP socket at SETUP time (ephemeral port via `BindServiceNameAsync("0")`) so the real OS-assigned port is known before iOS sends video. Previously a hardcoded constant was returned and nothing was listening there.
- FU-A fragment reassembly fixed: `ParseNalus` was discarding all continuation and end fragments of fragmented H.264 NALUs (type 28), corrupting every fragmented NALU. Added `_fuaBuffer` to accumulate all fragments and yield only when the end-bit (`0x40`) is set.

---

### 5. Diagnostic logging added throughout
**Commit:** [`9c2e36f`](https://github.com/shamair28/CloudCastX/commit/9c2e36faec0723a377bfca4ac1fc5083cd0d3cd5)

Structured `Debug.WriteLine` output added to every stage of the handshake: `/info`, `pair-setup`, `pair-verify` (phases 1+2), `fp-setup` (phases 1+2+3), `SETUP`, and `/stream`. All output prefixed with `[HAP]`, `[FairPlay]`, `[Mirroring]`, `[AirPlay]` for easy filtering in the VS Output window.

---

## Outstanding Issues (Next Agent Must Fix)

### 🔴 Issue A — Second SETUP destroys first session → COMException
**File:** `AirPlayControlServer.cs` → `HandleSetupPlistAsync`

iOS sends two SETUP requests per connection:
1. Video stream (FairPlay mode 1) — sets up H.264 RTP
2. Audio/timing stream (FairPlay mode 3) — sets up audio control channel

The current `HandleSetupPlistAsync` calls `_activeSession?.Stop()` unconditionally on every SETUP. The second call tears down the live video session and creates a new `MirroringSession`, which then calls `_player.Source = MediaSource.CreateFrom...` from a background socket thread → **COMException (wrong thread)**.

**Fix required:**
```csharp
// In HandleSetupPlistAsync — do NOT tear down existing session on second SETUP
// Only create a new session if none exists
if (_activeSession == null)
{
    _activeSession = new MirroringSession(_player);
    await _activeSession.BindUdpAsync();
}

// For audio stream SETUP, bind a separate dummy socket for the audio dataPort
// (we don't process audio data yet but iOS needs a live port in the response)
```

Also, `_player.Source = ...` in `MirroringSession.StartAsync` must be dispatched to the UI thread:
```csharp
await _player.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
{
    _player.Source = MediaSource.CreateFromMediaStreamSource(_mss);
});
```

### 🔴 Issue B — SETUP response must echo back stream `type` from request
**File:** `AirPlayControlServer.cs` → `HandleSetupPlistAsync`

The current response hardcodes `type = 110` for all streams. iOS sends the stream `type` in the request body's `streams` array and expects it echoed back unchanged. The response must parse the incoming `streams` array and reflect each stream's `type` alongside the assigned `dataPort`.

### 🟡 Issue C — `pair-setup` rejects `state=0` (empty body probe)
**File:** `HapPairing.cs` → `HandlePairSetupAsync`

iOS sends a zero-length POST to `/pair-setup` as a transient probe. The body decodes to `state=0`. The current guard `if (state != 1)` rejects it. Change to `if (state != 1 && state != 0)` — treat `state=0` as equivalent to M1 and respond with M2.

### 🟡 Issue D — Audio stream data not yet processed
The second SETUP's RTP data (AAC-ELD audio, multiplexed in the video stream) is not yet decoded. For now, binding a dummy UDP socket and returning a valid port is sufficient to unblock iOS from showing "Unable to connect." Audio decoding can be tackled as a follow-on task once video renders.

---

## Key Files

| File | Role |
|---|---|
| `CloudCastX/Services/AirPlayConfig.cs` | Protocol constants, features bitmask, device identity, Ed25519 key generation |
| `CloudCastX/Services/AirPlayControlServer.cs` | HTTP/RTSP request dispatcher, SETUP handler, session lifecycle |
| `CloudCastX/Services/HapPairing.cs` | HAP pair-setup + pair-verify, TLV8 codec, ECDH + Ed25519 crypto |
| `CloudCastX/Services/FairPlaySetup.cs` | FairPlay fp-setup phases 1–3, key message storage |
| `CloudCastX/Services/MirroringSession.cs` | UDP RTP receiver, AES-CTR decryption, H.264 NAL parsing, MediaStreamSource |
| `CloudCastX/Services/MdnsAdvertiser.cs` | mDNS _airplay._tcp + _raop._tcp registration via Windows.Networking.ServiceDiscovery.Dnssd |
| `CloudCastX/Util/BinaryPlist.cs` | Binary plist encoder/decoder (covers dict, array, string, long, byte[], bool) |
| `CloudCastX/Crypto/OmgHax.cs` | SteeBono FairPlay AES key unwrapping (MIT licensed) |

---

## Protocol Flow Reference

```
iOS                          CloudCastX
 |                               |
 |── GET /info ─────────────────>|  features, pk, statusFlags=0x04
 |<─ 200 binary-plist ───────────|
 |                               |
 |── POST /fp-setup (phase 1) ──>|  FairPlay mode 1 (video)
 |<─ 200 phase 1 response ───────|
 |── POST /fp-setup (phase 2) ──>|
 |<─ 200 phase 2 response ───────|  KeyMsg stored
 |                               |
 |── SETUP rtsp://… ────────────>|  ekey, eiv, streams[{type,screenID}]
 |<─ 200 {streams[{type,dataPort}], timingPort, eventPort} ──|
 |                               |
 |── POST /fp-setup (phase 1) ──>|  FairPlay mode 3 (audio)
 |── POST /fp-setup (phase 2) ──>|
 |── SETUP rtsp://… ────────────>|  second stream (audio)
 |<─ 200 {streams[{type,dataPort}]} ─|   ← CURRENTLY FAILING
 |                               |
 |── POST /stream ───────────────>|  start mirroring
 |<─ 200 ────────────────────────|
 |                               |
 |══ RTP (UDP) ══════════════════>|  H.264 + AAC-ELD
```

---

## Build Notes

- Target: UWP (Windows 10 / Xbox One), `x64` + `ARM64`
- NuGet: `BouncyCastle.Cryptography` (Ed25519, X25519, ChaCha20-Poly1305)
- WinRT APIs used: `Windows.Networking.Sockets`, `Windows.Networking.ServiceDiscovery.Dnssd`, `Windows.Media.Core`, `Windows.Media.Playback`
- `OmgHaxData.LoadTablesAsync()` must complete before first `MirroringSession.StartAsync()` call — it loads FairPlay lookup tables from app package assets
