# CloudCastX — Testing Branch Handoff

**Branch:** `testing`
**Repo:** https://github.com/shamair28/CloudCastX
**Last updated:** 2026-07-08
**Status:** SETUP handshake reworked to match the authoritative AirPlay 2 RTSP contract. The event/timing/data/control channels are now negotiated the way modern (PTP) iOS senders expect. Full PTP clock sync is the remaining known gap for video actually rendering (see Outstanding Issues).

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
