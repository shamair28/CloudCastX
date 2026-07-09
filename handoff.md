# CloudCast — Handoff Document
_Last updated: 2026-07-08_

> **Note:** This is the original phase-planning document. The live, up-to-date
> engineering status lives in `codex-changes.md` (testing branch). The FairPlay
> stub, namespace, and manifest issues described below are resolved; the current
> focus is the AirPlay 2 `SETUP` channel negotiation and PTP timing. See
> `codex-changes.md` → "2026-07-08 — SETUP handshake corrected against the AirPlay 2 spec".

---

## What this project is

A free UWP app for Xbox (and Windows 11 PC) that acts as an AirPlay 2 receiver — the same thing AirServer does for ~$20. The app advertises itself on the local network so iPhones, iPads, and Macs see it in their AirPlay picker and can mirror screens or stream audio to it.

---

## Project location

| Thing | Path |
|---|---|
| Solution | `D:\UWP\CloudCastX\CloudCastX.sln` |
| Project | `D:\UWP\CloudCastX\CloudCastX\` |
| Services | `D:\UWP\CloudCastX\CloudCastX\Services\` |
| Utilities | `D:\UWP\CloudCastX\CloudCastX\Util\` |
| Views | `D:\UWP\CloudCastX\CloudCastX\Views\` |

> **Why CloudCastX?** The original project was `CloudCast` but VS 2022 17.14 refused to load hand-crafted `.csproj` files (a chain of `targetPlatformVersion null` → `MSB3644` errors). A fresh VS-template-generated project named `CloudCastX` was created and all source files were copied into it manually.

---

## Architecture

```
App startup
  └─ MainPage.Loaded
       └─ AirPlayService.StartAsync()
            ├─ AirPlayControlServer  (HTTP on TCP :7000)
            ├─ RaopServer            (RAOP stub on TCP :5000)
            └─ MdnsAdvertiser        (UDP multicast :5353)
                  advertises _airplay._tcp + _raop._tcp
```

When an Apple device connects:
```
iPhone                        CloudCast
  │  GET /info                    │
  │◄──────────────────────────────│  binary plist with device capabilities
  │  POST /pair-setup (M1→M2)     │
  │  POST /pair-setup (M3→M4)     │  SRP-6a (BouncyCastle)
  │  POST /pair-setup (M5→M6)     │  Ed25519 key exchange
  │  POST /pair-verify (M1→M2)    │
  │  POST /pair-verify (M3→M4)    │  X25519 + Ed25519 (BouncyCastle)
  │  POST /fp-setup               │  ← STUB (returns 403) — blocks mirroring
  │  POST /stream                 │  H.264 RTP begins → MediaStreamSource
  │  RTP packets ────────────────►│  rendered in MediaPlayerElement
```

---

## NuGet packages

| Package | Version | Purpose |
|---|---|---|
| `Makaretu.Dns.Multicast` | 0.27.0 | mDNS service advertisement |
| `BouncyCastle.Cryptography` | 2.3.1 | SRP-6a, Ed25519, X25519, ChaCha20-Poly1305, HKDF |

---

## Source files

| File | Status | Notes |
|---|---|---|
| `Services/AirPlayConfig.cs` | ✅ Complete | Loads/persists Ed25519 key pair + device identity from `ApplicationData.LocalSettings` |
| `Services/AirPlayService.cs` | ✅ Complete | Orchestrator — starts all sub-services in order |
| `Services/MdnsAdvertiser.cs` | ✅ Complete | Advertises `_airplay._tcp` (port 7000) + `_raop._tcp` (port 5000) |
| `Services/AirPlayControlServer.cs` | ✅ Complete | HTTP server on port 7000; routes `/info`, `/pair-setup`, `/pair-verify`, `/fp-setup`, `/stream`, `/stop` |
| `Services/HapPairing.cs` | ✅ Complete | Full HAP pair-setup (SRP M1–M6) + pair-verify (M1–M4). **Caveat**: pair-verify M4 accepts without verifying the controller's LTPK (no persistence of paired controllers yet) |
| `Services/FairPlaySetup.cs` | ✅ Complete | FairPlay 3 phase 1/2 exchange (SteeBono port); KeyMsg feeds OmgHax AES key decryption |
| `Services/MirroringSession.cs` | ✅ Rewritten 2026-07-08 | TCP header-framed mirror receiver (128-byte headers, AES-CTR continuous keystream, AVCC→Annex B, avcC SPS/PPS) + `MediaStreamSource` pipeline. See `codex-changes.md` |
| `Services/RaopServer.cs` | ⬜ Stub | Listens on port 5000, immediately closes connections. Phase 4 target |
| `Util/BinaryPlist.cs` | ✅ Complete | Minimal binary plist encoder (dict, string, long, byte[], array) |
| `Util/Tlv8.cs` | ✅ Complete | HAP TLV8 encoder/decoder |
| `Views/MainPage.xaml` | ✅ Complete | Full-screen `MediaPlayerElement` + idle status overlay |
| `Views/MainPage.xaml.cs` | ✅ Complete | Wires `AirPlayService` events to UI |

---

## Current status

| Phase | Description | Status |
|---|---|---|
| 1 | mDNS advertisement — device appears in AirPlay picker | ✅ Working |
| 2 | Pairing + fp-setup + SETUP handshake — device connects | 🔄 SETUP responses corrected to spec (2026-07-08); event/data/control channels negotiated. Verify on-device |
| 3 | Screen mirroring — H.264 video renders | ⬜ Pending PTP clock responder (timing sync) |
| 4 | RAOP audio streaming | ⬜ Not started |
| 5 | Xbox polish (gamepad nav, suspend/resume) | ⬜ Not started |

---

## Active bug: "Unable to connect to CloudCast"

_Root cause identified 2026-07-08 — see `codex-changes.md` for the full write-up._

The phone saw CloudCast in the AirPlay picker (Phase 1 ✓) but failed when tapping
it. The failure was in the RTSP **`SETUP`** exchange, not in pairing, firewall,
namespaces, or the manifest — those earlier suspects are all resolved:

- ✅ `Package.appxmanifest` already declares `internetClient` + `privateNetworkClientServer`.
- ✅ Namespaces / `App.xaml.cs` navigation are correct (app starts, mDNS advertises, `/info` and pairing succeed).

The real problem: the two-part AirPlay 2 `SETUP` responses didn't match the spec.
Most importantly, **SETUP #1 returned the control port (7000) as the event port**,
so iOS opened its event channel into the RTSP server and — per the spec, *"the
event channel must be open or the RTSP won't continue"* — the handshake stalled.
Modern senders also use **PTP** timing, but the code always returned an NTP
`timingPort`. Both are now fixed in `AirPlayControlServer.cs`.

### If it still won't connect — check in order
1. **Windows Firewall** — allow inbound on the control port once, in elevated PowerShell:
   ```powershell
   New-NetFirewallRule -DisplayName "CloudCast AirPlay" -Direction Inbound -Protocol TCP -LocalPort 7000 -Action Allow
   ```
2. **Watch the `[WIRE]` / `[AirPlay]` debug log** through both `SETUP` requests. SETUP #1 should log `eventPort=<ephemeral, not 7000> timingPort=0` (PTP) and SETUP #2 should log `dataPort` + `controlPort`. If SETUP #1 never arrives, the block is before SETUP (pairing/fp-setup).
3. **PTP timing (known gap)** — if the handshake now completes but video never renders, the missing piece is the PTP clock responder (UDP 319/320). See `codex-changes.md` → "Remaining known gap".

---

## What's missing (to reach full screen mirroring)

### FairPlaySetup — the one hard blocker
`Services/FairPlaySetup.cs` currently returns HTTP 403 for `/fp-setup`. This endpoint exchanges a session key needed to decrypt the AES-CTR-encrypted H.264 stream. Without it, iOS refuses to start the video stream.

The implementation requires an RSA private key extracted from Apple TV firmware. This key is freely available in open-source AirPlay 2 implementations:
- **SteeBono/airplayreceiver** (C# — closest match): https://github.com/SteeBono/airplayreceiver
- **openairplay/airplay2-receiver** (Python reference): https://github.com/openairplay/airplay2-receiver

Look at how those projects handle `/fp-setup` and port the RSA decrypt + AES-CTR response into `FairPlaySetup.cs`.

### Pair-verify LTPK persistence
`HapPairing.HandlePairVerifyM3` accepts any structurally-valid M3 without checking the controller's Ed25519 public key (because we don't persist paired controller keys yet). Add persistence to `ApplicationData.LocalSettings` so paired devices don't need to re-pair after an app restart, and so M4 can properly verify the controller signature.

---

## Key constraints to remember

- **Xbox port restriction**: Xbox blocks ports 57344–65535. All dynamic port binds use port 0 (OS-assigned) and the actual port is advertised back to the sender.
- **No FairPlay DRM**: Xbox only supports PlayReady. Apple TV+, Netflix via AirPlay DRM, etc. will never work. This is acceptable — regular screen mirroring and audio work without DRM.
- **MFi auth skipped**: Hardware MFi chip auth is not implemented. All current open-source AirPlay 2 receivers skip it and most Apple devices still connect.
- **AirPlay 2 only**: Targets iOS 11.4+ / macOS 10.14+. AirPlay 1 not targeted.

---

## Protocol references

- Unofficial AirPlay 2 spec: https://openairplay.github.io/airplay-spec/
- HAP (HomeKit Accessory Protocol): Apple's HAP spec (public PDF via search)
- RFC 6184: RTP H.264 payload format
- RFC 5054: SRP-6a 3072-bit group parameters (used in HAP pair-setup)
