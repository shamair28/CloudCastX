# CloudCast — Handoff Document
_Last updated: 2026-05-05_

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
| `Services/FairPlaySetup.cs` | ❌ Stub | Returns HTTP 403. Blocks screen mirroring. See "What's missing" below |
| `Services/MirroringSession.cs` | ✅ Complete | RTP receiver + RFC 6184 H.264 NALU parsing + `MediaStreamSource` pipeline. AES-CTR decryption not wired up (depends on FairPlay) |
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
| 2 | HAP pairing handshake — device connects | 🔄 In progress — getting "Unable to connect" on phone |
| 3 | Screen mirroring — H.264 video renders | ⬜ Blocked by FairPlay stub |
| 4 | RAOP audio streaming | ⬜ Not started |
| 5 | Xbox polish (gamepad nav, suspend/resume) | ⬜ Not started |

---

## Active bug: "Unable to connect to CloudCast"

The phone sees CloudCast in AirPlay (Phase 1 ✓) but fails when tapping it. Three things to check in order:

### Check 1 — Package.appxmanifest capability (most likely)
The VS template generates a minimal manifest. The app **must** have `privateNetworkClientServer` or UWP silently blocks all inbound connections:
```xml
<Capabilities>
  <Capability Name="internetClient" />
  <Capability Name="privateNetworkClientServer" />
</Capabilities>
```
In VS: right-click `Package.appxmanifest` → Open With → XML Editor and verify both lines are present.

### Check 2 — Windows Firewall
Run once in elevated PowerShell:
```powershell
New-NetFirewallRule -DisplayName "CloudCast AirPlay" -Direction Inbound -Protocol TCP -LocalPort 7000 -Action Allow
```

### Check 3 — Namespace mismatch
All our `.cs` files use `namespace CloudCast.*`. The VS project is `CloudCastX`. If `App.xaml.cs` still has `typeof(CloudCast.Views.MainPage)` rather than the correct type, `AirPlayService` never starts. Check the `rootFrame.Navigate(typeof(...))` call in `App.xaml.cs` matches the actual namespace in `MainPage.xaml.cs`.

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
