using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Windows.Storage;

namespace CloudCast.Services
{
    internal class AirPlayConfig
    {
        // ── Protocol constants ─────────────────────────────────────────────────

        public const string Model         = "AppleTV5,3";
        public const string ServerVersion = "220.68";

        public const ushort ControlPort = 7000;
        public const ushort RaopPort    = 5000;

        // Fixed service ports (SteeBono-style). Fixed rather than OS-assigned so
        // a one-time firewall rule can cover them — iOS aborts after SETUP #1 if
        // its inbound event connection is dropped — and so we stay clear of the
        // Xbox-blocked 57344+ range that Windows uses for ephemeral ports.
        // Binds fall back to an OS-assigned port if the fixed one is taken.
        public const ushort EventPort        = 7001;
        public const ushort TimingPort       = 7002;
        public const ushort MirrorDataPort   = 7100;
        public const ushort AudioDataPort    = 6000;
        public const ushort AudioControlPort = 6001;

        // Features bitmask — SteeBono's known-working values from airplayreceiver
        // (https://github.com/SteeBono/airplayreceiver, MIT License).
        // These values include bit 27 (SupportsLegacyPairing / Authentication4),
        // which causes iOS to go through pair-setup/pair-verify instead of
        // skipping pairing entirely. The raw-byte pairing protocol below matches
        // what SteeBono implements for these feature flags.
        public const string FeaturesHex = "0x5A7FFFF7,0x1E";
        public const long   Features    = unchecked((long)0x1E5A7FFFF7);

        // ── Instance identity ──────────────────────────────────────────────────

        // Bump to force a brand-new receiver identity (new MAC, Ed25519 pair,
        // pairing ID, name). iOS caches receiver state keyed by deviceid/pk/pi;
        // the identity had been kept constant across weeks of protocol rework
        // (including an incompatible earlier pair-setup implementation), so a
        // stale cache entry on the sender can poison an otherwise-correct
        // handshake. A fresh identity makes the phone treat us as a new device.
        private const int IdentityVersion = 2;

        public string DeviceName    { get; private set; } = string.Empty;
        public string DeviceId      { get; private set; } = string.Empty;
        public string PairingId     { get; private set; } = string.Empty;

        public byte[] Ed25519PublicKey  { get; private set; } = Array.Empty<byte>();
        public byte[] Ed25519PrivateKey { get; private set; } = Array.Empty<byte>();

        // ── Factory ───────────────────────────────────────────────────────────

        public static AirPlayConfig Load()
        {
            var s = ApplicationData.Current.LocalSettings;
            var cfg = new AirPlayConfig();

            int storedVersion = s.Values["IdentityVersion"] is int v ? v : 0;
            var pubB64  = s.Values["Ed25519Pub"]  as string;
            var privB64 = s.Values["Ed25519Priv"] as string;

            if (storedVersion != IdentityVersion || pubB64 == null || privB64 == null)
            {
                cfg.DeviceId  = GenerateMac();
                cfg.PairingId = Guid.NewGuid().ToString("D");
                var (pub, priv) = GenerateEd25519();
                cfg.Ed25519PublicKey  = pub;
                cfg.Ed25519PrivateKey = priv;
                s.Values["IdentityVersion"] = IdentityVersion;
                s.Values["DeviceId"]    = cfg.DeviceId;
                s.Values["PairingId"]   = cfg.PairingId;
                s.Values["Ed25519Pub"]  = Convert.ToBase64String(pub);
                s.Values["Ed25519Priv"] = Convert.ToBase64String(priv);
                System.Diagnostics.Debug.WriteLine(
                    $"[Config] Generated fresh receiver identity v{IdentityVersion} ({cfg.DeviceId})");
            }
            else
            {
                cfg.DeviceId  = s.Values["DeviceId"]  as string ?? GenerateMac();
                cfg.PairingId = s.Values["PairingId"] as string ?? Guid.NewGuid().ToString("D");
                cfg.Ed25519PublicKey  = Convert.FromBase64String(pubB64);
                cfg.Ed25519PrivateKey = Convert.FromBase64String(privB64);
            }

            // Derive the visible name from the MAC so a fresh identity is also a
            // "new" device in the AirPlay picker (iOS caches by name too).
            cfg.DeviceName = $"CloudCast-{cfg.DeviceId.Replace(":", "").Substring(8)}";

            return cfg;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string GenerateMac()
        {
            var rng = new SecureRandom();
            var b = new byte[6];
            rng.NextBytes(b);
            b[0] = (byte)((b[0] & 0xFE) | 0x02);
            return string.Join(":", b.Select(x => x.ToString("X2")));
        }

        private static (byte[] pub, byte[] priv) GenerateEd25519()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var pub  = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
            var priv = ((Ed25519PrivateKeyParameters)kp.Private).GetEncoded();
            return (pub, priv);
        }
    }
}
