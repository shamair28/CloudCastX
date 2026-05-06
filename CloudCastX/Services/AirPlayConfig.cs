using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Windows.Storage;

namespace CloudCast.Services
{
    // Holds device identity and cryptographic keys that persist across app sessions.
    // Keys are stored in ApplicationData.LocalSettings so paired Apple devices don't
    // need to re-pair after an app restart.
    internal class AirPlayConfig
    {
        // ── Protocol constants ─────────────────────────────────────────────────

        public const string Model          = "AppleTV5,3";
        public const string ServerVersion  = "220.68";

        // Bug 3 fix: separate ports to avoid bind conflicts.
        public const ushort ControlPort    = 7000;
        public const ushort TimingPort     = 7001;  // NTP timing sync channel
        public const ushort EventPort      = 7002;  // AirPlay event channel
        public const ushort VideoPort      = 7100;  // mirroring video data
        public const ushort RaopPort       = 5000;

        // Features bitmask advertised to Apple devices (matches known-working values
        // from open-source AirPlay 2 implementations such as SteeBono/airplayreceiver).
        // Encodes: Video, Screen, Audio, AudioRedundant, FPSAPv2pt5_AES_GCM,
        // Authentication4 (HAP), various AudioFormat/Metadata flags.
        public const string FeaturesHex = "0x4A7FFFF7,0x0E";

        // Packed 64-bit form used in the binary plist /info response.
        public const long Features = unchecked((long)0x0E4A7FFFF7L);

        // ── Instance identity ──────────────────────────────────────────────────

        public string DeviceName    { get; private set; } = "CloudCastXTest";
        public string DeviceId      { get; private set; } = string.Empty;  // MAC-style
        public string PairingId     { get; private set; } = string.Empty;  // UUID

        // Ed25519 key pair used for HAP pairing handshake
        public byte[] Ed25519PublicKey  { get; private set; } = Array.Empty<byte>();
        public byte[] Ed25519PrivateKey { get; private set; } = Array.Empty<byte>();

        // ── Factory ───────────────────────────────────────────────────────────

        public static AirPlayConfig Load()
        {
            var s = ApplicationData.Current.LocalSettings;
            var cfg = new AirPlayConfig();

            cfg.DeviceId  = s.Values["DeviceId"]  as string ?? GenerateMac();
            cfg.PairingId = s.Values["PairingId"] as string ?? Guid.NewGuid().ToString("D");

            var pubB64  = s.Values["Ed25519Pub"]  as string;
            var privB64 = s.Values["Ed25519Priv"] as string;

            if (pubB64 == null || privB64 == null)
            {
                var (pub, priv) = GenerateEd25519();
                cfg.Ed25519PublicKey  = pub;
                cfg.Ed25519PrivateKey = priv;
                s.Values["DeviceId"]    = cfg.DeviceId;
                s.Values["PairingId"]   = cfg.PairingId;
                s.Values["Ed25519Pub"]  = Convert.ToBase64String(pub);
                s.Values["Ed25519Priv"] = Convert.ToBase64String(priv);
            }
            else
            {
                cfg.Ed25519PublicKey  = Convert.FromBase64String(pubB64);
                cfg.Ed25519PrivateKey = Convert.FromBase64String(privB64);
            }

            return cfg;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string GenerateMac()
        {
            var rng = new SecureRandom();
            var b = new byte[6];
            rng.NextBytes(b);
            b[0] = (byte)((b[0] & 0xFE) | 0x02); // locally administered unicast
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
