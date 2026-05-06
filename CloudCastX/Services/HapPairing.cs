using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

namespace CloudCast.Services
{
    // Implements Apple HomeKit Accessory Protocol (HAP) pairing:
    //   pair-setup  → M1→M2 (Ed25519 key exchange)
    //   pair-verify → M1→M2 (ECDH shared secret + Ed25519 signature verification)
    //
    // TLV8 tag constants (HAP spec §4):
    //   0x00 = Method    0x01 = Identifier  0x02 = Salt      0x03 = PublicKey
    //   0x04 = Proof     0x05 = EncData     0x06 = State     0x07 = Error
    //   0x09 = Signature 0x0A = Permissions 0x0D = SessionID
    internal class HapPairing
    {
        private readonly AirPlayConfig _config;

        // ECDH key pair generated once per server lifetime
        private readonly byte[] _ecdhPrivateKey;
        private readonly byte[] _ecdhPublicKey;

        // Ephemeral keys generated per verify session
        private byte[]? _verifyPrivateKey;
        private byte[]? _verifyPublicKey;
        private byte[]? _peerPublicKey;

        // Exposed for MirroringSession stream key derivation
        public byte[]? EcdhSharedSecret { get; private set; }

        public HapPairing(AirPlayConfig config)
        {
            _config = config;
            var gen = new X25519KeyPairGenerator();
            gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            _ecdhPrivateKey = new byte[32];
            _ecdhPublicKey  = new byte[32];
            ((X25519PrivateKeyParameters)kp.Private).Encode(_ecdhPrivateKey, 0);
            ((X25519PublicKeyParameters)kp.Public).Encode(_ecdhPublicKey, 0);
        }

        // ── pair-setup ────────────────────────────────────────────────────────
        // iOS sends M1 (state=1, method=0). We respond with M2: Ed25519 public key.
        public Task<byte[]?> HandlePairSetupAsync(byte[] body)
        {
            var tlv = DecodeTlv8(body);
            tlv.TryGetValue(0x06, out var stateBytes);
            byte state = (stateBytes != null && stateBytes.Length > 0) ? stateBytes[0] : (byte)0;
            System.Diagnostics.Debug.WriteLine($"[HAP] pair-setup state={state}");

            var response = EncodeTlv8(new Dictionary<byte, byte[]>
            {
                { 0x06, new byte[] { 0x02 } },      // state = M2
                { 0x03, _config.Ed25519PublicKey },  // public key
            });
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-setup M2: {response.Length} bytes, " +
                $"pk={BitConverter.ToString(_config.Ed25519PublicKey, 0, 4)}…");
            return Task.FromResult<byte[]?>(response);
        }

        // ── pair-verify ───────────────────────────────────────────────────────
        public Task<byte[]?> HandlePairVerifyAsync(byte[] body)
        {
            var tlv = DecodeTlv8(body);
            tlv.TryGetValue(0x06, out var stateBytes);
            byte state = (stateBytes != null && stateBytes.Length > 0) ? stateBytes[0] : (byte)0;
            System.Diagnostics.Debug.WriteLine($"[HAP] pair-verify state={state}");

            if (state == 1)
                return Task.FromResult(HandleVerifyPhase1(tlv));
            if (state == 3)
                return Task.FromResult(HandleVerifyPhase2(tlv));

            System.Diagnostics.Debug.WriteLine($"[HAP] pair-verify unknown state {state}");
            return Task.FromResult<byte[]?>(null);
        }

        private byte[]? HandleVerifyPhase1(Dictionary<byte, byte[]> tlv)
        {
            System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase 1 start");

            if (!tlv.TryGetValue(0x03, out _peerPublicKey) || _peerPublicKey.Length != 32)
            {
                System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase 1: missing/invalid peer public key");
                return null;
            }

            // Generate ephemeral X25519 key pair for this verify session
            var gen = new X25519KeyPairGenerator();
            gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            _verifyPrivateKey = new byte[32];
            _verifyPublicKey  = new byte[32];
            ((X25519PrivateKeyParameters)kp.Private).Encode(_verifyPrivateKey, 0);
            ((X25519PublicKeyParameters)kp.Public).Encode(_verifyPublicKey, 0);

            // ECDH: our ephemeral private + peer public → shared secret
            var agreement = new X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(_verifyPrivateKey, 0));
            EcdhSharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(
                new X25519PublicKeyParameters(_peerPublicKey, 0), EcdhSharedSecret, 0);

            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase 1: ECDH shared={BitConverter.ToString(EcdhSharedSecret, 0, 4)}…");

            // Sign: Ed25519( ourVerifyPublicKey || peerPublicKey )
            var msgToSign = Concat(_verifyPublicKey, _peerPublicKey);
            var signature = Ed25519Sign(msgToSign, _config.Ed25519PrivateKey);

            var response = EncodeTlv8(new Dictionary<byte, byte[]>
            {
                { 0x06, new byte[] { 0x02 } }, // state = M2
                { 0x03, _verifyPublicKey },     // our ephemeral verify public key
                { 0x09, signature },            // Ed25519 signature
            });
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase 1 M2: {response.Length} bytes");
            return response;
        }

        private byte[]? HandleVerifyPhase2(Dictionary<byte, byte[]> tlv)
        {
            System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase 2 start");

            if (EcdhSharedSecret == null || _verifyPublicKey == null || _peerPublicKey == null)
            {
                System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase 2: missing phase 1 state");
                return null;
            }

            if (!tlv.TryGetValue(0x05, out var encData) || encData.Length < 16)
            {
                System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase 2: missing encData");
                return null;
            }

            // Derive session key via HKDF-SHA-512
            byte[] sessionKey = HkdfSha512(
                EcdhSharedSecret,
                Encoding.UTF8.GetBytes("Pair-Verify-Encrypt-Salt"),
                Encoding.UTF8.GetBytes("Pair-Verify-Encrypt-Info"),
                32);

            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase 2: sessionKey={BitConverter.ToString(sessionKey, 0, 4)}…");

            // Decrypt using ChaCha20-Poly1305, nonce="PV-Msg03"
            byte[]? plaintext = ChaCha20Poly1305Decrypt(
                sessionKey, Encoding.UTF8.GetBytes("PV-Msg03"), encData);

            if (plaintext == null)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[HAP] pair-verify phase 2: ChaCha20-Poly1305 decryption failed");
                return null;
            }

            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase 2: decrypted {plaintext.Length} bytes");

            var inner = DecodeTlv8(plaintext);
            inner.TryGetValue(0x01, out var peerId);
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase 2: peerId={( peerId != null ? Encoding.UTF8.GetString(peerId) : "null")}");

            // Respond M4 — pairing complete
            var response = EncodeTlv8(new Dictionary<byte, byte[]>
            {
                { 0x06, new byte[] { 0x04 } }, // state = M4
            });
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify M4: {response.Length} bytes — pairing COMPLETE");
            return response;
        }

        // ── Crypto helpers ────────────────────────────────────────────────────

        private static byte[] Ed25519Sign(byte[] message, byte[] privateKey)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        private static byte[]? ChaCha20Poly1305Decrypt(
            byte[] key, byte[] nonce, byte[] ciphertext)
        {
            try
            {
                // HAP uses an 8-byte nonce, zero-padded to 12 bytes on the left
                var nonce12 = new byte[12];
                Array.Copy(nonce, 0, nonce12, 4, Math.Min(nonce.Length, 8));

                var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
                cipher.Init(false, new Org.BouncyCastle.Crypto.Parameters.AeadParameters(
                    new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key), 128, nonce12));

                var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
                int len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
                cipher.DoFinal(output, len);
                return output;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[HAP] ChaCha20Poly1305Decrypt exception: {ex.Message}");
                return null;
            }
        }

        private static byte[] HkdfSha512(byte[] ikm, byte[] salt, byte[] info, int outputLen)
        {
            using var hmacExtract = new HMACSHA512(salt);
            byte[] prk = hmacExtract.ComputeHash(ikm);

            var output = new System.Collections.Generic.List<byte>();
            byte[] prev = Array.Empty<byte>();
            byte counter = 1;
            while (output.Count < outputLen)
            {
                using var hmacExpand = new HMACSHA512(prk);
                hmacExpand.TransformBlock(prev, 0, prev.Length, null, 0);
                hmacExpand.TransformBlock(info, 0, info.Length, null, 0);
                hmacExpand.TransformFinalBlock(new[] { counter++ }, 0, 1);
                prev = hmacExpand.Hash!;
                output.AddRange(prev);
            }
            return output.Take(outputLen).ToArray();
        }

        // ── TLV8 codec ────────────────────────────────────────────────────────

        internal static byte[] EncodeTlv8(Dictionary<byte, byte[]> items)
        {
            var result = new System.Collections.Generic.List<byte>();
            foreach (var kv in items)
            {
                byte tag   = kv.Key;
                byte[] value = kv.Value;
                int offset = 0;
                do
                {
                    int chunkLen = Math.Min(value.Length - offset, 255);
                    result.Add(tag);
                    result.Add((byte)chunkLen);  // explicit cast: int → byte
                    result.AddRange(new ArraySegment<byte>(value, offset, chunkLen));
                    offset += chunkLen;
                } while (offset < value.Length);
            }
            return result.ToArray();
        }

        internal static Dictionary<byte, byte[]> DecodeTlv8(byte[] data)
        {
            var result = new Dictionary<byte, byte[]>();
            int i = 0;
            while (i + 1 < data.Length)
            {
                byte tag = data[i++];
                int  len = data[i++];
                if (i + len > data.Length) break;
                var chunk = new ArraySegment<byte>(data, i, len);
                i += len;
                if (result.TryGetValue(tag, out var existing))
                {
                    var merged = new byte[existing.Length + len];
                    existing.CopyTo(merged, 0);
                    chunk.CopyTo(merged, existing.Length);
                    result[tag] = merged;
                }
                else
                {
                    result[tag] = chunk.ToArray();
                }
            }
            return result;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            a.CopyTo(r, 0);
            b.CopyTo(r, a.Length);
            return r;
        }
    }
}
