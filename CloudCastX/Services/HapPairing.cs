// Pairing protocol ported from SteeBono/airplayreceiver (MIT License):
//   https://github.com/SteeBono/airplayreceiver
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace CloudCast.Services
{
    // Raw-byte AirPlay pairing (SteeBono-style, NOT TLV8/HAP).
    //
    // pair-setup:  32 bytes in (ignored) → 32 bytes out (Ed25519 public key)
    // pair-verify: phase1: 68 bytes in → 96 bytes out (ECDH + encrypted sig)
    //              phase2: 68 bytes in → 0 bytes out  (verify client sig)
    internal class HapPairing
    {
        private readonly AirPlayConfig _config;
        private VerifyState? _verify;

        public byte[]? EcdhSharedSecret { get; private set; }

        public HapPairing(AirPlayConfig config) => _config = config;

        // ── pair-setup ──────────────────────────────────────────────────────
        public Task<byte[]?> HandlePairSetupAsync(byte[] body)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-setup: returning raw 32-byte Ed25519 pk (body={body.Length}B)");
            return Task.FromResult<byte[]?>((byte[])_config.Ed25519PublicKey.Clone());
        }

        // ── pair-verify ─────────────────────────────────────────────────────
        public Task<byte[]?> HandlePairVerifyAsync(byte[] body)
        {
            if (body == null || body.Length < 4)
                return Task.FromResult<byte[]?>(null);

            byte flag = body[0];
            System.Diagnostics.Debug.WriteLine($"[HAP] pair-verify: flag={flag} body={body.Length}B");

            byte[]? response = flag > 0
                ? HandleVerifyPhase1(body)
                : HandleVerifyPhase2(body);

            return Task.FromResult(response);
        }

        private byte[]? HandleVerifyPhase1(byte[] body)
        {
            if (body.Length < 68)
            {
                System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase1: body too short");
                return null;
            }

            // Parse: [flag:1][pad:3][ecdh_theirs:32][ed_theirs:32]
            var ecdhTheirs = new byte[32];
            var edTheirs = new byte[32];
            Buffer.BlockCopy(body, 4, ecdhTheirs, 0, 32);
            Buffer.BlockCopy(body, 36, edTheirs, 0, 32);

            // Generate ephemeral X25519 keypair
            var kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var kp = kpGen.GenerateKeyPair();
            var ecdhOurs = ((X25519PublicKeyParameters)kp.Public).GetEncoded();
            var ecdhPriv = (X25519PrivateKeyParameters)kp.Private;

            // Compute shared secret
            var agreement = new X25519Agreement();
            agreement.Init(ecdhPriv);
            var sharedSecret = new byte[32];
            agreement.CalculateAgreement(
                new X25519PublicKeyParameters(ecdhTheirs, 0), sharedSecret, 0);

            EcdhSharedSecret = (byte[])sharedSecret.Clone();

            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase1: ECDH shared={BitConverter.ToString(sharedSecret, 0, 4)}…");

            // Derive AES-CTR key and IV
            var aesKey = DeriveHash("Pair-Verify-AES-Key", sharedSecret);
            var aesIv = DeriveHash("Pair-Verify-AES-IV", sharedSecret);

            // Sign (ecdhOurs | ecdhTheirs) with Ed25519
            var signData = new byte[64];
            Buffer.BlockCopy(ecdhOurs, 0, signData, 0, 32);
            Buffer.BlockCopy(ecdhTheirs, 0, signData, 32, 32);
            var signature = Ed25519Sign(_config.Ed25519PrivateKey, signData);

            // Encrypt signature with AES/CTR
            var cipher = CreateAesCtr(aesKey, aesIv, forEncryption: true);
            var encryptedSig = new byte[64];
            cipher.ProcessBytes(signature, 0, 64, encryptedSig, 0);

            // Store state for phase 2
            _verify = new VerifyState
            {
                EcdhOurs = ecdhOurs,
                EcdhTheirs = ecdhTheirs,
                EdTheirs = edTheirs,
                SharedSecret = sharedSecret,
            };

            // Response: [ecdhOurs:32][encryptedSig:64] = 96 bytes
            var response = new byte[96];
            Buffer.BlockCopy(ecdhOurs, 0, response, 0, 32);
            Buffer.BlockCopy(encryptedSig, 0, response, 32, 64);

            System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase1: returning 96 bytes");
            return response;
        }

        private byte[]? HandleVerifyPhase2(byte[] body)
        {
            if (_verify == null || body.Length < 68)
            {
                System.Diagnostics.Debug.WriteLine("[HAP] pair-verify phase2: missing state or body too short");
                return null;
            }

            // Parse: [flag:1][pad:3][encrypted_client_sig:64]
            var clientEncSig = new byte[64];
            Buffer.BlockCopy(body, 4, clientEncSig, 0, 64);

            // Re-derive cipher, advance past the 64 bytes used in phase 1
            var aesKey = DeriveHash("Pair-Verify-AES-Key", _verify.SharedSecret);
            var aesIv = DeriveHash("Pair-Verify-AES-IV", _verify.SharedSecret);
            var cipher = CreateAesCtr(aesKey, aesIv, forEncryption: false);

            // Advance counter by processing 64 dummy bytes (matches phase 1 state)
            cipher.ProcessBytes(new byte[64], 0, 64, new byte[64], 0);

            // Decrypt client's signature
            var clientSig = new byte[64];
            cipher.ProcessBytes(clientEncSig, 0, 64, clientSig, 0);

            // Verify: Ed25519(edTheirs, ecdhTheirs | ecdhOurs, clientSig)
            var verifyData = new byte[64];
            Buffer.BlockCopy(_verify.EcdhTheirs, 0, verifyData, 0, 32);
            Buffer.BlockCopy(_verify.EcdhOurs, 0, verifyData, 32, 32);

            bool ok = Ed25519Verify(_verify.EdTheirs, verifyData, clientSig);
            System.Diagnostics.Debug.WriteLine(
                $"[HAP] pair-verify phase2: signature {(ok ? "VERIFIED" : "FAILED")}");

            _verify = null;
            return Array.Empty<byte>(); // empty response
        }

        // ── Crypto helpers ──────────────────────────────────────────────────

        private static byte[] DeriveHash(string label, byte[] sharedSecret)
        {
            using var sha = SHA512.Create();
            var input = new byte[Encoding.UTF8.GetByteCount(label) + sharedSecret.Length];
            Encoding.UTF8.GetBytes(label, 0, label.Length, input, 0);
            Buffer.BlockCopy(sharedSecret, 0, input, input.Length - sharedSecret.Length, sharedSecret.Length);
            var hash = sha.ComputeHash(input);
            var result = new byte[16];
            Buffer.BlockCopy(hash, 0, result, 0, 16);
            return result;
        }

        private static Org.BouncyCastle.Crypto.IBufferedCipher CreateAesCtr(
            byte[] key, byte[] iv, bool forEncryption)
        {
            var cipher = Org.BouncyCastle.Security.CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(forEncryption, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                Org.BouncyCastle.Security.ParameterUtilities.CreateKeyParameter("AES", key), iv));
            return cipher;
        }

        private static byte[] Ed25519Sign(byte[] privateKey, byte[] message)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        private static bool Ed25519Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            try
            {
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
                verifier.BlockUpdate(message, 0, message.Length);
                return verifier.VerifySignature(signature);
            }
            catch { return false; }
        }

        private sealed class VerifyState
        {
            public byte[] EcdhOurs = null!;
            public byte[] EcdhTheirs = null!;
            public byte[] EdTheirs = null!;
            public byte[] SharedSecret = null!;
        }
    }
}
