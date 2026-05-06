// Pairing protocol ported from SteeBono/airplayreceiver (MIT License):
//   https://github.com/SteeBono/airplayreceiver
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using CloudCast.Util;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace CloudCast.Services
{
    // Implements the transient AirPlay pairing handshake used by SteeBono/airplayreceiver.
    //
    // Pair-Setup (1 round-trip): server returns TLV8-encoded Ed25519 public key.
    //   TLV8 response: [0x06][0x01][0x02] (state=M2) + [0x03][0x20][pk:32]
    //
    // Pair-Verify (2 round-trips): raw Curve25519 ECDH with AES-CTR-encrypted Ed25519 proof.
    //   Phase 1 body: [flag:1][padding:3][ecdhTheirs:32][edTheirs:32]  = 68 bytes
    //   Phase 1 resp: [ecdhOurs:32][encryptedSignature:64]             = 96 bytes
    //   Phase 2 body: [flag:1][padding:3][encryptedClientSig:64]       = 68 bytes
    //   Phase 2 resp: empty
    internal class HapPairing
    {
        private readonly AirPlayConfig _config;
        private PairVerifyState? _verify;

        // Raw X25519 shared secret from the most recent pair-verify.
        // Needed downstream for AES stream-key derivation.
        public byte[]? EcdhSharedSecret { get; private set; }

        public HapPairing(AirPlayConfig config) => _config = config;

        // ── Pair-Setup ────────────────────────────────────────────────────────

        // Bug 1 fix: return TLV8-encoded response instead of raw key bytes.
        // iOS expects: tag 0x06 (state=M2) + tag 0x03 (Ed25519 public key).
        public Task<byte[]?> HandlePairSetupAsync(byte[] body)
        {
            System.Diagnostics.Debug.WriteLine("[HapPairing] pair-setup: returning TLV8-encoded Ed25519 public key");

            byte[] pk = _config.Ed25519PublicKey;

            // TLV8 layout: [tag:1][len:1][value:N]
            // Entry 1: tag=0x06 (state), len=1, value=0x02 (M2)
            // Entry 2: tag=0x03 (public key), len=32, value=pk
            var tlv = new byte[3 + 2 + pk.Length];
            tlv[0] = 0x06; tlv[1] = 0x01; tlv[2] = 0x02;          // state = M2
            tlv[3] = 0x03; tlv[4] = (byte)pk.Length;               // pk tag + length
            Buffer.BlockCopy(pk, 0, tlv, 5, pk.Length);

            return Task.FromResult<byte[]?>(tlv);
        }

        // ── Pair-Verify ───────────────────────────────────────────────────────

        // Dispatch on the flag byte (first byte of the raw body).
        public Task<byte[]?> HandlePairVerifyAsync(byte[] body)
        {
            if (body == null || body.Length < 1)
                return Task.FromResult<byte[]?>(null);

            byte flag = body[0];
            byte[]? response = flag > 0
                ? HandleVerifyPhase1(body)
                : HandleVerifyPhase2(body);

            return Task.FromResult(response);
        }

        // Phase 1: flag=1, body=[flag:1][pad:3][ecdhTheirs:32][edTheirs:32]
        private byte[]? HandleVerifyPhase1(byte[] body)
        {
            if (body.Length < 68)
            {
                System.Diagnostics.Debug.WriteLine("[HapPairing] pair-verify phase1: body too short");
                return null;
            }

            // Skip flag + 3 bytes padding
            byte[] ecdhTheirs = new byte[32];
            byte[] edTheirs   = new byte[32];
            Buffer.BlockCopy(body, 4, ecdhTheirs, 0, 32);
            Buffer.BlockCopy(body, 36, edTheirs,  0, 32);

            // Generate ephemeral X25519 keypair
            var kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var kp = kpGen.GenerateKeyPair();
            byte[] ecdhOurs = ((X25519PublicKeyParameters)kp.Public).GetEncoded();
            var   ecdhPriv  = (X25519PrivateKeyParameters)kp.Private;

            // Compute X25519 shared secret
            var agreement = new X25519Agreement();
            agreement.Init(ecdhPriv);
            byte[] sharedSecret = new byte[32];
            agreement.CalculateAgreement(
                new X25519PublicKeyParameters(ecdhTheirs, 0), sharedSecret, 0);

            EcdhSharedSecret = (byte[])sharedSecret.Clone();

            // Derive AES-CTR key and IV from shared secret via SHA-512
            byte[] aesKey = DeriveAesKeyOrIv("Pair-Verify-AES-Key", sharedSecret);
            byte[] aesIv  = DeriveAesKeyOrIv("Pair-Verify-AES-IV",  sharedSecret);

            // Sign (ecdhOurs | ecdhTheirs) with our Ed25519 long-term key
            byte[] signData = new byte[64];
            Buffer.BlockCopy(ecdhOurs,   0, signData,  0, 32);
            Buffer.BlockCopy(ecdhTheirs, 0, signData, 32, 32);
            byte[] signature = Ed25519Sign(_config.Ed25519PrivateKey, signData);

            // Encrypt the 64-byte signature with AES/CTR — counter starts at 0.
            // This consumes keystream bytes 0..63 (CTR block 0).
            byte[] encryptedSig = AesCtrProcess(aesKey, aesIv, signature);

            // Persist state for phase 2
            _verify = new PairVerifyState
            {
                EcdhOurs    = ecdhOurs,
                EcdhTheirs  = ecdhTheirs,
                EdTheirs    = edTheirs,
                SharedSecret = sharedSecret,
            };

            System.Diagnostics.Debug.WriteLine("[HapPairing] pair-verify phase1: sending ecdhOurs + encryptedSig");

            // Response: [ecdhOurs:32][encryptedSig:64] = 96 bytes
            byte[] response = new byte[96];
            Buffer.BlockCopy(ecdhOurs,     0, response,  0, 32);
            Buffer.BlockCopy(encryptedSig, 0, response, 32, 64);
            return response;
        }

        // Phase 2: flag=0, body=[flag:1][pad:3][encryptedClientSig:64]
        private byte[]? HandleVerifyPhase2(byte[] body)
        {
            if (_verify == null)
            {
                System.Diagnostics.Debug.WriteLine("[HapPairing] pair-verify phase2: no verify state");
                return null;
            }
            if (body.Length < 68)
            {
                System.Diagnostics.Debug.WriteLine("[HapPairing] pair-verify phase2: body too short");
                return null;
            }

            byte[] clientEncryptedSig = new byte[64];
            Buffer.BlockCopy(body, 4, clientEncryptedSig, 0, 64);

            // Re-derive AES-CTR key/IV from the stored shared secret
            byte[] aesKey = DeriveAesKeyOrIv("Pair-Verify-AES-Key", _verify.SharedSecret);
            byte[] aesIv  = DeriveAesKeyOrIv("Pair-Verify-AES-IV",  _verify.SharedSecret);

            // Bug 4 fix: create cipher and advance counter by 64 bytes (one full AES block
            // worth of keystream = CTR block 0) to match phase 1 encryption offset,
            // then decrypt the client signature using CTR block 1 onwards.
            var cipher = CreateAesCtrCipher(aesKey, aesIv, forEncryption: false);
            var dummy  = new byte[64];
            cipher.ProcessBytes(new byte[64], 0, 64, dummy, 0);

            // Debug assertion: log first dummy byte to verify counter advancement
            System.Diagnostics.Debug.WriteLine(
                $"[HapPairing] pair-verify phase2: CTR advanced 64 bytes, dummy[0]=0x{dummy[0]:X2} (expect non-zero keystream)");

            byte[] clientSig = new byte[64];
            cipher.ProcessBytes(clientEncryptedSig, 0, 64, clientSig, 0);

            // Verify the client's signature over (ecdhTheirs | ecdhOurs)
            byte[] verifyData = new byte[64];
            Buffer.BlockCopy(_verify.EcdhTheirs, 0, verifyData,  0, 32);
            Buffer.BlockCopy(_verify.EcdhOurs,   0, verifyData, 32, 32);
            bool verified = Ed25519Verify(_verify.EdTheirs, verifyData, clientSig);

            System.Diagnostics.Debug.WriteLine(
                $"[HapPairing] pair-verify phase2: signature {(verified ? "OK" : "FAILED")}");

            // Keep EcdhSharedSecret for downstream use; clear the per-handshake state
            _verify = null;

            // Return empty response on success, null on verification failure
            return verified ? Array.Empty<byte>() : null;
        }

        // ── Crypto helpers ────────────────────────────────────────────────────

        // SHA-512(label | sharedSecret), take first 16 bytes → AES key or IV.
        private static byte[] DeriveAesKeyOrIv(string label, byte[] sharedSecret)
        {
            byte[] labelBytes = System.Text.Encoding.ASCII.GetBytes(label);
            byte[] input = new byte[labelBytes.Length + sharedSecret.Length];
            Buffer.BlockCopy(labelBytes,   0, input, 0,              labelBytes.Length);
            Buffer.BlockCopy(sharedSecret, 0, input, labelBytes.Length, sharedSecret.Length);

            using var sha = SHA512.Create();
            byte[] hash = sha.ComputeHash(input);
            byte[] result = new byte[16];
            Buffer.BlockCopy(hash, 0, result, 0, 16);
            return result;
        }

        // Encrypt/decrypt data with AES/CTR (NoPadding).
        private static byte[] AesCtrProcess(byte[] key, byte[] iv, byte[] data)
        {
            var cipher = CreateAesCtrCipher(key, iv, forEncryption: true);
            byte[] output = new byte[data.Length];
            int n = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, n);
            return output;
        }

        private static Org.BouncyCastle.Crypto.IBufferedCipher CreateAesCtrCipher(
            byte[] key, byte[] iv, bool forEncryption)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            var keyParam = ParameterUtilities.CreateKeyParameter("AES", key);
            cipher.Init(forEncryption, new ParametersWithIV(keyParam, iv));
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

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0; foreach (var p in parts) total += p.Length;
            var r = new byte[total]; int off = 0;
            foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, off, p.Length); off += p.Length; }
            return r;
        }

        // ── Session state ─────────────────────────────────────────────────────

        private sealed class PairVerifyState
        {
            public byte[] EcdhOurs    = null!;
            public byte[] EcdhTheirs  = null!;
            public byte[] EdTheirs    = null!;
            public byte[] SharedSecret = null!;
        }
    }
}
