using System;
using System.Collections.Generic;
using System.IO;

namespace CloudCast.Util
{
    // TLV8 encoder/decoder used by the HomeKit Accessory Protocol (HAP) pairing messages.
    // Format: [tag:1][length:1][value:length] repeated.
    // Values longer than 255 bytes are split into consecutive TLVs with the same tag.
    internal static class Tlv8
    {
        // Common HAP TLV tags
        public const byte TagMethod        = 0x00;
        public const byte TagIdentifier    = 0x01;
        public const byte TagSalt          = 0x02;
        public const byte TagPublicKey     = 0x03;
        public const byte TagProof         = 0x04;
        public const byte TagEncryptedData = 0x05;
        public const byte TagState         = 0x06;
        public const byte TagError         = 0x07;
        public const byte TagRetryDelay    = 0x08;
        public const byte TagCertificate   = 0x09;
        public const byte TagSignature     = 0x0A;
        public const byte TagPermissions   = 0x0B;
        public const byte TagSeparator     = 0xFF;

        // HAP error codes
        public const byte ErrorUnknown          = 0x01;
        public const byte ErrorAuthentication   = 0x02;
        public const byte ErrorBackoff          = 0x03;
        public const byte ErrorMaxPeers         = 0x04;
        public const byte ErrorMaxTries         = 0x05;
        public const byte ErrorUnavailable      = 0x06;
        public const byte ErrorBusy             = 0x07;

        // ── Encoding ───────────────────────────────────────────────────────────

        public static byte[] Encode(IEnumerable<(byte tag, byte[] value)> items)
        {
            using var ms = new MemoryStream();
            foreach (var (tag, value) in items)
            {
                if (value.Length == 0)
                {
                    ms.WriteByte(tag);
                    ms.WriteByte(0);
                    continue;
                }

                int offset = 0;
                int remaining = value.Length;
                while (remaining > 0)
                {
                    int chunk = Math.Min(remaining, 255);
                    ms.WriteByte(tag);
                    ms.WriteByte((byte)chunk);
                    ms.Write(value, offset, chunk);
                    offset += chunk;
                    remaining -= chunk;
                }
            }
            return ms.ToArray();
        }

        // Convenience: single item
        public static byte[] Encode(byte tag, byte[] value)
            => Encode(new[] { (tag, value) });

        // ── Decoding ───────────────────────────────────────────────────────────

        // Returns a dictionary mapping each tag to its concatenated value bytes.
        // Multi-chunk values (same tag in consecutive TLVs) are merged.
        public static Dictionary<byte, byte[]> Decode(byte[] data)
        {
            var chunks = new Dictionary<byte, List<byte>>();
            int i = 0;
            while (i + 2 <= data.Length)
            {
                byte tag = data[i++];
                int len  = data[i++];

                if (!chunks.ContainsKey(tag))
                    chunks[tag] = new List<byte>();

                for (int j = 0; j < len && i < data.Length; j++, i++)
                    chunks[tag].Add(data[i]);
            }

            var result = new Dictionary<byte, byte[]>();
            foreach (var kv in chunks)
                result[kv.Key] = kv.Value.ToArray();
            return result;
        }
    }
}
