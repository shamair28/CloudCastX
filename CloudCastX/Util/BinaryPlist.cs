using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CloudCast.Util
{
    // Binary plist encoder/decoder covering the types used in AirPlay protocol:
    // Dictionary<string, object>, string, long, byte[], bool.
    internal static class BinaryPlist
    {
        // ── Decoder ───────────────────────────────────────────────────────────

        public static Dictionary<string, object>? Decode(byte[] data)
        {
            if (data == null || data.Length < 40) return null;
            if (data[0] != 'b' || data[1] != 'p' || data[2] != 'l' ||
                data[3] != 'i' || data[4] != 's' || data[5] != 't')
                return null;

            int trailerStart = data.Length - 32;
            int offsetIntSize = data[trailerStart + 6];
            int objRefSize    = data[trailerStart + 7];
            long numObjects   = ReadIntBE(data, trailerStart + 8, 8);
            long topObject    = ReadIntBE(data, trailerStart + 16, 8);
            long offsetTableOffset = ReadIntBE(data, trailerStart + 24, 8);

            var offsets = new long[numObjects];
            for (int i = 0; i < numObjects; i++)
                offsets[i] = ReadIntBE(data, (int)(offsetTableOffset + i * offsetIntSize), offsetIntSize);

            var parsed = new object[numObjects];
            for (int i = 0; i < numObjects; i++)
                parsed[i] = DecodeObject(data, (int)offsets[i], objRefSize, offsets, parsed);

            return parsed[topObject] as Dictionary<string, object>;
        }

        private static object DecodeObject(byte[] data, int offset, int refSize,
            long[] offsets, object[] parsed)
        {
            byte marker = data[offset];
            int high = (marker >> 4) & 0x0F;
            int low  = marker & 0x0F;

            switch (high)
            {
                case 0x0: // null, bool, fill
                    return marker == 0x09;

                case 0x1: // int
                {
                    int byteCount = 1 << low;
                    return ReadIntBE(data, offset + 1, byteCount);
                }

                case 0x2: // real
                {
                    int byteCount = 1 << low;
                    if (byteCount == 4)
                    {
                        var bytes = new byte[4];
                        Array.Copy(data, offset + 1, bytes, 0, 4);
                        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                        return (double)BitConverter.ToSingle(bytes, 0);
                    }
                    else
                    {
                        var bytes = new byte[8];
                        Array.Copy(data, offset + 1, bytes, 0, 8);
                        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                        return BitConverter.ToDouble(bytes, 0);
                    }
                }

                case 0x4: // data (byte[])
                {
                    int count = DecodeCount(data, ref offset, low);
                    var result = new byte[count];
                    Buffer.BlockCopy(data, offset, result, 0, count);
                    return result;
                }

                case 0x5: // ASCII string
                {
                    int count = DecodeCount(data, ref offset, low);
                    return Encoding.ASCII.GetString(data, offset, count);
                }

                case 0x6: // Unicode string
                {
                    int count = DecodeCount(data, ref offset, low);
                    var chars = new char[count];
                    for (int i = 0; i < count; i++)
                        chars[i] = (char)ReadIntBE(data, offset + i * 2, 2);
                    return new string(chars);
                }

                case 0xA: // array
                {
                    int count = DecodeCount(data, ref offset, low);
                    var arr = new object[count];
                    for (int i = 0; i < count; i++)
                    {
                        int idx = (int)ReadIntBE(data, offset + i * refSize, refSize);
                        if (parsed[idx] == null)
                            parsed[idx] = DecodeObject(data, (int)offsets[idx], refSize, offsets, parsed);
                        arr[i] = parsed[idx];
                    }
                    return arr;
                }

                case 0xD: // dict
                {
                    int count = DecodeCount(data, ref offset, low);
                    var dict = new Dictionary<string, object>(count);
                    int keysStart = offset;
                    int valsStart = offset + count * refSize;
                    for (int i = 0; i < count; i++)
                    {
                        int ki = (int)ReadIntBE(data, keysStart + i * refSize, refSize);
                        int vi = (int)ReadIntBE(data, valsStart + i * refSize, refSize);
                        if (parsed[ki] == null)
                            parsed[ki] = DecodeObject(data, (int)offsets[ki], refSize, offsets, parsed);
                        if (parsed[vi] == null)
                            parsed[vi] = DecodeObject(data, (int)offsets[vi], refSize, offsets, parsed);
                        string key = parsed[ki]?.ToString() ?? "";
                        dict[key] = parsed[vi];
                    }
                    return dict;
                }

                default:
                    return marker;
            }
        }

        private static int DecodeCount(byte[] data, ref int offset, int low)
        {
            if (low < 15)
            {
                offset++;
                return low;
            }
            offset++;
            byte sizeMarker = data[offset];
            int sizeBytes = 1 << (sizeMarker & 0x0F);
            offset++;
            int count = (int)ReadIntBE(data, offset, sizeBytes);
            offset += sizeBytes;
            return count;
        }

        private static long ReadIntBE(byte[] data, int offset, int size)
        {
            long val = 0;
            for (int i = 0; i < size && (offset + i) < data.Length; i++)
                val = (val << 8) | data[offset + i];
            return val;
        }

        // ── Encoder ───────────────────────────────────────────────────────────

        public static byte[] Encode(Dictionary<string, object> root)
        {
            var objects = new List<object>();
            Collect(root, objects);

            using var ms = new MemoryStream();

            // Header
            ms.Write(Encoding.ASCII.GetBytes("bplist00"), 0, 8);

            // Write all objects, recording their byte offsets
            var offsets = new long[objects.Count];
            int objRefSize = objects.Count < 256 ? 1 : 2;

            for (int i = 0; i < objects.Count; i++)
            {
                offsets[i] = ms.Position;
                WriteObject(ms, objects[i], objects, objRefSize);
            }

            // Offset table
            long maxOffset = ms.Position;
            int offsetIntSize = maxOffset < 256 ? 1 : maxOffset < 65536 ? 2 : 4;
            long offsetTablePos = ms.Position;

            foreach (long off in offsets)
                WriteIntBE(ms, off, offsetIntSize);

            // 32-byte trailer
            ms.Write(new byte[6], 0, 6);          // padding
            ms.WriteByte(0);                        // sort version
            ms.WriteByte((byte)offsetIntSize);
            ms.WriteByte((byte)objRefSize);
            WriteIntBE(ms, objects.Count, 8);       // num objects
            WriteIntBE(ms, 0, 8);                   // top object index
            WriteIntBE(ms, offsetTablePos, 8);      // offset table offset

            return ms.ToArray();
        }

        // ── object collection ──────────────────────────────────────────────────

        private static void Collect(object obj, List<object> list)
        {
            list.Add(obj);
            if (obj is Dictionary<string, object> dict)
            {
                foreach (var kv in dict)
                {
                    Collect(kv.Key, list);
                    Collect(kv.Value, list);
                }
            }
            else if (obj is object[] arr)
            {
                foreach (var item in arr)
                    Collect(item, list);
            }
        }

        // ── object writing ─────────────────────────────────────────────────────

        private static void WriteObject(Stream s, object obj, List<object> objects, int refSize)
        {
            switch (obj)
            {
                case bool b:
                    s.WriteByte(b ? (byte)0x09 : (byte)0x08);
                    break;

                case long l:
                    WriteIntObject(s, l);
                    break;

                case int i:
                    WriteIntObject(s, i);
                    break;

                case byte[] data:
                    WriteCount(s, 0x40, data.Length);
                    s.Write(data, 0, data.Length);
                    break;

                case string str:
                    var ascii = Encoding.ASCII.GetBytes(str);
                    WriteCount(s, 0x50, str.Length);
                    s.Write(ascii, 0, ascii.Length);
                    break;

                case Dictionary<string, object> dict:
                    WriteCount(s, 0xD0, dict.Count);
                    foreach (var kv in dict)
                        WriteRef(s, objects.IndexOf(kv.Key), refSize);
                    foreach (var kv in dict)
                        WriteRef(s, objects.IndexOf(kv.Value), refSize);
                    break;

                case object[] arr:
                    WriteCount(s, 0xA0, arr.Length);
                    foreach (var item in arr)
                        WriteRef(s, objects.IndexOf(item), refSize);
                    break;
            }
        }

        // Writes the type nibble + count. If count < 15 it fits in the low nibble;
        // otherwise writes 0xXF followed by an int object for the count.
        private static void WriteCount(Stream s, int typeNibble, int count)
        {
            if (count < 15)
            {
                s.WriteByte((byte)(typeNibble | count));
            }
            else
            {
                s.WriteByte((byte)(typeNibble | 0x0F));
                WriteIntObject(s, count);
            }
        }

        private static void WriteIntObject(Stream s, long value)
        {
            if (value <= 0xFF)       { s.WriteByte(0x10); WriteIntBE(s, value, 1); }
            else if (value <= 0xFFFF)   { s.WriteByte(0x11); WriteIntBE(s, value, 2); }
            else if (value <= 0xFFFFFFFF) { s.WriteByte(0x12); WriteIntBE(s, value, 4); }
            else                        { s.WriteByte(0x13); WriteIntBE(s, value, 8); }
        }

        private static void WriteRef(Stream s, int index, int refSize)
            => WriteIntBE(s, index, refSize);

        private static void WriteIntBE(Stream s, long value, int size)
        {
            var b = new byte[size];
            for (int i = size - 1; i >= 0; i--)
            {
                b[i] = (byte)(value & 0xFF);
                value >>= 8;
            }
            s.Write(b, 0, b.Length);
        }
    }
}
