using System;

namespace CloudCast.Crypto
{
    // Modified MD5 with mid-round block swaps.
    //
    // Ported from SteeBono/airplayreceiver (MIT License):
    //   https://github.com/SteeBono/airplayreceiver
    internal class ModifiedMD5
    {
        private static readonly int[] Shift = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        public void Compute(byte[] originalBlockIn, byte[] keyIn, byte[] keyOut)
        {
            var blockIn = new byte[64];
            Array.Copy(originalBlockIn, 0, blockIn, 0, 64);

            long A = ReadInt32LE(keyIn, 0) & 0xffffffffL;
            long B = ReadInt32LE(keyIn, 4) & 0xffffffffL;
            long C = ReadInt32LE(keyIn, 8) & 0xffffffffL;
            long D = ReadInt32LE(keyIn, 12) & 0xffffffffL;

            for (int i = 0; i < 64; i++)
            {
                int j;
                if (i < 16) j = i;
                else if (i < 32) j = (5 * i + 1) % 16;
                else if (i < 48) j = (3 * i + 5) % 16;
                else j = 7 * i % 16;

                int input = ((blockIn[4 * j] & 0xFF) << 24) |
                            ((blockIn[4 * j + 1] & 0xFF) << 16) |
                            ((blockIn[4 * j + 2] & 0xFF) << 8) |
                            (blockIn[4 * j + 3] & 0xFF);

                long Z = A + input + (long)((1L << 32) * Math.Abs(Math.Sin(i + 1)));

                if (i < 16) Z = Rol(Z + ((B & C) | (~B & D)), Shift[i]);
                else if (i < 32) Z = Rol(Z + ((B & D) | (C & ~D)), Shift[i]);
                else if (i < 48) Z = Rol(Z + (B ^ C ^ D), Shift[i]);
                else Z = Rol(Z + (C ^ (B | ~D)), Shift[i]);

                Z += B;
                long tmp = D;
                D = C;
                C = B;
                B = Z;
                A = tmp;

                if (i == 31)
                {
                    Swap(blockIn, 4 * (int)(A & 15), 4 * (int)(B & 15));
                    Swap(blockIn, 4 * (int)(C & 15), 4 * (int)(D & 15));
                    Swap(blockIn, 4 * (int)((A & (15 << 4)) >> 4), 4 * (int)((B & (15 << 4)) >> 4));
                    Swap(blockIn, 4 * (int)((A & (15 << 8)) >> 8), 4 * (int)((B & (15 << 8)) >> 8));
                    Swap(blockIn, 4 * (int)((A & (15 << 12)) >> 12), 4 * (int)((B & (15 << 12)) >> 12));
                }
            }

            WriteInt32LE(keyOut, 0, (int)(ReadInt32LE(keyIn, 0) + A));
            WriteInt32LE(keyOut, 4, (int)(ReadInt32LE(keyIn, 4) + B));
            WriteInt32LE(keyOut, 8, (int)(ReadInt32LE(keyIn, 8) + C));
            WriteInt32LE(keyOut, 12, (int)(ReadInt32LE(keyIn, 12) + D));
        }

        private static long Rol(long input, int count)
            => ((input << count) & 0xffffffffL) | (input & 0xffffffffL) >> (32 - count);

        private static int ReadInt32LE(byte[] data, int offset)
            => data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);

        private static void WriteInt32LE(byte[] data, int offset, int value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        private static void Swap(byte[] arr, int idxA, int idxB)
        {
            if (idxA == idxB) return;
            for (int i = 0; i < 4; i++)
            {
                byte t = arr[idxA + i];
                arr[idxA + i] = arr[idxB + i];
                arr[idxB + i] = t;
            }
        }
    }
}
