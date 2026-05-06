using System;

namespace CloudCast.Crypto
{
    // Custom hash function combining LFSR + HandGarble.
    //
    // Ported from SteeBono/airplayreceiver (MIT License):
    //   https://github.com/SteeBono/airplayreceiver
    internal class SapHash
    {
        private readonly HandGarble _handGarble = new HandGarble();

        public void Hash(byte[] blockIn, byte[] keyOut)
        {
            var buffer0 = new byte[] {
                0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18,
                0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC, 0x22,
                0x03, 0xD1, 0x20, 0x8F
            };
            var buffer1 = new byte[210];
            var buffer2 = new byte[] {
                0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3,
                0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D,
                0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA,
                0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20,
                0x9D, 0x42, 0x3A
            };
            var buffer3 = new byte[132];
            var buffer4 = new byte[] {
                0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02,
                0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52, 0xC0,
                0xBD, 0xE3, 0x1B, 0x49, 0xC7
            };
            var i0Index = new int[] { 18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30 };

            for (int i = 0; i < 210; i++)
            {
                int wordOffset = ((i % 64) >> 2) * 4;
                int inWord = (blockIn[wordOffset] << 24) |
                             (blockIn[wordOffset + 1] << 16) |
                             (blockIn[wordOffset + 2] << 8) |
                             blockIn[wordOffset + 3];
                buffer1[i] = (byte)((inWord >> ((3 - (i % 4)) << 3)) & 0xff);
            }

            for (int i = 0; i < 840; i++)
            {
                byte x = buffer1[(int)(((i - 155) & 0xffffffffL) % 210)];
                byte y = buffer1[(int)(((i - 57) & 0xffffffffL) % 210)];
                byte z = buffer1[(int)(((i - 13) & 0xffffffffL) % 210)];
                byte w = buffer1[(int)((i & 0xffffffffL) % 210)];
                buffer1[i % 210] = (byte)((Rol8(y, 5) + (Rol8(z, 3) ^ w) - Rol8(x, 7)) & 0xff);
            }

            _handGarble.Garble(buffer0, buffer1, buffer2, buffer3, buffer4);

            for (int i = 0; i < 16; i++)
                keyOut[i] = 0xE1;

            for (int i = 0; i < 11; i++)
            {
                if (i == 3)
                    keyOut[i] = 0x3d;
                else
                    keyOut[i] = (byte)((keyOut[i] + buffer3[i0Index[i] * 4]) & 0xff);
            }

            for (int i = 0; i < 20; i++)
                keyOut[i % 16] ^= buffer0[i];

            for (int i = 0; i < 35; i++)
                keyOut[i % 16] ^= buffer2[i];

            for (int i = 0; i < 210; i++)
                keyOut[i % 16] ^= buffer1[i];

            for (int j = 0; j < 16; j++)
            {
                for (int i = 0; i < 16; i++)
                {
                    byte xv = keyOut[(int)(((i - 7) & 0xffffffffL) % 16)];
                    byte yv = keyOut[i % 16];
                    byte zv = keyOut[(int)(((i - 37) & 0xffffffffL) % 16)];
                    byte wv = keyOut[(int)(((i - 177) & 0xffffffffL) % 16)];
                    keyOut[i] = (byte)(Rol8(xv, 1) ^ yv ^ Rol8(zv, 6) ^ Rol8(wv, 5));
                }
            }
        }

        private static byte Rol8(byte input, int count)
            => (byte)(((input << count) & 0xff) | (input & 0xff) >> (8 - count));
    }
}
