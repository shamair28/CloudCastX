using System;
using System.IO;

namespace CloudCast.Crypto
{
    // White-box AES decryption engine for FairPlay session keys.
    //
    // Ported from SteeBono/airplayreceiver (MIT License):
    //   https://github.com/SteeBono/airplayreceiver
    //
    // Decrypts the AES key used for screen-mirroring stream encryption. The key
    // is derived from the FairPlay key message (164 bytes from /fp-setup phase 2)
    // and the encrypted AES key sent in the SETUP request (ekey field).
    internal class OmgHax
    {
        private readonly ModifiedMD5 _modifiedMD5 = new ModifiedMD5();
        private readonly SapHash _sapHash = new SapHash();

        public void DecryptAesKey(byte[] message3, byte[] cipherText, byte[] keyOut)
        {
            var chunk1 = CopyOfRange(cipherText, 16, cipherText.Length);
            var chunk2 = CopyOfRange(cipherText, 56, cipherText.Length);

            var blockIn = new byte[16];
            var sapKey = new byte[16];
            var keySchedule = new int[11][];

            GenerateSessionKey(OmgHaxData.DefaultSap, message3, sapKey);
            GenerateKeySchedule(sapKey, keySchedule);

            ZXor(chunk2, blockIn, 1);
            Cycle(blockIn, keySchedule);

            for (int i = 0; i < 16; i++)
                keyOut[i] = (byte)(blockIn[i] ^ chunk1[i]);

            XXor(keyOut, keyOut, 1);
            ZXor(keyOut, keyOut, 1);
        }

        private void DecryptMessage(byte[] messageIn, byte[] decryptedMessage)
        {
            var buffer = new byte[16];
            byte tmp;
            int mode = messageIn[12];

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    if (mode == 3)
                        buffer[j] = messageIn[(0x80 - 0x10 * i) + j];
                    else
                        buffer[j] = messageIn[(0x10 * (i + 1)) + j];
                }

                for (int j = 0; j < 9; j++)
                {
                    int @base = 0x80 - 0x10 * j;

                    buffer[0x0] = (byte)(MessageTableIndex(@base + 0x0)[buffer[0x0] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x0]);
                    buffer[0x4] = (byte)(MessageTableIndex(@base + 0x4)[buffer[0x4] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x4]);
                    buffer[0x8] = (byte)(MessageTableIndex(@base + 0x8)[buffer[0x8] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x8]);
                    buffer[0xc] = (byte)(MessageTableIndex(@base + 0xc)[buffer[0xc] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xc]);

                    tmp = buffer[0x0d];
                    buffer[0xd] = (byte)(MessageTableIndex(@base + 0xd)[buffer[0x9] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xd]);
                    buffer[0x9] = (byte)(MessageTableIndex(@base + 0x9)[buffer[0x5] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x9]);
                    buffer[0x5] = (byte)(MessageTableIndex(@base + 0x5)[buffer[0x1] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x5]);
                    buffer[0x1] = (byte)(MessageTableIndex(@base + 0x1)[tmp & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x1]);

                    tmp = buffer[0x02];
                    buffer[0x2] = (byte)(MessageTableIndex(@base + 0x2)[buffer[0xa] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x2]);
                    buffer[0xa] = (byte)(MessageTableIndex(@base + 0xa)[tmp & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xa]);
                    tmp = buffer[0x06];
                    buffer[0x6] = (byte)(MessageTableIndex(@base + 0x6)[buffer[0xe] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x6]);
                    buffer[0xe] = (byte)(MessageTableIndex(@base + 0xe)[tmp & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xe]);

                    tmp = buffer[0x3];
                    buffer[0x3] = (byte)(MessageTableIndex(@base + 0x3)[buffer[0x7] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x3]);
                    buffer[0x7] = (byte)(MessageTableIndex(@base + 0x7)[buffer[0xb] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0x7]);
                    buffer[0xb] = (byte)(MessageTableIndex(@base + 0xb)[buffer[0xf] & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xb]);
                    buffer[0xf] = (byte)(MessageTableIndex(@base + 0xf)[tmp & 0xFF] ^ OmgHaxData.MessageKey[mode][@base + 0xf]);

                    WriteInt32LE(buffer, 0, OmgHaxData.TableS9[0x000 + (buffer[0x0] & 0xFF)] ^
                            OmgHaxData.TableS9[0x100 + (buffer[0x1] & 0xFF)] ^
                            OmgHaxData.TableS9[0x200 + (buffer[0x2] & 0xFF)] ^
                            OmgHaxData.TableS9[0x300 + (buffer[0x3] & 0xFF)]);
                    WriteInt32LE(buffer, 4, OmgHaxData.TableS9[0x000 + (buffer[0x4] & 0xFF)] ^
                            OmgHaxData.TableS9[0x100 + (buffer[0x5] & 0xFF)] ^
                            OmgHaxData.TableS9[0x200 + (buffer[0x6] & 0xFF)] ^
                            OmgHaxData.TableS9[0x300 + (buffer[0x7] & 0xFF)]);
                    WriteInt32LE(buffer, 8, OmgHaxData.TableS9[0x000 + (buffer[0x8] & 0xFF)] ^
                            OmgHaxData.TableS9[0x100 + (buffer[0x9] & 0xFF)] ^
                            OmgHaxData.TableS9[0x200 + (buffer[0xa] & 0xFF)] ^
                            OmgHaxData.TableS9[0x300 + (buffer[0xb] & 0xFF)]);
                    WriteInt32LE(buffer, 12, OmgHaxData.TableS9[0x000 + (buffer[0xc] & 0xFF)] ^
                            OmgHaxData.TableS9[0x100 + (buffer[0xd] & 0xFF)] ^
                            OmgHaxData.TableS9[0x200 + (buffer[0xe] & 0xFF)] ^
                            OmgHaxData.TableS9[0x300 + (buffer[0xf] & 0xFF)]);
                }

                buffer[0x0] = OmgHaxData.TableS10[(0x0 << 8) + (buffer[0x0] & 0xFF)];
                buffer[0x4] = OmgHaxData.TableS10[(0x4 << 8) + (buffer[0x4] & 0xFF)];
                buffer[0x8] = OmgHaxData.TableS10[(0x8 << 8) + (buffer[0x8] & 0xFF)];
                buffer[0xc] = OmgHaxData.TableS10[(0xc << 8) + (buffer[0xc] & 0xFF)];

                tmp = buffer[0x0d];
                buffer[0xd] = OmgHaxData.TableS10[(0xd << 8) + (buffer[0x9] & 0xFF)];
                buffer[0x9] = OmgHaxData.TableS10[(0x9 << 8) + (buffer[0x5] & 0xFF)];
                buffer[0x5] = OmgHaxData.TableS10[(0x5 << 8) + (buffer[0x1] & 0xFF)];
                buffer[0x1] = OmgHaxData.TableS10[(0x1 << 8) + (tmp & 0xFF)];

                tmp = buffer[0x02];
                buffer[0x2] = OmgHaxData.TableS10[(0x2 << 8) + (buffer[0xa] & 0xFF)];
                buffer[0xa] = OmgHaxData.TableS10[(0xa << 8) + (tmp & 0xFF)];
                tmp = buffer[0x06];
                buffer[0x6] = OmgHaxData.TableS10[(0x6 << 8) + (buffer[0xe] & 0xFF)];
                buffer[0xe] = OmgHaxData.TableS10[(0xe << 8) + (tmp & 0xFF)];

                tmp = buffer[0x3];
                buffer[0x3] = OmgHaxData.TableS10[(0x3 << 8) + (buffer[0x7] & 0xFF)];
                buffer[0x7] = OmgHaxData.TableS10[(0x7 << 8) + (buffer[0xb] & 0xFF)];
                buffer[0xb] = OmgHaxData.TableS10[(0xb << 8) + (buffer[0xf] & 0xFF)];
                buffer[0xf] = OmgHaxData.TableS10[(0xf << 8) + (tmp & 0xFF)];

                var xorResult = new byte[16];
                if (mode == 2 || mode == 1 || mode == 0)
                {
                    if (i > 0)
                    {
                        XorBlocks(buffer, CopyOfRange(messageIn, 0x10 * i, 0x10 * i + 16), xorResult);
                        Array.Copy(xorResult, 0, decryptedMessage, 0x10 * i, 16);
                    }
                    else
                    {
                        XorBlocks(buffer, OmgHaxData.MessageIv[mode], xorResult);
                        Array.Copy(xorResult, 0, decryptedMessage, 0x10 * i, 16);
                    }
                }
                else
                {
                    if (i < 7)
                    {
                        XorBlocks(buffer, CopyOfRange(messageIn, 0x70 - 0x10 * i, (0x70 - 0x10 * i) + 16), xorResult);
                        Array.Copy(xorResult, 0, decryptedMessage, 0x70 - 0x10 * i, 16);
                    }
                    else
                    {
                        XorBlocks(buffer, OmgHaxData.MessageIv[mode], xorResult);
                        Array.Copy(xorResult, 0, decryptedMessage, 0x70 - 0x10 * i, 16);
                    }
                }
            }
        }

        private void GenerateKeySchedule(byte[] keyMaterial, int[][] keySchedule)
        {
            var keyData = new int[4];
            var deadbeef = 0xdeadbeef;

            for (int i = 0; i < 11; i++)
                keySchedule[i] = new int[] { (byte)deadbeef, (byte)deadbeef, (byte)deadbeef, (byte)deadbeef };

            var buffer = new byte[16];
            int ti = 0;

            TXor(keyMaterial, buffer);

            for (int i = 0; i < 4; i++)
                keyData[i] = ReadInt32LE(buffer, i * 4);

            for (int round = 0; round < 11; round++)
            {
                keySchedule[round][0] = keyData[0];

                byte[] table1 = TableIndex(ti);
                byte[] table2 = TableIndex(ti + 1);
                byte[] table3 = TableIndex(ti + 2);
                byte[] table4 = TableIndex(ti + 3);
                ti += 4;

                buffer[0] ^= (byte)(table1[buffer[0x0d] & 0xFF] ^ OmgHaxData.IndexMAngle[round]);
                buffer[1] ^= table2[buffer[0x0e] & 0xFF];
                buffer[2] ^= table3[buffer[0x0f] & 0xFF];
                buffer[3] ^= table4[buffer[0x0c] & 0xFF];

                keyData[0] = ReadInt32LE(buffer, 0);
                keySchedule[round][1] = keyData[1];
                keyData[1] ^= keyData[0];

                WriteInt32LE(buffer, 4, keyData[1]);
                keySchedule[round][2] = keyData[2];
                keyData[2] ^= keyData[1];

                WriteInt32LE(buffer, 8, keyData[2]);
                keySchedule[round][3] = keyData[3];
                keyData[3] ^= keyData[2];

                WriteInt32LE(buffer, 12, keyData[3]);
            }
        }

        private void GenerateSessionKey(byte[] oldSap, byte[] messageIn, byte[] sessionKey)
        {
            var decryptedMessage = new byte[128];
            var newSap = new byte[320];
            var md5 = new byte[16];

            DecryptMessage(messageIn, decryptedMessage);

            Array.Copy(OmgHaxData.StaticSource1, 0, newSap, 0, 0x11);
            Array.Copy(decryptedMessage, 0, newSap, 0x11, 0x80);
            Array.Copy(oldSap, 0x80, newSap, 0x091, 0x80);
            Array.Copy(OmgHaxData.StaticSource2, 0, newSap, 0x111, 0x2f);
            Array.Copy(OmgHaxData.InitialSessionKey, 0, sessionKey, 0, 16);

            for (int round = 0; round < 5; round++)
            {
                var block = CopyOfRange(newSap, round * 64, newSap.Length);
                _modifiedMD5.Compute(block, sessionKey, md5);
                _sapHash.Hash(block, sessionKey);

                for (int i = 0; i < 4; i++)
                {
                    int intSess = ReadInt32LE(sessionKey, i * 4);
                    int intMd5 = ReadInt32LE(md5, i * 4);
                    WriteInt32LE(sessionKey, i * 4, (int)((intSess + intMd5) & 0xffffffffL));
                }
            }

            // Byte-swap each 32-bit word
            for (int i = 0; i < 16; i += 4)
            {
                byte t = sessionKey[i];
                sessionKey[i] = sessionKey[i + 3];
                sessionKey[i + 3] = t;
                t = sessionKey[i + 1];
                sessionKey[i + 1] = sessionKey[i + 2];
                sessionKey[i + 2] = t;
            }

            for (int i = 0; i < 16; i++)
                sessionKey[i] ^= 121;
        }

        private void Cycle(byte[] block, int[][] keySchedule)
        {
            XorInt32LE(block, 0, keySchedule[10][0]);
            XorInt32LE(block, 4, keySchedule[10][1]);
            XorInt32LE(block, 8, keySchedule[10][2]);
            XorInt32LE(block, 12, keySchedule[10][3]);

            PermuteBlock1(block);

            for (int round = 0; round < 9; round++)
            {
                var key = new byte[16];
                for (int i = 0; i < 4; i++)
                    WriteInt32LE(key, i * 4, keySchedule[9 - round][i]);

                int ab;
                ab = OmgHaxData.TableS5[(block[3] & 0xff) ^ (key[3] & 0xff)] ^
                     OmgHaxData.TableS6[(block[2] & 0xff) ^ (key[2] & 0xff)] ^
                     OmgHaxData.TableS8[(block[0] & 0xff) ^ (key[0] & 0xff)] ^
                     OmgHaxData.TableS7[(block[1] & 0xff) ^ (key[1] & 0xff)];
                WriteInt32LE(block, 0, ab);

                ab = OmgHaxData.TableS5[(block[7] & 0xff) ^ (key[7] & 0xff)] ^
                     OmgHaxData.TableS6[(block[6] & 0xff) ^ (key[6] & 0xff)] ^
                     OmgHaxData.TableS8[(block[4] & 0xff) ^ (key[4] & 0xff)] ^
                     OmgHaxData.TableS7[(block[5] & 0xff) ^ (key[5] & 0xff)];
                WriteInt32LE(block, 4, ab);

                WriteInt32LE(block, 8,
                    OmgHaxData.TableS5[(block[11] & 0xff) ^ (key[11] & 0xff)] ^
                    OmgHaxData.TableS6[(block[10] & 0xff) ^ (key[10] & 0xff)] ^
                    OmgHaxData.TableS7[(block[9] & 0xff) ^ (key[9] & 0xff)] ^
                    OmgHaxData.TableS8[(block[8] & 0xff) ^ (key[8] & 0xff)]);

                WriteInt32LE(block, 12,
                    OmgHaxData.TableS5[(block[15] & 0xff) ^ (key[15] & 0xff)] ^
                    OmgHaxData.TableS6[(block[14] & 0xff) ^ (key[14] & 0xff)] ^
                    OmgHaxData.TableS7[(block[13] & 0xff) ^ (key[13] & 0xff)] ^
                    OmgHaxData.TableS8[(block[12] & 0xff) ^ (key[12] & 0xff)]);

                PermuteBlock2(block, 8 - round);
            }

            XorInt32LE(block, 0, keySchedule[0][0]);
            XorInt32LE(block, 4, keySchedule[0][1]);
            XorInt32LE(block, 8, keySchedule[0][2]);
            XorInt32LE(block, 12, keySchedule[0][3]);
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static void XorBlocks(byte[] a, byte[] b, byte[] output)
        {
            for (int i = 0; i < 16; i++)
                output[i] = (byte)(a[i] ^ b[i]);
        }

        private static void ZXor(byte[] input, byte[] output, int blocks)
        {
            for (int j = 0; j < blocks; j++)
                for (int i = 0; i < 16; i++)
                    output[j * 16 + i] = (byte)(input[j * 16 + i] ^ OmgHaxData.ZKey[i]);
        }

        private static void XXor(byte[] input, byte[] output, int blocks)
        {
            for (int j = 0; j < blocks; j++)
                for (int i = 0; i < 16; i++)
                    output[j * 16 + i] = (byte)(input[j * 16 + i] ^ OmgHaxData.XKey[i]);
        }

        private static void TXor(byte[] input, byte[] output)
        {
            for (int i = 0; i < 16; i++)
                output[i] = (byte)(input[i] ^ OmgHaxData.TKey[i]);
        }

        private static byte[] TableIndex(int i)
            => CopyOfRange(OmgHaxData.TableS1, ((31 * i) % 0x28) << 8, OmgHaxData.TableS1.Length);

        private static byte[] MessageTableIndex(int i)
            => CopyOfRange(OmgHaxData.TableS2, (97 * i % 144) << 8, OmgHaxData.TableS2.Length);

        private static void PermuteBlock1(byte[] block)
        {
            block[0] = OmgHaxData.TableS3[block[0] & 0xff];
            block[4] = OmgHaxData.TableS3[0x400 + (block[4] & 0xff)];
            block[8] = OmgHaxData.TableS3[0x800 + (block[8] & 0xff)];
            block[12] = OmgHaxData.TableS3[0xc00 + (block[12] & 0xff)];

            byte tmp = block[13];
            block[13] = OmgHaxData.TableS3[0x100 + (block[9] & 0xff)];
            block[9] = OmgHaxData.TableS3[0xd00 + (block[5] & 0xff)];
            block[5] = OmgHaxData.TableS3[0x900 + (block[1] & 0xff)];
            block[1] = OmgHaxData.TableS3[0x500 + (tmp & 0xff)];

            tmp = block[2];
            block[2] = OmgHaxData.TableS3[0xa00 + (block[10] & 0xff)];
            block[10] = OmgHaxData.TableS3[0x200 + (tmp & 0xff)];
            tmp = block[6];
            block[6] = OmgHaxData.TableS3[0xe00 + (block[14] & 0xff)];
            block[14] = OmgHaxData.TableS3[0x600 + (tmp & 0xff)];

            tmp = block[3];
            block[3] = OmgHaxData.TableS3[0xf00 + (block[7] & 0xff)];
            block[7] = OmgHaxData.TableS3[0x300 + (block[11] & 0xff)];
            block[11] = OmgHaxData.TableS3[0x700 + (block[15] & 0xff)];
            block[15] = OmgHaxData.TableS3[0xb00 + (tmp & 0xff)];
        }

        private static byte[] PermuteTable2(int i)
            => CopyOfRange(OmgHaxData.TableS4, ((71 * i) % 144) << 8, OmgHaxData.TableS4.Length);

        private static void PermuteBlock2(byte[] block, int round)
        {
            block[0] = PermuteTable2(round * 16 + 0)[(block[0] & 0xff)];
            block[4] = PermuteTable2(round * 16 + 4)[(block[4] & 0xff)];
            block[8] = PermuteTable2(round * 16 + 8)[(block[8] & 0xff)];
            block[12] = PermuteTable2(round * 16 + 12)[(block[12] & 0xff)];

            byte tmp = block[13];
            block[13] = PermuteTable2(round * 16 + 13)[(block[9] & 0xff)];
            block[9] = PermuteTable2(round * 16 + 9)[(block[5] & 0xff)];
            block[5] = PermuteTable2(round * 16 + 5)[(block[1] & 0xff)];
            block[1] = PermuteTable2(round * 16 + 1)[(tmp & 0xff)];

            tmp = block[2];
            block[2] = PermuteTable2(round * 16 + 2)[(block[10] & 0xff)];
            block[10] = PermuteTable2(round * 16 + 10)[(tmp & 0xff)];
            tmp = block[6];
            block[6] = PermuteTable2(round * 16 + 6)[(block[14] & 0xff)];
            block[14] = PermuteTable2(round * 16 + 14)[(tmp & 0xff)];

            tmp = block[3];
            block[3] = PermuteTable2(round * 16 + 3)[(block[7] & 0xff)];
            block[7] = PermuteTable2(round * 16 + 7)[(block[11] & 0xff)];
            block[11] = PermuteTable2(round * 16 + 11)[(block[15] & 0xff)];
            block[15] = PermuteTable2(round * 16 + 15)[(tmp & 0xff)];
        }

        private static byte[] CopyOfRange(byte[] src, int start, int end)
        {
            int len = end - start;
            var dest = new byte[len];
            Array.Copy(src, start, dest, 0, len);
            return dest;
        }

        private static int ReadInt32LE(byte[] data, int offset)
            => data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);

        private static void WriteInt32LE(byte[] data, int offset, int value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        private static void XorInt32LE(byte[] data, int offset, int value)
        {
            int current = ReadInt32LE(data, offset);
            WriteInt32LE(data, offset, current ^ value);
        }
    }
}
