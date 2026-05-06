using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CloudCast.Crypto;
using Windows.Media.Core;
using Windows.Media.MediaProperties;
using Windows.Media.Playback;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Controls;
using SysBuffer = System.Buffer;

namespace CloudCast.Services
{
    // Receives an H.264 screen-mirroring stream over RTP (UDP) and renders it via
    // MediaPlayerElement using a MediaStreamSource for live/no-seek playback.
    //
    // Stream decryption ported from SteeBono/airplayreceiver (MIT License):
    //   https://github.com/SteeBono/airplayreceiver
    internal class MirroringSession
    {
        private readonly MediaPlayerElement _player;
        private DatagramSocket? _rtp;
        private MediaStreamSource? _mss;
        private FrameQueue _frames = new FrameQueue();
        private CancellationTokenSource _cts = new CancellationTokenSource();

        // AES-CTR decryption state
        private byte[]? _decryptKey;
        private byte[]? _decryptIv;
        private bool _decryptionReady;

        public ushort VideoPort { get; private set; }

        public MirroringSession(MediaPlayerElement player) => _player = player;

        public async Task StartAsync(uint width, uint height,
            byte[]? keyMsg = null, byte[]? encryptedAesKey = null,
            byte[]? aesIv = null, byte[]? ecdhShared = null,
            string? streamConnectionId = null)
        {
            await InitDecryptionAsync(keyMsg, encryptedAesKey, aesIv, ecdhShared, streamConnectionId);

            _rtp = new DatagramSocket();
            _rtp.MessageReceived += OnRtpMessage;
            await _rtp.BindServiceNameAsync("0");
            VideoPort = ushort.Parse(_rtp.Information.LocalPort);

            var videoProps = VideoEncodingProperties.CreateH264();
            videoProps.Width  = width;
            videoProps.Height = height;

            _mss = new MediaStreamSource(new VideoStreamDescriptor(videoProps))
            {
                BufferTime = TimeSpan.Zero,
                CanSeek    = false,
                Duration   = TimeSpan.Zero,
            };
            _mss.Starting        += OnStarting;
            _mss.SampleRequested += OnSampleRequested;

            _player.Source = MediaSource.CreateFromMediaStreamSource(_mss);
        }

        private async Task InitDecryptionAsync(
            byte[]? keyMsg, byte[]? encryptedAesKey, byte[]? aesIv,
            byte[]? ecdhShared, string? streamConnectionId)
        {
            if (keyMsg == null || encryptedAesKey == null || ecdhShared == null)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[Mirroring] Missing crypto state — stream will not be decrypted");
                return;
            }

            try
            {
                if (!OmgHaxData.IsLoaded)
                    await OmgHaxData.LoadTablesAsync();

                var omgHax = new OmgHax();
                var decryptedAesKey = new byte[16];
                omgHax.DecryptAesKey(keyMsg, encryptedAesKey, decryptedAesKey);

                // Derive stream key: SHA-512(decryptedAesKey || ecdhShared) → first 16 bytes
                byte[] eaesKey = Sha512Concat(decryptedAesKey, ecdhShared);

                string connId = streamConnectionId ?? "";
                byte[] streamKeyInput = Encoding.UTF8.GetBytes($"AirPlayStreamKey{connId}");
                byte[] hash1 = Sha512Concat(streamKeyInput, Take(eaesKey, 16));

                byte[] streamIvInput = Encoding.UTF8.GetBytes($"AirPlayStreamIV{connId}");
                byte[] hash2 = Sha512Concat(streamIvInput, Take(eaesKey, 16));

                _decryptKey = Take(hash1, 16);
                _decryptIv  = Take(hash2, 16);
                _decryptionReady = true;

                System.Diagnostics.Debug.WriteLine("[Mirroring] AES-CTR decryption initialized");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[Mirroring] Decryption init failed: {ex.Message}");
            }
        }

        public void Stop()
        {
            _cts.Cancel();
            _player.Source = null;
            _rtp?.Dispose();
            _mss = null;
        }

        // ── MediaStreamSource callbacks ───────────────────────────────────────

        private void OnStarting(MediaStreamSource s, MediaStreamSourceStartingEventArgs e)
            => e.Request.SetActualStartPosition(TimeSpan.Zero);

        private void OnSampleRequested(MediaStreamSource s, MediaStreamSourceSampleRequestedEventArgs e)
        {
            var deferral = e.Request.GetDeferral();
            _ = DeliverSampleAsync(e.Request, deferral);
        }

        private async Task DeliverSampleAsync(
            Windows.Media.Core.MediaStreamSourceSampleRequest req,
            Windows.Media.Core.MediaStreamSourceSampleRequestDeferral deferral)
        {
            try
            {
                var frame = await _frames.DequeueAsync(_cts.Token);
                if (frame != null)
                    req.Sample = MediaStreamSample.CreateFromBuffer(
                        frame.Data.AsBuffer(), frame.Pts);
            }
            catch (OperationCanceledException) { /* session stopped */ }
            finally { deferral.Complete(); }
        }

        // ── RTP receiver ──────────────────────────────────────────────────────

        private void OnRtpMessage(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs e)
        {
            try
            {
                using var dr = e.GetDataReader();
                uint len = dr.UnconsumedBufferLength;
                if (len < 12) return;

                byte b0 = dr.ReadByte();
                byte b1 = dr.ReadByte();
                dr.ReadByte(); dr.ReadByte();
                uint ts  = ReadUInt32(dr);
                ReadUInt32(dr);

                int cc = b0 & 0x0F;
                for (int i = 0; i < cc && dr.UnconsumedBufferLength >= 4; i++)
                    ReadUInt32(dr);

                if ((b0 & 0x10) != 0 && dr.UnconsumedBufferLength >= 4)
                {
                    ReadUInt16(dr);
                    int extLen = ReadUInt16(dr);
                    for (int i = 0; i < extLen && dr.UnconsumedBufferLength >= 4; i++)
                        ReadUInt32(dr);
                }

                if (dr.UnconsumedBufferLength == 0) return;

                byte[] payload = new byte[dr.UnconsumedBufferLength];
                dr.ReadBytes(payload);

                if (_decryptionReady)
                    payload = DecryptPayload(payload);

                foreach (var nalu in ParseNalus(payload))
                    _frames.Enqueue(new VideoFrame
                    {
                        Data = WrapAnnexB(nalu),
                        Pts  = TimeSpan.FromSeconds(ts / 90000.0),
                    });
            }
            catch { /* ignore malformed packets */ }
        }

        // ── AES-CTR decryption ───────────────────────────────────────────────

        private byte[] DecryptPayload(byte[] data)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = _decryptKey!;

                var counter = (byte[])_decryptIv!.Clone();
                var output = new byte[data.Length];
                var block = new byte[16];

                using var encryptor = aes.CreateEncryptor();
                int fullBlocks = data.Length / 16;

                for (int i = 0; i < fullBlocks; i++)
                {
                    encryptor.TransformBlock(counter, 0, 16, block, 0);
                    for (int j = 0; j < 16; j++)
                        output[i * 16 + j] = (byte)(data[i * 16 + j] ^ block[j]);
                    IncrementCounter(counter);
                }

                int remainder = data.Length % 16;
                if (remainder > 0)
                {
                    encryptor.TransformBlock(counter, 0, 16, block, 0);
                    int offset = fullBlocks * 16;
                    for (int j = 0; j < remainder; j++)
                        output[offset + j] = (byte)(data[offset + j] ^ block[j]);
                }

                return output;
            }
            catch
            {
                return data;
            }
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
        }

        // ── RFC 6184 H.264 RTP payload parsing ───────────────────────────────

        private static IEnumerable<byte[]> ParseNalus(byte[] payload)
        {
            if (payload.Length == 0) yield break;

            byte naluType = (byte)(payload[0] & 0x1F);

            if (naluType >= 1 && naluType <= 23)
            {
                yield return payload;
            }
            else if (naluType == 24)
            {
                int i = 1;
                while (i + 2 <= payload.Length)
                {
                    int size = (payload[i] << 8) | payload[i + 1];
                    i += 2;
                    if (i + size > payload.Length) break;
                    var nalu = new byte[size];
                    SysBuffer.BlockCopy(payload, i, nalu, 0, size);
                    yield return nalu;
                    i += size;
                }
            }
            else if (naluType == 28)
            {
                byte fuHeader = payload[1];
                bool start = (fuHeader & 0x80) != 0;
                byte nal1  = (byte)((payload[0] & 0xE0) | (fuHeader & 0x1F));

                if (start)
                {
                    var frag = new byte[1 + payload.Length - 2];
                    frag[0] = nal1;
                    SysBuffer.BlockCopy(payload, 2, frag, 1, payload.Length - 2);
                    yield return frag;
                }
            }
        }

        private static byte[] WrapAnnexB(byte[] nalu)
        {
            var r = new byte[4 + nalu.Length];
            r[2] = 0x00; r[3] = 0x01;
            SysBuffer.BlockCopy(nalu, 0, r, 4, nalu.Length);
            return r;
        }

        // ── Crypto helpers ───────────────────────────────────────────────────

        private static byte[] Sha512Concat(byte[] a, byte[] b)
        {
            using var sha = SHA512.Create();
            var combined = new byte[a.Length + b.Length];
            SysBuffer.BlockCopy(a, 0, combined, 0, a.Length);
            SysBuffer.BlockCopy(b, 0, combined, a.Length, b.Length);
            return sha.ComputeHash(combined);
        }

        private static byte[] Take(byte[] src, int count)
        {
            var result = new byte[count];
            SysBuffer.BlockCopy(src, 0, result, 0, count);
            return result;
        }

        private static uint   ReadUInt32(DataReader dr) =>
            ((uint)dr.ReadByte() << 24) | ((uint)dr.ReadByte() << 16) |
            ((uint)dr.ReadByte() << 8)  |  dr.ReadByte();

        private static int ReadUInt16(DataReader dr) =>
            (dr.ReadByte() << 8) | dr.ReadByte();
    }

    // ── Supporting types ──────────────────────────────────────────────────────

    internal sealed class VideoFrame
    {
        public byte[]    Data = null!;
        public TimeSpan  Pts;
    }

    internal sealed class FrameQueue
    {
        private readonly SemaphoreSlim       _sem   = new SemaphoreSlim(0, int.MaxValue);
        private readonly Queue<VideoFrame>   _q     = new Queue<VideoFrame>();
        private readonly object              _lock  = new object();

        public void Enqueue(VideoFrame f)
        {
            lock (_lock) _q.Enqueue(f);
            _sem.Release();
        }

        public async Task<VideoFrame?> DequeueAsync(CancellationToken ct)
        {
            await _sem.WaitAsync(ct);
            lock (_lock) return _q.Count > 0 ? _q.Dequeue() : null;
        }
    }
}
