using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CloudCast.Crypto;
using Windows.Media.Core;
using Windows.Media.MediaProperties;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Controls;
using SysBuffer = System.Buffer;

namespace CloudCast.Services
{
    // Receives the AirPlay screen-mirroring stream and renders it via
    // MediaPlayerElement using a MediaStreamSource.
    //
    // Transport: the sender opens a TCP connection to VideoPort (the dataPort we
    // return in SETUP #2 for stream type 110) and sends framed packets:
    //   [128-byte header][payload]
    //     header[0..3]   payload size  (uint32, little-endian)
    //     header[4..5]   payload type  (uint16 LE; & 0xFF → 0=video, 1=codec data, 2=heartbeat)
    //     header[8..15]  NTP timestamp (uint64, little-endian)
    // Type-0 payloads are AES-128-CTR encrypted (keystream runs CONTINUOUSLY
    // across packets) and contain H.264 in AVCC framing (4-byte big-endian NALU
    // lengths). Type-1 payloads are an unencrypted avcC record with SPS/PPS.
    //
    // Protocol and key derivation ported from SteeBono/airplayreceiver and
    // RPiPlay (both MIT License).
    internal class MirroringSession
    {
        private const int MaxPayloadSize = 8 * 1024 * 1024;
        private const int MaxQueuedFrames = 120;

        private readonly MediaPlayerElement _player;
        private StreamSocketListener? _listener;
        private MediaStreamSource? _mss;
        private readonly FrameQueue _frames = new FrameQueue();
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        // AES-CTR decryption state — keystream position persists across packets
        private Aes? _aes;
        private ICryptoTransform? _ecb;
        private byte[]? _counter;
        private readonly byte[] _keystream = new byte[16];
        private int _keystreamOffset = 16; // 16 = exhausted, generate next block
        private bool _decryptionReady;

        // SPS/PPS (Annex B) from the most recent codec-data packet
        private byte[]? _spsPps;
        private bool _spsPpsPending;

        // PTS bookkeeping
        private double _baseSeconds = -1;
        private TimeSpan _lastPts = TimeSpan.MinValue;
        private long _frameCounter;
        private bool _playbackStarted;

        public ushort VideoPort { get; private set; }

        // Raised when the sender actually opens its mirror data connection
        public event Action? SenderConnected;

        public MirroringSession(MediaPlayerElement player) => _player = player;

        // Bind the mirror TCP listener during SETUP #2 so its port can be
        // returned as dataPort. iOS connects here right after RECORD.
        public async Task BindTcpAsync()
        {
            if (_listener != null) return;
            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnMirrorConnection;
            try
            {
                await _listener.BindServiceNameAsync(AirPlayConfig.MirrorDataPort.ToString());
            }
            catch
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[Mirroring] Port {AirPlayConfig.MirrorDataPort} unavailable — falling back to ephemeral");
                _listener.Dispose();
                _listener = new StreamSocketListener();
                _listener.ConnectionReceived += OnMirrorConnection;
                await _listener.BindServiceNameAsync("0");
            }
            VideoPort = ushort.Parse(_listener.Information.LocalPort);
            System.Diagnostics.Debug.WriteLine($"[Mirroring] TCP listener bound on port {VideoPort}");
        }

        public async Task ConfigureDecryptionAsync(
            byte[]? keyMsg, byte[]? encryptedAesKey,
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

                // eaesKey = SHA-512(decryptedAesKey || ecdhShared), first 16 bytes used
                byte[] eaesKey = Sha512Concat(decryptedAesKey, ecdhShared);

                string connId = streamConnectionId ?? "";
                byte[] key = Take(Sha512Concat(
                    Encoding.UTF8.GetBytes("AirPlayStreamKey" + connId), Take(eaesKey, 16)), 16);
                byte[] iv = Take(Sha512Concat(
                    Encoding.UTF8.GetBytes("AirPlayStreamIV" + connId), Take(eaesKey, 16)), 16);

                _aes = Aes.Create();
                _aes.Mode = CipherMode.ECB;
                _aes.Padding = PaddingMode.None;
                _aes.Key = key;
                _ecb = _aes.CreateEncryptor();
                _counter = (byte[])iv.Clone();
                _keystreamOffset = 16;
                _decryptionReady = true;

                System.Diagnostics.Debug.WriteLine(
                    $"[Mirroring] AES-CTR decryption initialized (connId='{connId}')");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[Mirroring] Decryption init failed: {ex.Message}");
            }
        }

        public async Task StartPlaybackAsync()
        {
            if (_playbackStarted) return;
            _playbackStarted = true;

            var videoProps = VideoEncodingProperties.CreateH264();
            videoProps.Width = 1920;
            videoProps.Height = 1080;

            _mss = new MediaStreamSource(new VideoStreamDescriptor(videoProps))
            {
                BufferTime = TimeSpan.Zero,
                CanSeek = false,
                Duration = TimeSpan.Zero,
            };
            _mss.Starting += OnStarting;
            _mss.SampleRequested += OnSampleRequested;

            await _player.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                _player.Source = MediaSource.CreateFromMediaStreamSource(_mss);
            });
        }

        public async Task StopAsync()
        {
            _cts.Cancel();
            try
            {
                await _player.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                    _player.Source = null);
            }
            catch { /* dispatcher may be gone during shutdown */ }
            _listener?.Dispose();
            _listener = null;
            _mss = null;
            _ecb?.Dispose();
            _aes?.Dispose();
            VideoPort = 0;
        }

        // ── Mirror TCP connection ─────────────────────────────────────────────

        private async void OnMirrorConnection(StreamSocketListener sender,
            StreamSocketListenerConnectionReceivedEventArgs args)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[Mirroring] Sender connected from {args.Socket.Information.RemoteAddress.DisplayName}");
            SenderConnected?.Invoke();

            try
            {
                using var socket = args.Socket;
                // InputStreamOptions.None: LoadAsync completes only when the full
                // requested count is available (or the stream ends) — exact reads.
                var reader = new DataReader(socket.InputStream)
                {
                    InputStreamOptions = InputStreamOptions.None
                };

                var header = new byte[128];
                while (!_cts.IsCancellationRequested)
                {
                    await reader.LoadAsync(128);
                    if (reader.UnconsumedBufferLength < 128) break; // stream ended
                    reader.ReadBytes(header);

                    uint payloadSize = (uint)(header[0] | (header[1] << 8) |
                                              (header[2] << 16) | (header[3] << 24));
                    int payloadType = header[4]; // low byte of LE uint16
                    ulong ntp = ReadUInt64LE(header, 8);

                    if (payloadSize > MaxPayloadSize)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"[Mirroring] Bogus payload size {payloadSize} — desynced, closing");
                        break;
                    }

                    byte[] payload = Array.Empty<byte>();
                    if (payloadSize > 0)
                    {
                        await reader.LoadAsync(payloadSize);
                        if (reader.UnconsumedBufferLength < payloadSize) break;
                        payload = new byte[payloadSize];
                        reader.ReadBytes(payload);
                    }

                    switch (payloadType)
                    {
                        case 0: HandleVideoPayload(payload, ntp); break;
                        case 1: HandleCodecData(payload); break;
                        default: break; // 2 = heartbeat, others ignored
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Mirroring] Data connection error: {ex.Message}");
            }
            System.Diagnostics.Debug.WriteLine("[Mirroring] Sender data connection closed");
        }

        // Type 0: AES-CTR encrypted AVCC H.264 — one or more [len:4 BE][NALU]
        private void HandleVideoPayload(byte[] payload, ulong ntp)
        {
            if (payload.Length == 0) return;

            if (_decryptionReady)
                CtrTransform(payload); // in-place; keystream continues across packets

            // AVCC → Annex B
            var frame = new List<byte>(payload.Length + 64);
            bool keyFrame = false;
            int i = 0;
            while (i + 4 <= payload.Length)
            {
                int nalLen = (payload[i] << 24) | (payload[i + 1] << 16) |
                             (payload[i + 2] << 8) | payload[i + 3];
                i += 4;
                if (nalLen <= 0 || i + nalLen > payload.Length) break;

                int nalType = payload[i] & 0x1F;
                if (nalType == 5) keyFrame = true;

                frame.Add(0); frame.Add(0); frame.Add(0); frame.Add(1);
                frame.AddRange(new ArraySegment<byte>(payload, i, nalLen));
                i += nalLen;
            }
            if (frame.Count == 0) return;

            byte[] data;
            if (_spsPpsPending && _spsPps != null)
            {
                data = new byte[_spsPps.Length + frame.Count];
                SysBuffer.BlockCopy(_spsPps, 0, data, 0, _spsPps.Length);
                frame.CopyTo(data, _spsPps.Length);
                _spsPpsPending = false;
                keyFrame = true;
            }
            else
            {
                data = frame.ToArray();
            }

            _frames.Enqueue(new VideoFrame
            {
                Data = data,
                Pts = NtpToPts(ntp),
                KeyFrame = keyFrame,
            }, MaxQueuedFrames);
        }

        // Type 1: unencrypted avcC record — extract SPS/PPS, convert to Annex B,
        // and prepend to the next video frame so the decoder can (re)configure.
        private void HandleCodecData(byte[] payload)
        {
            try
            {
                if (payload.Length < 8) return;
                var outBytes = new List<byte>(payload.Length + 16);

                int i = 5;
                int numSps = payload[i++] & 0x1F;
                for (int s = 0; s < numSps && i + 2 <= payload.Length; s++)
                {
                    int len = (payload[i] << 8) | payload[i + 1];
                    i += 2;
                    if (i + len > payload.Length) return;
                    outBytes.Add(0); outBytes.Add(0); outBytes.Add(0); outBytes.Add(1);
                    outBytes.AddRange(new ArraySegment<byte>(payload, i, len));
                    i += len;
                }

                if (i >= payload.Length) return;
                int numPps = payload[i++];
                for (int p = 0; p < numPps && i + 2 <= payload.Length; p++)
                {
                    int len = (payload[i] << 8) | payload[i + 1];
                    i += 2;
                    if (i + len > payload.Length) return;
                    outBytes.Add(0); outBytes.Add(0); outBytes.Add(0); outBytes.Add(1);
                    outBytes.AddRange(new ArraySegment<byte>(payload, i, len));
                    i += len;
                }

                _spsPps = outBytes.ToArray();
                _spsPpsPending = true;
                System.Diagnostics.Debug.WriteLine(
                    $"[Mirroring] Codec data: SPS/PPS updated ({_spsPps.Length}B Annex B)");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Mirroring] Codec data parse failed: {ex.Message}");
            }
        }

        private TimeSpan NtpToPts(ulong ntp)
        {
            TimeSpan pts;
            if (ntp == 0)
            {
                pts = TimeSpan.FromSeconds(_frameCounter++ / 60.0);
            }
            else
            {
                double seconds = (ntp >> 32) + (uint)ntp / 4294967296.0;
                if (_baseSeconds < 0) _baseSeconds = seconds;
                pts = TimeSpan.FromSeconds(Math.Max(0, seconds - _baseSeconds));
            }
            if (pts <= _lastPts)
                pts = _lastPts + TimeSpan.FromMilliseconds(1);
            _lastPts = pts;
            return pts;
        }

        // ── AES-CTR (byte-continuous keystream across packets) ────────────────

        private void CtrTransform(byte[] buf)
        {
            for (int i = 0; i < buf.Length; i++)
            {
                if (_keystreamOffset == 16)
                {
                    _ecb!.TransformBlock(_counter!, 0, 16, _keystream, 0);
                    IncrementCounter(_counter!);
                    _keystreamOffset = 0;
                }
                buf[i] ^= _keystream[_keystreamOffset++];
            }
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
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
            MediaStreamSourceSampleRequest req,
            MediaStreamSourceSampleRequestDeferral deferral)
        {
            try
            {
                var frame = await _frames.DequeueAsync(_cts.Token);
                if (frame != null)
                {
                    var sample = MediaStreamSample.CreateFromBuffer(frame.Data.AsBuffer(), frame.Pts);
                    sample.KeyFrame = frame.KeyFrame;
                    req.Sample = sample;
                }
            }
            catch (OperationCanceledException) { /* session stopped */ }
            finally { deferral.Complete(); }
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

        private static ulong ReadUInt64LE(byte[] data, int offset)
        {
            ulong v = 0;
            for (int i = 7; i >= 0; i--)
                v = (v << 8) | data[offset + i];
            return v;
        }
    }

    // ── Supporting types ──────────────────────────────────────────────────────

    internal sealed class VideoFrame
    {
        public byte[] Data = null!;
        public TimeSpan Pts;
        public bool KeyFrame;
    }

    internal sealed class FrameQueue
    {
        private readonly SemaphoreSlim _sem = new SemaphoreSlim(0, int.MaxValue);
        private readonly Queue<VideoFrame> _q = new Queue<VideoFrame>();
        private readonly object _lock = new object();

        public void Enqueue(VideoFrame f, int maxDepth = int.MaxValue)
        {
            lock (_lock)
            {
                // Bound the queue so a stalled decoder can't grow memory forever;
                // dropping oldest frames keeps latency low for live mirroring.
                while (_q.Count >= maxDepth)
                {
                    _q.Dequeue();
                    _sem.Wait(0);
                }
                _q.Enqueue(f);
            }
            _sem.Release();
        }

        public async Task<VideoFrame?> DequeueAsync(CancellationToken ct)
        {
            await _sem.WaitAsync(ct);
            lock (_lock) return _q.Count > 0 ? _q.Dequeue() : null;
        }
    }
}
