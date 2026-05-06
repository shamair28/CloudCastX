using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CloudCast.Util;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Controls;

namespace CloudCast.Services
{
    internal class AirPlayControlServer
    {
        private readonly AirPlayConfig _config;
        private readonly MediaPlayerElement _player;
        private readonly HapPairing _hap;
        private readonly FairPlaySetup _fp;
        private StreamSocketListener? _listener;
        private MirroringSession? _activeSession;
        private DatagramSocket? _audioSocket;
        private DatagramSocket? _timingSocket;
        private DatagramSocket? _eventSocket;
        private ushort _eventPort;

        private byte[]? _encryptedAesKey;
        private byte[]? _aesIv;
        private string? _streamConnectionId;
        private ushort _clientTimingPort;
        private string? _clientAddress;
        private bool _sessionActive; // set after initial SETUP — changes statusFlags in /info

        public event Action<string>? StatusChanged;
        public event Action<string>? StreamingStarted;
        public event Action? StreamingStopped;

        public AirPlayControlServer(AirPlayConfig config, MediaPlayerElement player)
        {
            _config = config;
            _player = player;
            _hap    = new HapPairing(config);
            _fp     = new FairPlaySetup();
        }

        public async Task StartAsync()
        {
            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnConnectionReceived;
            await _listener.BindServiceNameAsync(AirPlayConfig.ControlPort.ToString());
            System.Diagnostics.Debug.WriteLine($"[AirPlay] TCP listener ready on port {AirPlayConfig.ControlPort}");
        }

        public Task StopAsync()
        {
            _listener?.Dispose();
            return Task.CompletedTask;
        }

        private async void OnConnectionReceived(StreamSocketListener sender,
            StreamSocketListenerConnectionReceivedEventArgs args)
        {
            try
            {
                using var socket = args.Socket;
                _clientAddress = socket.Information.RemoteAddress.DisplayName;
                System.Diagnostics.Debug.WriteLine($"[AirPlay] Connection from {_clientAddress}");

                while (true)
                {
                    var req = await ReadRequestAsync(socket);
                    if (req == null) break;

                    var resp = await HandleRequestAsync(req);
                    await SendResponseAsync(socket, resp, req);
                    System.Diagnostics.Debug.WriteLine("[WIRE] --- waiting for next request ---");

                    if (req.Headers.TryGetValue("Connection", out var conn) &&
                        conn.Equals("close", StringComparison.OrdinalIgnoreCase))
                        break;
                }
                System.Diagnostics.Debug.WriteLine("[AirPlay] Connection closed");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] Connection error: {ex.Message}");
            }
        }

        private static async Task<HttpReq?> ReadRequestAsync(StreamSocket socket)
        {
            var reader = new DataReader(socket.InputStream)
            {
                InputStreamOptions = InputStreamOptions.Partial
            };

            var lines = new List<string>();
            var lineBytes = new List<byte>();

            while (true)
            {
                uint loaded = await reader.LoadAsync(1);
                if (loaded == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[AirPlay] Peer closed connection");
                    return null;
                }

                byte b = reader.ReadByte();
                lineBytes.Add(b);

                int n = lineBytes.Count;
                if (n >= 2 && lineBytes[n - 2] == '\r' && lineBytes[n - 1] == '\n')
                {
                    string line = Encoding.UTF8.GetString(lineBytes.ToArray(), 0, n - 2);
                    lineBytes.Clear();
                    if (line.Length == 0) break;
                    lines.Add(line);
                }
            }

            if (lines.Count == 0) return null;

            var parts = lines[0].Split(' ');
            if (parts.Length < 2) return null;
            string method   = parts[0];
            string path     = parts[1].Split('?')[0];
            string protocol = parts.Length >= 3 ? parts[2] : "HTTP/1.1";

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Count; i++)
            {
                int colon = lines[i].IndexOf(':');
                if (colon > 0)
                    headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
            }

            byte[] body = Array.Empty<byte>();
            if (headers.TryGetValue("Content-Length", out string? clStr) &&
                int.TryParse(clStr, out int cl) && cl > 0)
            {
                await reader.LoadAsync((uint)cl);
                body = new byte[cl];
                reader.ReadBytes(body);
            }

            System.Diagnostics.Debug.WriteLine($"[WIRE] >>> {method} {path} {protocol}");
            foreach (var h in headers)
                System.Diagnostics.Debug.WriteLine($"[WIRE] >>> {h.Key}: {h.Value}");
            if (body.Length > 0)
                System.Diagnostics.Debug.WriteLine($"[WIRE] >>> Body: {body.Length} bytes [{BitConverter.ToString(body, 0, Math.Min(body.Length, 64))}]");

            return new HttpReq(method, path, protocol, headers, body);
        }

        private static async Task SendResponseAsync(StreamSocket socket, HttpResp resp, HttpReq req)
        {
            using var writer = new DataWriter(socket.OutputStream);

            var sb = new StringBuilder();
            // Mirror the client's protocol (RTSP/1.0 or HTTP/1.1)
            sb.Append($"{req.Protocol} {resp.StatusCode} {resp.StatusText}\r\n");
            sb.Append($"Server: AirTunes/{AirPlayConfig.ServerVersion}\r\n");
            // Echo CSeq — mandatory in RTSP, harmless in HTTP
            if (req.Headers.TryGetValue("CSeq", out var cseq))
                sb.Append($"CSeq: {cseq}\r\n");
            sb.Append($"Content-Length: {resp.Body.Length}\r\n");
            if (!string.IsNullOrEmpty(resp.ContentType))
                sb.Append($"Content-Type: {resp.ContentType}\r\n");
            foreach (var h in resp.ExtraHeaders)
                sb.Append($"{h.Key}: {h.Value}\r\n");
            sb.Append("\r\n");

            System.Diagnostics.Debug.WriteLine($"[WIRE] <<< {req.Protocol} {resp.StatusCode} {resp.StatusText}");
            if (req.Headers.TryGetValue("CSeq", out var cseqLog))
                System.Diagnostics.Debug.WriteLine($"[WIRE] <<< CSeq: {cseqLog}");
            System.Diagnostics.Debug.WriteLine($"[WIRE] <<< Content-Length: {resp.Body.Length}");
            if (!string.IsNullOrEmpty(resp.ContentType))
                System.Diagnostics.Debug.WriteLine($"[WIRE] <<< Content-Type: {resp.ContentType}");
            if (resp.Body.Length > 0)
                System.Diagnostics.Debug.WriteLine($"[WIRE] <<< Body: [{BitConverter.ToString(resp.Body, 0, Math.Min(resp.Body.Length, 128))}]");

            writer.WriteBytes(Encoding.ASCII.GetBytes(sb.ToString()));
            if (resp.Body.Length > 0)
                writer.WriteBytes(resp.Body);

            await writer.StoreAsync();
            await writer.FlushAsync();
            writer.DetachStream();
        }

        private async Task<HttpResp> HandleRequestAsync(HttpReq req)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] {req.Method} {req.Path}");
                return (req.Method, req.Path) switch
                {
                    ("GET",  "/info")           => HandleInfo(),
                    (_, "/pair-setup")           => await HandlePairSetupAsync(req),
                    (_, "/pair-verify")          => await HandlePairVerifyAsync(req),
                    ("POST", "/fp-setup")        => HandleFpSetup(req),
                    ("POST", "/feedback")        => HttpResp.Ok(Array.Empty<byte>()),
                    ("POST", "/stream")          => await HandleStreamAsync(req),
                    ("GET",  "/playback-info")   => HandlePlaybackInfo(),
                    ("POST", "/stop")            => await HandleStop(),
                    _                            => await HandleSetupOrDefaultAsync(req),
                };
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] {req.Method} {req.Path} error: {ex.Message}");
                return HttpResp.Error(500);
            }
        }

        private HttpResp HandleInfo()
        {
            // pk must be raw bytes (binary plist DATA type 0x4x).
            // statusFlags=0x04 = transient pairing supported.
            //   0x00 would mean "already paired" which iOS rejects on first contact.
            //   0x04 means "I support transient pairing, no PIN needed".
            var dict = new Dictionary<string, object>
            {
                ["deviceID"]                = _config.DeviceId,
                ["features"]                = AirPlayConfig.Features,
                ["keepAliveLowPower"]       = true,
                ["keepAliveSendStatsAsBody"] = true,
                ["macAddress"]              = _config.DeviceId,
                ["model"]                   = AirPlayConfig.Model,
                ["name"]                    = _config.DeviceName,
                ["pi"]                      = _config.PairingId,
                ["pk"]                      = _config.Ed25519PublicKey,
                ["psi"]                     = "00000000-0000-0000-0000-000000000000",
                ["srcvers"]                 = AirPlayConfig.ServerVersion,
                ["statusFlags"]             = (long)(_sessionActive ? 0x20004 : 0x04),
                ["vv"]                      = (long)2,

                // Display capabilities — required for iOS to know mirroring resolution
                ["displays"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["width"]          = (long)1920,
                        ["height"]         = (long)1080,
                        ["widthPixels"]    = (long)1920,
                        ["heightPixels"]   = (long)1080,
                        ["widthPhysical"]  = (long)0,
                        ["heightPhysical"] = (long)0,
                        ["refreshRate"]    = (long)60,
                        ["maxFPS"]         = (long)30,
                        ["rotation"]       = false,
                        ["overscanned"]    = false,
                        ["features"]       = (long)14,
                        ["uuid"]           = _config.PairingId,
                    }
                },

                // Audio format capabilities
                ["audioFormats"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["type"]               = (long)100,
                        ["audioInputFormats"]  = (long)67108860,
                        ["audioOutputFormats"] = (long)67108860,
                    },
                    new Dictionary<string, object>
                    {
                        ["type"]               = (long)101,
                        ["audioInputFormats"]  = (long)67108860,
                        ["audioOutputFormats"] = (long)67108860,
                    }
                },

                // Audio latency info
                ["audioLatencies"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["outputLatencyMicros"] = (long)0,
                        ["type"]                = (long)100,
                        ["audioType"]           = "default",
                        ["inputLatencyMicros"]  = (long)0,
                    },
                    new Dictionary<string, object>
                    {
                        ["outputLatencyMicros"] = (long)0,
                        ["type"]                = (long)101,
                        ["audioType"]           = "default",
                        ["inputLatencyMicros"]  = (long)0,
                    }
                },
            };

            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] /info: statusFlags=0x{(_sessionActive ? 0x20004 : 0x04):X} ({(_sessionActive ? "active" : "transient")}), " +
                $"features=0x{AirPlayConfig.Features:X}, " +
                $"pk={BitConverter.ToString(_config.Ed25519PublicKey, 0, 4)}…");

            byte[] plist = BinaryPlist.Encode(dict);
            return HttpResp.Ok(plist, "application/x-apple-binary-plist");
        }

        private async Task<HttpResp> HandlePairSetupAsync(HttpReq req)
        {
            var response = await _hap.HandlePairSetupAsync(req.Body);
            return response != null
                ? HttpResp.Ok(response, "application/octet-stream")
                : HttpResp.Error(470);
        }

        private async Task<HttpResp> HandlePairVerifyAsync(HttpReq req)
        {
            var response = await _hap.HandlePairVerifyAsync(req.Body);
            return response != null
                ? HttpResp.Ok(response, "application/octet-stream")
                : HttpResp.Error(470);
        }

        private HttpResp HandleFpSetup(HttpReq req)
        {
            var response = _fp.Handle(req.Body);
            return response != null
                ? HttpResp.Ok(response, "application/octet-stream")
                : HttpResp.Error(403);
        }

        private async Task<HttpResp> HandleSetupOrDefaultAsync(HttpReq req)
        {
            if (req.Body.Length == 0)
                return HttpResp.Ok(Array.Empty<byte>());

            try   { return await HandleSetupPlistAsync(req.Body); }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] SETUP error: {ex.Message}");
                return HttpResp.Ok(Array.Empty<byte>());
            }
        }

        private async Task<HttpResp> HandleSetupPlistAsync(byte[] body)
        {
            var plist = BinaryPlist.Decode(body);
            if (plist == null)
            {
                System.Diagnostics.Debug.WriteLine("[AirPlay] SETUP: failed to decode plist");
                return HttpResp.Ok(Array.Empty<byte>());
            }

            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] SETUP plist keys: {string.Join(", ", plist.Keys)}");

            // Extract crypto keys whenever present (may arrive in initial or stream SETUP)
            if (plist.TryGetValue("ekey", out var ekeyObj) && ekeyObj is byte[] ekey)
            {
                _encryptedAesKey = ekey;
                System.Diagnostics.Debug.WriteLine($"[AirPlay] SETUP: ekey ({ekey.Length}B)");
            }
            if (plist.TryGetValue("eiv", out var eivObj) && eivObj is byte[] eiv)
            {
                _aesIv = eiv;
                System.Diagnostics.Debug.WriteLine($"[AirPlay] SETUP: eiv ({eiv.Length}B)");
            }
            if (plist.TryGetValue("streamConnectionID", out var scid))
            {
                _streamConnectionId = scid.ToString();
                System.Diagnostics.Debug.WriteLine($"[AirPlay] SETUP: streamConnectionID={_streamConnectionId}");
            }
            if (plist.TryGetValue("timingPort", out var tpObj))
            {
                _clientTimingPort = (ushort)Convert.ToInt64(tpObj);
                System.Diagnostics.Debug.WriteLine($"[AirPlay] SETUP: client timingPort={_clientTimingPort}");
            }

            // Branch: initial SETUP (no streams) vs stream SETUP (has streams)
            if (plist.ContainsKey("streams"))
                return await HandleStreamSetupAsync(plist);
            else
                return await HandleInitialSetupAsync();
        }

        // Phase 1: Initial SETUP — store ekey/eiv, bind sockets, return empty 200 OK.
        // Samsung TV wire capture shows Content-Length: 0 for the initial SETUP.
        // eventPort/timingPort go in the stream SETUP response.
        // Returning a plist here causes iOS to reject immediately (faster failure).
        private async Task<HttpResp> HandleInitialSetupAsync()
        {
            await EnsureEventSocketAsync();
            await EnsureTimingSocketAsync();
            _sessionActive = true;

            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] SETUP initial: empty 200 OK (session active, event={_eventPort} timing={GetTimingPort()})");

            // Start NTP timing immediately (fire-and-forget)
            _ = StartNtpTimingAsync();

            return HttpResp.Ok(Array.Empty<byte>());
        }

        // Phase 2: Stream SETUP — parse the streams array, bind ports, echo type back.
        // Response includes eventPort + timingPort (real UDP) alongside the streams array.
        private async Task<HttpResp> HandleStreamSetupAsync(Dictionary<string, object> plist)
        {
            await EnsureEventSocketAsync();

            long streamType = 110;
            if (plist.TryGetValue("streams", out var streamsObj) && streamsObj is object[] arr && arr.Length > 0)
            {
                if (arr[0] is Dictionary<string, object> firstStream)
                {
                    if (firstStream.TryGetValue("type", out var typeObj))
                        streamType = Convert.ToInt64(typeObj);
                }
            }

            long dataPort;

            if (streamType == 110) // video mirroring
            {
                if (_activeSession == null)
                {
                    _activeSession = new MirroringSession(_player);
                    await _activeSession.BindUdpAsync();
                }
                dataPort = _activeSession.VideoPort;
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP stream: type=110 (video) dataPort={dataPort}");
            }
            else // audio (type=96) or other — bind a dummy UDP socket
            {
                _audioSocket?.Dispose();
                _audioSocket = new DatagramSocket();
                await _audioSocket.BindServiceNameAsync("0");
                dataPort = long.Parse(_audioSocket.Information.LocalPort);
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP stream: type={streamType} (audio) dataPort={dataPort}");
            }

            ushort timingPort = GetTimingPort();
            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] SETUP stream response: type={streamType} dataPort={dataPort} " +
                $"eventPort={_eventPort} timingPort={timingPort}");

            var responseDict = new Dictionary<string, object>
            {
                ["eventPort"]  = (long)_eventPort,
                ["timingPort"] = (long)timingPort,
                ["streams"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["type"]     = streamType,
                        ["dataPort"] = dataPort,
                    }
                }
            };
            return HttpResp.Ok(BinaryPlist.Encode(responseDict), "application/x-apple-binary-plist");
        }

        private async Task<HttpResp> HandleStreamAsync(HttpReq req)
        {
            Dictionary<string, object>? plist = null;
            if (req.Body.Length > 0)
            {
                try { plist = BinaryPlist.Decode(req.Body); }
                catch { }
            }

            if (plist != null)
            {
                if (plist.TryGetValue("ekey", out var ekeyObj) && ekeyObj is byte[] ekey)
                    _encryptedAesKey = ekey;
                if (plist.TryGetValue("eiv", out var eivObj) && eivObj is byte[] eiv)
                    _aesIv = eiv;
                if (plist.TryGetValue("streamConnectionID", out var scid))
                    _streamConnectionId = scid?.ToString();
            }

            if (_fp.KeyMsg == null)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[AirPlay] /stream: FairPlay KeyMsg null — fp-setup not complete");
                return HttpResp.Error(403);
            }

            if (_activeSession == null)
            {
                _activeSession = new MirroringSession(_player);
                await _activeSession.BindUdpAsync();
            }

            await _activeSession.StartAsync(1920, 1080,
                _fp.KeyMsg, _encryptedAesKey, _aesIv,
                _hap.EcdhSharedSecret, _streamConnectionId);

            StatusChanged?.Invoke("Connecting…");

            var responseDict = new Dictionary<string, object>
            {
                ["streams"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        ["type"]     = (long)110,
                        ["dataPort"] = (long)_activeSession.VideoPort,
                    }
                }
            };
            _ = Task.Run(async () =>
            {
                await Task.Delay(500);
                StreamingStarted?.Invoke("AirPlay device");
            });

            return HttpResp.Ok(BinaryPlist.Encode(responseDict), "application/x-apple-binary-plist");
        }

        private HttpResp HandlePlaybackInfo()
        {
            var dict = new Dictionary<string, object>
            {
                ["duration"]         = (long)0,
                ["position"]         = (long)0,
                ["rate"]             = (long)(_activeSession != null ? 1 : 0),
                ["readyToPlay"]      = _activeSession != null,
                ["playbackBufferFull"]  = false,
                ["playbackBufferEmpty"] = true,
                ["playbackLikelyToKeepUp"] = _activeSession != null,
            };
            return HttpResp.Ok(BinaryPlist.Encode(dict), "application/x-apple-binary-plist");
        }

        private async Task<HttpResp> HandleStop()
        {
            if (_activeSession != null)
            {
                await _activeSession.StopAsync();
                _activeSession = null;
            }
            _audioSocket?.Dispose();
            _audioSocket = null;
            _timingSocket?.Dispose();
            _timingSocket = null;
            _eventSocket?.Dispose();
            _eventSocket = null;
            StreamingStopped?.Invoke();
            return HttpResp.Ok(Array.Empty<byte>());
        }

        // ── Event + timing port helpers ───────────────────────────────────────

        private async Task EnsureEventSocketAsync()
        {
            if (_eventSocket != null) return;
            _eventSocket = new DatagramSocket();
            _eventSocket.MessageReceived += (s, e) =>
            {
                using var reader = e.GetDataReader();
                uint len = reader.UnconsumedBufferLength;
                byte[] data = new byte[len];
                reader.ReadBytes(data);
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] Event received: {len} bytes [{BitConverter.ToString(data, 0, Math.Min((int)len, 32))}]");
            };
            await _eventSocket.BindServiceNameAsync("0");
            _eventPort = ushort.Parse(_eventSocket.Information.LocalPort);
            System.Diagnostics.Debug.WriteLine($"[AirPlay] Event socket bound on port {_eventPort}");
        }

        private async Task EnsureTimingSocketAsync()
        {
            if (_timingSocket != null) return;
            _timingSocket = new DatagramSocket();
            _timingSocket.MessageReceived += OnTimingMessage;
            await _timingSocket.BindServiceNameAsync("0");
            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] Timing socket bound on port {_timingSocket.Information.LocalPort}");
        }

        private ushort GetTimingPort()
        {
            if (_timingSocket != null)
            {
                try { return ushort.Parse(_timingSocket.Information.LocalPort); }
                catch { }
            }
            return (ushort)AirPlayConfig.ControlPort;
        }

        // ── NTP timing ───────────────────────────────────────────────────────
        // After the initial SETUP, the receiver must initiate NTP timing to
        // the client's timingPort. iOS waits for timing sync before proceeding
        // to the stream SETUP.

        private async Task StartNtpTimingAsync()
        {
            if (_clientTimingPort == 0 || string.IsNullOrEmpty(_clientAddress))
            {
                System.Diagnostics.Debug.WriteLine("[NTP] No client timing info — skipping");
                return;
            }

            try
            {
                await EnsureTimingSocketAsync(); // reuse if already created

                System.Diagnostics.Debug.WriteLine(
                    $"[NTP] Starting timing to {_clientAddress}:{_clientTimingPort}");

                // Send a burst of 3 initial packets, then continue periodically
                for (int i = 0; i < 3; i++)
                {
                    await SendNtpPacketAsync();
                    await Task.Delay(300);
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        for (int i = 0; i < 50; i++)
                        {
                            await Task.Delay(500);
                            await SendNtpPacketAsync();
                        }
                    }
                    catch { /* timing stopped */ }
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NTP] Failed to start: {ex.Message}");
            }
        }

        private async Task SendNtpPacketAsync()
        {
            if (_timingSocket == null || _clientAddress == null || _clientTimingPort == 0)
                return;

            try
            {
                var outputStream = await _timingSocket.GetOutputStreamAsync(
                    new Windows.Networking.HostName(_clientAddress),
                    _clientTimingPort.ToString());
                using var writer = new DataWriter(outputStream);

                // 32-byte NTP timing request
                // [0-1] RTP header: V=2, PT=0xD2  [2-3] seq  [4-23] zeros
                // [24-31] NTP transmit timestamp (seconds.fraction since 1900)
                var packet = new byte[32];
                packet[0] = 0x80;
                packet[1] = 0xd2;
                packet[2] = 0x00;
                packet[3] = 0x07;

                long unixSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long ntpSec  = unixSec + 2208988800L; // NTP epoch offset
                long frac    = (long)((DateTimeOffset.UtcNow.Millisecond / 1000.0) * 0x100000000L);

                packet[24] = (byte)(ntpSec >> 24);
                packet[25] = (byte)(ntpSec >> 16);
                packet[26] = (byte)(ntpSec >> 8);
                packet[27] = (byte)ntpSec;
                packet[28] = (byte)(frac >> 24);
                packet[29] = (byte)(frac >> 16);
                packet[30] = (byte)(frac >> 8);
                packet[31] = (byte)frac;

                writer.WriteBytes(packet);
                await writer.StoreAsync();

                System.Diagnostics.Debug.WriteLine("[NTP] Timing packet sent");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NTP] Send failed: {ex.Message}");
            }
        }

        private void OnTimingMessage(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs e)
        {
            try
            {
                using var reader = e.GetDataReader();
                uint len = reader.UnconsumedBufferLength;
                byte[] data = new byte[len];
                reader.ReadBytes(data);
                System.Diagnostics.Debug.WriteLine(
                    $"[NTP] Received {len}-byte timing response: [{BitConverter.ToString(data, 0, Math.Min((int)len, 32))}]");
            }
            catch { }
        }
    }

    internal class HttpReq
    {
        public string Method   { get; }
        public string Path     { get; }
        public string Protocol { get; } // "RTSP/1.0" or "HTTP/1.1"
        public Dictionary<string, string> Headers { get; }
        public byte[] Body     { get; }
        public HttpReq(string method, string path, string protocol,
            Dictionary<string, string> headers, byte[] body)
        { Method = method; Path = path; Protocol = protocol; Headers = headers; Body = body; }
    }

    internal class HttpResp
    {
        public int    StatusCode  { get; set; }
        public string StatusText  { get; set; } = "OK";
        public byte[] Body        { get; set; } = Array.Empty<byte>();
        public string ContentType { get; set; } = string.Empty;
        public Dictionary<string, string> ExtraHeaders { get; set; } = new();

        public static HttpResp Ok(byte[] body, string? contentType = null) => new HttpResp
        {
            StatusCode  = 200,
            StatusText  = "OK",
            Body        = body,
            ContentType = contentType ?? string.Empty,
        };

        public static HttpResp Error(int code)
        {
            string text = code switch
            {
                403  => "Forbidden",
                470  => "Connection Authorization Required",
                500  => "Internal Server Error",
                _    => "Error",
            };
            return new HttpResp { StatusCode = code, StatusText = text };
        }
    }
}
