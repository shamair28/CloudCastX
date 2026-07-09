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
        private DatagramSocket? _audioControlSocket;
        private DatagramSocket? _timingSocket;
        private StreamSocketListener? _eventListener;
        private ushort _eventPort;
        private bool _eventConnected;

        private byte[]? _encryptedAesKey;
        private byte[]? _aesIv;
        private string? _streamConnectionId;
        private ushort _clientTimingPort;
        private string? _clientAddress;
        private string? _localAddress; // receiver's own IP on this connection (for PTP timingPeerInfo)

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
                // Capture the receiver's own address on this connection — needed for
                // the PTP timingPeerInfo we return in SETUP #1.
                try { _localAddress = socket.Information.LocalAddress?.DisplayName; } catch { }
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] Connection from {_clientAddress} (local {_localAddress})");

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
                // With InputStreamOptions.Partial a single LoadAsync may return
                // fewer bytes than requested (body spanning TCP segments), and
                // ReadBytes would then throw and kill the connection — loop
                // until the full body is buffered.
                while (reader.UnconsumedBufferLength < cl)
                {
                    uint loaded = await reader.LoadAsync((uint)cl - reader.UnconsumedBufferLength);
                    if (loaded == 0)
                    {
                        System.Diagnostics.Debug.WriteLine("[AirPlay] Peer closed mid-body");
                        return null;
                    }
                }
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
            {
                sb.Append($"CSeq: {cseq}\r\n");
                // UxPlay adds this to every RTSP response except RECORD; some
                // senders expect it on legacy (NTP) sessions.
                if (!req.Method.Equals("RECORD", StringComparison.OrdinalIgnoreCase))
                    sb.Append("Audio-Jack-Status: connected; type=digital\r\n");
            }
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
                    ("GET",  "/info")           => HandleInfo(req),
                    (_, "/pair-setup")           => await HandlePairSetupAsync(req),
                    (_, "/pair-verify")          => await HandlePairVerifyAsync(req),
                    ("POST", "/fp-setup")        => HandleFpSetup(req),
                    ("POST", "/feedback")        => HttpResp.Ok(Array.Empty<byte>()),
                    ("POST", "/stream")          => await HandleStreamAsync(req),
                    ("GET",  "/playback-info")   => HandlePlaybackInfo(),
                    ("POST", "/stop")            => await HandleStop(),
                    ("RECORD", _)               => HandleRecord(req),
                    ("SETPEERS", _)             => HandleSetPeers(req),
                    ("TEARDOWN", _)             => await HandleTeardownAsync(req),
                    _                            => await HandleSetupOrDefaultAsync(req),
                };
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] {req.Method} {req.Path} error: {ex.Message}");
                return HttpResp.Error(500);
            }
        }

        private HttpResp HandleInfo(HttpReq req)
        {
            // iOS's first GET /info carries a plist body with a "qualifier"
            // asking for the raw mDNS TXT record over unicast (txtAirPlay /
            // txtRAOP). Per UxPlay's raop_handler_info, the response to that
            // request must contain ONLY the requested TXT record(s) — the full
            // device dict below is reserved for the body-less GET /info.
            if (req.Body.Length > 0)
            {
                var qualifierDict = new Dictionary<string, object>();
                try
                {
                    var q = BinaryPlist.Decode(req.Body);
                    if (q != null && q.TryGetValue("qualifier", out var qObj) && qObj is object[] quals)
                    {
                        foreach (var item in quals)
                        {
                            if ("txtAirPlay".Equals(item as string, StringComparison.Ordinal))
                                qualifierDict["txtAirPlay"] = MdnsAdvertiser.BuildTxtRecordBytes(
                                    MdnsAdvertiser.GetAirPlayTxtPairs(_config));
                            else if ("txtRAOP".Equals(item as string, StringComparison.Ordinal))
                                qualifierDict["txtRAOP"] = MdnsAdvertiser.BuildTxtRecordBytes(
                                    MdnsAdvertiser.GetRaopTxtPairs(_config));
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[AirPlay] /info qualifier parse failed: {ex.Message}");
                }
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] /info qualifier response: [{string.Join(", ", qualifierDict.Keys)}]");
                return HttpResp.Ok(BinaryPlist.Encode(qualifierDict), "application/x-apple-binary-plist");
            }

            // pk must be raw bytes (binary plist DATA type 0x4x).
            // statusFlags=0x04 = transient pairing supported, no PIN needed.
            // This value is kept CONSTANT for the lifetime of the receiver. The
            // sender issues a second GET /info mid-handshake; changing statusFlags
            // between the two responses (e.g. flipping bit 17) can make iOS believe
            // a password is now required and abort with "Unable to connect".
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
                ["statusFlags"]             = (long)0x04,
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
                $"[AirPlay] /info: statusFlags=0x04 (transient), " +
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

        private HttpResp HandleRecord(HttpReq req)
        {
            System.Diagnostics.Debug.WriteLine("[AirPlay] RECORD — streaming initiated");
            var resp = HttpResp.Ok(Array.Empty<byte>());
            resp.ExtraHeaders["Audio-Latency"] = "0";
            return resp;
        }

        // TEARDOWN carries a plist body listing the streams being torn down;
        // without an explicit route it fell through to the default handler and
        // was misparsed as a SETUP #2, re-binding sockets mid-teardown.
        private async Task<HttpResp> HandleTeardownAsync(HttpReq req)
        {
            System.Diagnostics.Debug.WriteLine("[AirPlay] TEARDOWN");
            if (_activeSession != null)
            {
                await _activeSession.StopAsync();
                _activeSession = null;
            }
            _audioSocket?.Dispose();
            _audioSocket = null;
            _audioControlSocket?.Dispose();
            _audioControlSocket = null;
            StreamingStopped?.Invoke();
            return HttpResp.Ok(Array.Empty<byte>());
        }

        private HttpResp HandleSetPeers(HttpReq req)
        {
            System.Diagnostics.Debug.WriteLine($"[AirPlay] SETPEERS — {req.Body.Length} bytes");
            return HttpResp.Ok(Array.Empty<byte>());
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
                _streamConnectionId = FormatConnectionId(scid);
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
                return await HandleInitialSetupAsync(plist);
        }

        // SETUP #1 — "info and event" per the AirPlay 2 RTSP spec.
        // The sender sends generic device info, encryption keys (ekey/eiv) and the
        // timing protocol it wants to use. The receiver must:
        //   • open a DEDICATED event TCP channel and return its port in `eventPort`
        //     (the RTSP flow will NOT continue until this channel is established), and
        //   • declare its timing: for PTP return timingPort=0 + timingPeerInfo; for
        //     legacy NTP open a UDP timing socket and return its port.
        // Ref: https://emanuelecozzi.net/docs/airplay2/rtsp/  (SETUP → 1) info and event)
        private async Task<HttpResp> HandleInitialSetupAsync(Dictionary<string, object> plist)
        {
            // Our advertised features (SteeBono's 0x1E5A7FFFF7) do NOT include the
            // PTP bit, so senders use NTP timing and typically omit the
            // timingProtocol key entirely. An absent key therefore means NTP —
            // defaulting to PTP here made us return timingPort=0 and never drive
            // NTP, so the sender stalled waiting for timing sync. Only honour PTP
            // when the sender explicitly asks for it.
            string timingProtocol = "NTP";
            if (plist.TryGetValue("timingProtocol", out var tpProto) &&
                tpProto is string proto && !string.IsNullOrEmpty(proto))
                timingProtocol = proto;

            bool useNtp = timingProtocol.Equals("NTP", StringComparison.OrdinalIgnoreCase);

            long timingPort;
            long eventPort;
            if (useNtp)
            {
                // The event channel is NOT used in NTP mirror/audio mode — UxPlay
                // (known-working with current iOS) returns eventPort=0 and never
                // binds an event listener ("the event port is not used in mirror
                // mode or audio mode", raop_handlers.h). Returning a real port
                // here made iOS abort right after the SETUP #1 response.
                eventPort = 0;
                await EnsureTimingSocketAsync();
                timingPort = GetTimingPort();
                _ = StartNtpTimingAsync(); // legacy senders expect us to drive NTP
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP #1 (NTP): eventPort=0 timingPort={timingPort}");
            }
            else
            {
                // PTP (modern AirPlay 2 flow): a dedicated event TCP channel is
                // required and the receiver declares PTP by returning timingPort=0.
                await EnsureEventSocketAsync();
                eventPort  = _eventPort;
                timingPort = 0;
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP #1 (PTP): eventPort={_eventPort} timingPort=0");

                // In the PTP flow the RTSP handshake will not continue until the
                // sender opens its event connection; surface a firewall hint if
                // it never arrives.
                _eventConnected = false;
                _ = Task.Run(async () =>
                {
                    await Task.Delay(3000);
                    if (!_eventConnected)
                        System.Diagnostics.Debug.WriteLine(
                            $"[AirPlay] WARNING: no event connection on port {_eventPort} within 3s — " +
                            "check Windows Firewall inbound rules for this port");
                });
            }

            var responseDict = new Dictionary<string, object>
            {
                ["eventPort"]  = eventPort,
                ["timingPort"] = timingPort,
            };

            // For PTP, announce ourselves as a timing peer so the sender can locate us.
            if (!useNtp && !string.IsNullOrEmpty(_localAddress))
            {
                responseDict["timingPeerInfo"] = new Dictionary<string, object>
                {
                    ["Addresses"] = new object[] { _localAddress! },
                    ["ID"]        = _localAddress!,
                };
            }

            return HttpResp.Ok(BinaryPlist.Encode(responseDict), "application/x-apple-binary-plist");
        }

        // SETUP #2 — "control and data" per the AirPlay 2 RTSP spec.
        // The sender declares one or more streams (screen=110, audio=96/103, …).
        // The receiver binds a UDP data channel (RTP payload) and a UDP control
        // channel (RTCP) for each stream and echoes back, per stream:
        //     { type, dataPort, controlPort }
        // NOTE: eventPort/timingPort belong ONLY to SETUP #1 and must NOT be
        // repeated here — doing so previously made iOS reopen its event/timing
        // channels against stale ports.
        // Ref: https://emanuelecozzi.net/docs/airplay2/rtsp/  (SETUP → 2) control and data)
        private async Task<HttpResp> HandleStreamSetupAsync(Dictionary<string, object> plist)
        {
            long streamType = 110;
            if (plist.TryGetValue("streams", out var streamsObj) && streamsObj is object[] arr && arr.Length > 0)
            {
                if (arr[0] is Dictionary<string, object> firstStream)
                {
                    if (firstStream.TryGetValue("type", out var typeObj))
                        streamType = Convert.ToInt64(typeObj);
                    // streamConnectionID lives INSIDE the stream dict in SETUP #2;
                    // it feeds the AES-CTR key derivation for the mirror stream.
                    if (firstStream.TryGetValue("streamConnectionID", out var scid))
                    {
                        _streamConnectionId = FormatConnectionId(scid);
                        System.Diagnostics.Debug.WriteLine(
                            $"[AirPlay] SETUP #2: streamConnectionID={_streamConnectionId}");
                    }
                }
            }

            Dictionary<string, object> streamResponse;

            if (streamType == 110) // screen mirroring — data arrives over TCP
            {
                if (_activeSession == null)
                {
                    _activeSession = new MirroringSession(_player);
                    _activeSession.SenderConnected += () =>
                        StreamingStarted?.Invoke("AirPlay device");
                }
                await _activeSession.BindTcpAsync();
                await _activeSession.ConfigureDecryptionAsync(
                    _fp.KeyMsg, _encryptedAesKey, _hap.EcdhSharedSecret, _streamConnectionId);
                await _activeSession.StartPlaybackAsync();
                StatusChanged?.Invoke("Connecting…");

                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP #2: type=110 (screen) dataPort={_activeSession.VideoPort} (TCP)");

                streamResponse = new Dictionary<string, object>
                {
                    ["type"]     = streamType,
                    ["dataPort"] = (long)_activeSession.VideoPort,
                };
            }
            else // audio (type=96/103) or other — UDP data + control sockets
            {
                _audioSocket        = await BindUdpAsync(_audioSocket, AirPlayConfig.AudioDataPort);
                _audioControlSocket = await BindUdpAsync(_audioControlSocket, AirPlayConfig.AudioControlPort);
                long dataPort    = long.Parse(_audioSocket.Information.LocalPort);
                long controlPort = long.Parse(_audioControlSocket.Information.LocalPort);
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] SETUP #2: type={streamType} (audio) dataPort={dataPort} controlPort={controlPort}");

                streamResponse = new Dictionary<string, object>
                {
                    ["type"]        = streamType,
                    ["dataPort"]    = dataPort,
                    ["controlPort"] = controlPort,
                };
            }

            var responseDict = new Dictionary<string, object>
            {
                ["streams"] = new object[] { streamResponse }
            };
            return HttpResp.Ok(BinaryPlist.Encode(responseDict), "application/x-apple-binary-plist");
        }

        // Key derivation uses the UNSIGNED decimal form of streamConnectionID
        // (a uint64). Our plist decoder returns 8-byte ints as signed longs, so
        // IDs with the high bit set would otherwise render with a '-' and derive
        // the wrong stream key (RPiPlay/UxPlay both format with %llu).
        private static string FormatConnectionId(object value) =>
            value is long l ? ((ulong)l).ToString() : value.ToString() ?? "";

        // Returns the given UDP socket if already bound, otherwise binds a fresh
        // one to the preferred fixed port, falling back to an OS-assigned port.
        // (Cannot use a ref parameter here because async methods disallow
        // ref/out — callers assign the returned socket.)
        private static async Task<DatagramSocket> BindUdpAsync(DatagramSocket? existing, ushort preferredPort)
        {
            if (existing != null) return existing;
            var socket = new DatagramSocket();
            try
            {
                await socket.BindServiceNameAsync(preferredPort.ToString());
            }
            catch
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] UDP port {preferredPort} unavailable — falling back to ephemeral");
                socket.Dispose();
                socket = new DatagramSocket();
                await socket.BindServiceNameAsync("0");
            }
            return socket;
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
                if (plist.TryGetValue("streamConnectionID", out var scid) && scid != null)
                    _streamConnectionId = FormatConnectionId(scid);
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
                _activeSession.SenderConnected += () =>
                    StreamingStarted?.Invoke("AirPlay device");
            }
            await _activeSession.BindTcpAsync();
            await _activeSession.ConfigureDecryptionAsync(
                _fp.KeyMsg, _encryptedAesKey, _hap.EcdhSharedSecret, _streamConnectionId);
            await _activeSession.StartPlaybackAsync();

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
            _audioControlSocket?.Dispose();
            _audioControlSocket = null;
            _timingSocket?.Dispose();
            _timingSocket = null;
            _eventListener?.Dispose();
            _eventListener = null;
            StreamingStopped?.Invoke();
            return HttpResp.Ok(Array.Empty<byte>());
        }

        // ── Event + timing port helpers ───────────────────────────────────────

        private async Task EnsureEventSocketAsync()
        {
            if (_eventListener != null) return;
            _eventListener = new StreamSocketListener();
            _eventListener.ConnectionReceived += OnEventConnectionReceived;
            try
            {
                await _eventListener.BindServiceNameAsync(AirPlayConfig.EventPort.ToString());
            }
            catch
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] Event port {AirPlayConfig.EventPort} unavailable — falling back to ephemeral");
                _eventListener.Dispose();
                _eventListener = new StreamSocketListener();
                _eventListener.ConnectionReceived += OnEventConnectionReceived;
                await _eventListener.BindServiceNameAsync("0");
            }
            _eventPort = ushort.Parse(_eventListener.Information.LocalPort);
            System.Diagnostics.Debug.WriteLine($"[AirPlay] Event TCP listener bound on port {_eventPort}");
        }

        private async void OnEventConnectionReceived(StreamSocketListener sender,
            StreamSocketListenerConnectionReceivedEventArgs args)
        {
            _eventConnected = true;
            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] Event connection from {args.Socket.Information.RemoteAddress.DisplayName}");
            // Keep the connection alive — iOS uses this for event delivery
            try
            {
                using var socket = args.Socket;
                var reader = new DataReader(socket.InputStream) { InputStreamOptions = InputStreamOptions.Partial };
                while (true)
                {
                    uint loaded = await reader.LoadAsync(4096);
                    if (loaded == 0) break;
                    byte[] data = new byte[loaded];
                    reader.ReadBytes(data);
                    System.Diagnostics.Debug.WriteLine(
                        $"[AirPlay] Event data: {loaded} bytes [{BitConverter.ToString(data, 0, Math.Min((int)loaded, 32))}]");
                }
            }
            catch { }
            System.Diagnostics.Debug.WriteLine("[AirPlay] Event connection closed");
        }

        private async Task EnsureTimingSocketAsync()
        {
            if (_timingSocket != null) return;
            _timingSocket = new DatagramSocket();
            _timingSocket.MessageReceived += OnTimingMessage;
            try
            {
                await _timingSocket.BindServiceNameAsync(AirPlayConfig.TimingPort.ToString());
            }
            catch
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[AirPlay] Timing port {AirPlayConfig.TimingPort} unavailable — falling back to ephemeral");
                _timingSocket.Dispose();
                _timingSocket = new DatagramSocket();
                _timingSocket.MessageReceived += OnTimingMessage;
                await _timingSocket.BindServiceNameAsync("0");
            }
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

                // Send a burst of 3 initial packets, then poll every 3 s like
                // UxPlay for as long as the timing socket lives.
                for (int i = 0; i < 3; i++)
                {
                    await SendNtpPacketAsync();
                    await Task.Delay(300);
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (_timingSocket != null)
                        {
                            await Task.Delay(3000);
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
