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

        private byte[]? _encryptedAesKey;
        private byte[]? _aesIv;
        private string? _streamConnectionId;

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
                while (true)
                {
                    var req = await ReadRequestAsync(socket);
                    if (req == null) break;

                    var resp = await HandleRequestAsync(req);
                    await SendResponseAsync(socket, resp);

                    if (req.Headers.TryGetValue("Connection", out var conn) &&
                        conn.Equals("close", StringComparison.OrdinalIgnoreCase))
                        break;
                }
            }
            catch { /* client disconnected */ }
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
                if (loaded == 0) return null;

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
            string method = parts[0];
            string path   = parts[1].Split('?')[0];

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

            return new HttpReq(method, path, headers, body);
        }

        private static async Task SendResponseAsync(StreamSocket socket, HttpResp resp)
        {
            using var writer = new DataWriter(socket.OutputStream);

            var sb = new StringBuilder();
            sb.Append($"HTTP/1.1 {resp.StatusCode} {resp.StatusText}\r\n");
            sb.Append($"Server: AirTunes/{AirPlayConfig.ServerVersion}\r\n");
            sb.Append($"Content-Length: {resp.Body.Length}\r\n");
            if (!string.IsNullOrEmpty(resp.ContentType))
                sb.Append($"Content-Type: {resp.ContentType}\r\n");
            foreach (var h in resp.ExtraHeaders)
                sb.Append($"{h.Key}: {h.Value}\r\n");
            sb.Append("\r\n");

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
                ["statusFlags"]             = (long)0x04,
                ["vv"]                      = (long)2,
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
                return HttpResp.Ok(Array.Empty<byte>());

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

            // Branch: initial SETUP (no streams) vs stream SETUP (has streams)
            if (plist.ContainsKey("streams"))
                return await HandleStreamSetupAsync(plist);
            else
                return HandleInitialSetup();
        }

        // Phase 1: Initial SETUP — store ekey/eiv, return timing/event ports.
        // Both point to ControlPort (7000) so iOS timing/event traffic arrives
        // on the existing TCP listener (unrecognized requests return 200 OK).
        private HttpResp HandleInitialSetup()
        {
            System.Diagnostics.Debug.WriteLine(
                $"[AirPlay] SETUP initial: timingPort={AirPlayConfig.ControlPort}, " +
                $"eventPort={AirPlayConfig.ControlPort}");

            var responseDict = new Dictionary<string, object>
            {
                ["timingPort"] = (long)AirPlayConfig.ControlPort,
                ["eventPort"]  = (long)AirPlayConfig.ControlPort,
            };
            return HttpResp.Ok(BinaryPlist.Encode(responseDict), "application/x-apple-binary-plist");
        }

        // Phase 2: Stream SETUP — parse the streams array, bind ports, echo type back.
        private async Task<HttpResp> HandleStreamSetupAsync(Dictionary<string, object> plist)
        {
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

            var responseDict = new Dictionary<string, object>
            {
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
            StreamingStopped?.Invoke();
            return HttpResp.Ok(Array.Empty<byte>());
        }
    }

    internal class HttpReq
    {
        public string Method  { get; }
        public string Path    { get; }
        public Dictionary<string, string> Headers { get; }
        public byte[] Body    { get; }
        public HttpReq(string method, string path,
            Dictionary<string, string> headers, byte[] body)
        { Method = method; Path = path; Headers = headers; Body = body; }
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
