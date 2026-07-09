using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking.ServiceDiscovery.Dnssd;
using Windows.Networking.Sockets;

namespace CloudCast.Services
{
    internal class MdnsAdvertiser
    {
        private readonly AirPlayConfig _config;
        private DnssdServiceInstance? _airplayInstance;
        private DnssdServiceInstance? _raopInstance;
        private DnssdRegistrationResult? _airplayReg;
        private DnssdRegistrationResult? _raopReg;

        public MdnsAdvertiser(AirPlayConfig config)
        {
            _config = config;
        }

        // ── TXT records ───────────────────────────────────────────────────────
        // Single source of truth for the TXT key/value pairs. Used both for the
        // mDNS advertisement and for GET /info "qualifier" responses (iOS asks
        // for the raw txtAirPlay record over unicast and the two must match).

        private static string PkHex(AirPlayConfig config) =>
            BitConverter.ToString(config.Ed25519PublicKey).Replace("-", "").ToLowerInvariant();

        public static List<KeyValuePair<string, string>> GetAirPlayTxtPairs(AirPlayConfig config) =>
            new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("deviceid", config.DeviceId),
                new KeyValuePair<string, string>("features", AirPlayConfig.FeaturesHex),
                // sf=0x4: transient pairing (matches statusFlags in /info).
                new KeyValuePair<string, string>("flags",    "0x4"),
                new KeyValuePair<string, string>("model",    AirPlayConfig.Model),
                new KeyValuePair<string, string>("pk",       PkHex(config)),
                new KeyValuePair<string, string>("pi",       config.PairingId),
                new KeyValuePair<string, string>("srcvers",  AirPlayConfig.ServerVersion),
                new KeyValuePair<string, string>("vv",       "2"),
            };

        public static List<KeyValuePair<string, string>> GetRaopTxtPairs(AirPlayConfig config) =>
            new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("am", AirPlayConfig.Model),
                new KeyValuePair<string, string>("et", "0,3,5"),
                new KeyValuePair<string, string>("ft", AirPlayConfig.FeaturesHex),
                new KeyValuePair<string, string>("md", "0,1,2"),
                new KeyValuePair<string, string>("pk", PkHex(config)),
                new KeyValuePair<string, string>("sf", "0x4"),
                new KeyValuePair<string, string>("tp", "UDP"),
                new KeyValuePair<string, string>("vn", "65537"),
                new KeyValuePair<string, string>("vs", AirPlayConfig.ServerVersion),
            };

        // DNS TXT wire format: each entry is one length byte + "key=value".
        public static byte[] BuildTxtRecordBytes(IEnumerable<KeyValuePair<string, string>> pairs)
        {
            using var ms = new MemoryStream();
            foreach (var kv in pairs)
            {
                var entry = Encoding.UTF8.GetBytes($"{kv.Key}={kv.Value}");
                ms.WriteByte((byte)entry.Length);
                ms.Write(entry, 0, entry.Length);
            }
            return ms.ToArray();
        }

        public async Task StartAsync()
        {
            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] Registering '{_config.DeviceName}' on port {AirPlayConfig.ControlPort}");

            string pkHex = PkHex(_config);

            // ── _airplay._tcp ─────────────────────────────────────────────────
            _airplayInstance = new DnssdServiceInstance(
                $"{_config.DeviceName}._airplay._tcp.local",
                null,
                (ushort)AirPlayConfig.ControlPort);

            var airplayTxt = _airplayInstance.TextAttributes;
            foreach (var kv in GetAirPlayTxtPairs(_config))
                airplayTxt[kv.Key] = kv.Value;

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp: features={AirPlayConfig.FeaturesHex} sf=0x4 pk={pkHex.Substring(0, 8)}…");

            _airplayReg = await _airplayInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp registration: {_airplayReg.Status}");

            // ── _raop._tcp ────────────────────────────────────────────────────
            string macNc = _config.DeviceId.Replace(":", "");
            _raopInstance = new DnssdServiceInstance(
                $"{macNc}@{_config.DeviceName}._raop._tcp.local",
                null,
                (ushort)AirPlayConfig.ControlPort);

            var raopTxt = _raopInstance.TextAttributes;
            foreach (var kv in GetRaopTxtPairs(_config))
                raopTxt[kv.Key] = kv.Value;

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp: {macNc}@{_config.DeviceName} sf=0x4");

            _raopReg = await _raopInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp registration: {_raopReg.Status}");
        }

        public Task StopAsync()
        {
            _airplayReg      = null;
            _raopReg         = null;
            _airplayInstance = null;
            _raopInstance    = null;
            System.Diagnostics.Debug.WriteLine("[mDNS] Stopped");
            return Task.CompletedTask;
        }
    }
}
