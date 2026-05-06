using System;
using System.Linq;
using System.Threading.Tasks;
using Makaretu.Dns;

namespace CloudCast.Services
{
    // Advertises two mDNS/DNS-SD services so Apple devices can find CloudCast in the
    // AirPlay picker without any manual configuration:
    //   _airplay._tcp  — primary AirPlay 2 discovery service
    //   _raop._tcp     — legacy Remote Audio Output Protocol discovery
    //
    // Uses Makaretu.Dns.Multicast (UdpClient-based, works on both PC and Xbox with the
    // privateNetworkClientServer capability declared in Package.appxmanifest).
    internal class MdnsAdvertiser
    {
        private readonly AirPlayConfig _config;
        private MulticastService? _mdns;
        private ServiceDiscovery? _sd;
        private ServiceProfile? _airplayProfile;
        private ServiceProfile? _raopProfile;

        public MdnsAdvertiser(AirPlayConfig config) => _config = config;

        public Task StartAsync()
        {
            _mdns = new MulticastService();
            _sd   = new ServiceDiscovery(_mdns);

            _airplayProfile = BuildAirPlayProfile();
            _raopProfile    = BuildRaopProfile();

            _sd.Advertise(_airplayProfile);
            _sd.Advertise(_raopProfile);

            _mdns.Start();
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            if (_airplayProfile != null) _sd?.Unadvertise(_airplayProfile);
            if (_raopProfile    != null) _sd?.Unadvertise(_raopProfile);
            _mdns?.Stop();
            return Task.CompletedTask;
        }

        // ── Profile builders ──────────────────────────────────────────────────

        private ServiceProfile BuildAirPlayProfile()
        {
            // Instance name visible in the AirPlay picker
            var p = new ServiceProfile(_config.DeviceName, "_airplay._tcp", AirPlayConfig.ControlPort);

            p.AddProperty("deviceid", _config.DeviceId);
            p.AddProperty("features", AirPlayConfig.FeaturesHex);
            p.AddProperty("flags",    "0x4");
            p.AddProperty("igl",      "1");
            p.AddProperty("model",    AirPlayConfig.Model);
            p.AddProperty("pi",       _config.PairingId);
            p.AddProperty("pk",       ToHex(_config.Ed25519PublicKey));
            p.AddProperty("psi",      "00000000-0000-0000-0000-000000000000");
            p.AddProperty("srcvers",  AirPlayConfig.ServerVersion);
            p.AddProperty("vv",       "2");
            p.AddProperty("acl",      "0");

            return p;
        }

        private ServiceProfile BuildRaopProfile()
        {
            // RAOP instance name: "AABBCCDDEEFF@DeviceName" (MAC without colons)
            string raopName = _config.DeviceId.Replace(":", "") + "@" + _config.DeviceName;
            var p = new ServiceProfile(raopName, "_raop._tcp", AirPlayConfig.RaopPort);

            p.AddProperty("am",  AirPlayConfig.Model);
            p.AddProperty("ch",  "2");
            p.AddProperty("cn",  "0,1,2,3");  // PCM, ALAC, AAC, AAC-ELD
            p.AddProperty("et",  "0,3,5");     // none, FairPlay, MFiSAP
            p.AddProperty("ft",  AirPlayConfig.FeaturesHex);
            p.AddProperty("md",  "0,1,2");
            p.AddProperty("pk",  ToHex(_config.Ed25519PublicKey));
            p.AddProperty("sr",  "44100");
            p.AddProperty("ss",  "16");
            p.AddProperty("sv",  "false");
            p.AddProperty("tp",  "UDP");
            p.AddProperty("vn",  "65537");
            p.AddProperty("vs",  AirPlayConfig.ServerVersion);
            p.AddProperty("vv",  "2");

            return p;
        }

        private static string ToHex(byte[] b)
            => string.Concat(b.Select(x => x.ToString("x2")));
    }
}
