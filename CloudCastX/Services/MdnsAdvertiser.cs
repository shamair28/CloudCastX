using System;
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

        public async Task StartAsync()
        {
            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] Registering '{_config.DeviceName}' on port {AirPlayConfig.ControlPort}");

            string pkHex = BitConverter.ToString(_config.Ed25519PublicKey)
                               .Replace("-", "").ToLowerInvariant();

            // ── _airplay._tcp ─────────────────────────────────────────────────
            _airplayInstance = new DnssdServiceInstance(
                $"{_config.DeviceName}._airplay._tcp.local",
                null,
                (ushort)AirPlayConfig.ControlPort);

            var airplayTxt = _airplayInstance.TextAttributes;
            airplayTxt["deviceid"] = _config.DeviceId;
            airplayTxt["features"] = AirPlayConfig.FeaturesHex;
            // sf=0x4: transient pairing (matches statusFlags in /info).
            // sf=0x0 would mean already-paired; sf=0x4 is the correct value
            // for a receiver that supports transient pairing without a PIN.
            airplayTxt["flags"]    = "0x4";
            airplayTxt["model"]    = AirPlayConfig.Model;
            airplayTxt["pk"]       = pkHex;
            airplayTxt["pi"]       = _config.PairingId;
            airplayTxt["srcvers"]  = AirPlayConfig.ServerVersion;
            airplayTxt["vv"]       = "2";

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
            raopTxt["am"] = AirPlayConfig.Model;
            raopTxt["et"] = "0,3,5";
            raopTxt["ft"] = AirPlayConfig.FeaturesHex;
            raopTxt["md"] = "0,1,2";
            raopTxt["pk"] = pkHex;
            // sf=0x4 must match _airplay._tcp flags above
            raopTxt["sf"] = "0x4";
            raopTxt["tp"] = "UDP";
            raopTxt["vn"] = "65537";
            raopTxt["vs"] = AirPlayConfig.ServerVersion;

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
