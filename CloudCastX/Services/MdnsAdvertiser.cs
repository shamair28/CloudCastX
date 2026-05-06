using System;
using System.Threading.Tasks;
using Windows.Networking.ServiceDiscovery.Dnssd;
using Windows.Networking.Sockets;

namespace CloudCast.Services
{
    // Advertises the AirPlay receiver over mDNS/DNS-SD so iOS can discover it.
    // Registers two service types as Apple's AirPlay 2 stack requires:
    //   _airplay._tcp  — carries capabilities + pairing key
    //   _raop._tcp     — legacy audio path (needed for iOS to show the device in
    //                    the AirPlay picker even for video-only receivers)
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
            airplayTxt["flags"]    = "0x0";
            airplayTxt["model"]    = AirPlayConfig.Model;
            airplayTxt["pk"]       = pkHex;
            airplayTxt["pi"]       = _config.PairingId;
            airplayTxt["srcvers"]  = AirPlayConfig.ServerVersion;
            airplayTxt["vv"]       = "2";

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp TXT: features={AirPlayConfig.FeaturesHex} pk={pkHex.Substring(0, 8)}…");

            _airplayReg = await _airplayInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp registration status: {_airplayReg.Status}");

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
            raopTxt["sf"] = "0x0";
            raopTxt["tp"] = "UDP";
            raopTxt["vn"] = "65537";
            raopTxt["vs"] = AirPlayConfig.ServerVersion;

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp instance: {macNc}@{_config.DeviceName}");

            _raopReg = await _raopInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp registration status: {_raopReg.Status}");
        }

        // DnssdRegistrationResult does not implement IDisposable in WinRT —
        // release by nulling references so the GC can collect them.
        public Task StopAsync()
        {
            _airplayReg = null;
            _raopReg    = null;
            _airplayInstance = null;
            _raopInstance    = null;
            System.Diagnostics.Debug.WriteLine("[mDNS] Stopped");
            return Task.CompletedTask;
        }
    }
}
