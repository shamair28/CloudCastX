using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        private DnssdServiceInstance? _airplayInstance;
        private DnssdServiceInstance? _raopInstance;
        private DnssdRegistrationResult? _airplayReg;
        private DnssdRegistrationResult? _raopReg;

        public async Task StartAsync(AirPlayConfig config)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] Registering '{config.DeviceName}' on port {AirPlayConfig.ControlPort}");

            string pkHex = BitConverter.ToString(config.Ed25519PublicKey)
                               .Replace("-", "").ToLowerInvariant();

            // ── _airplay._tcp ─────────────────────────────────────────────────
            _airplayInstance = new DnssdServiceInstance(
                $"{config.DeviceName}._airplay._tcp.local",
                null,
                (ushort)AirPlayConfig.ControlPort)
            {
                DnssdServiceInstanceName = $"{config.DeviceName}._airplay._tcp.local"
            };

            // TXT record fields — must match what /info returns.
            // 'features' uses comma-separated lo,hi 32-bit halves of the 64-bit bitmask.
            var airplayTxt = _airplayInstance.TextAttributes;
            airplayTxt["deviceid"]   = config.DeviceId;
            airplayTxt["features"]   = AirPlayConfig.FeaturesHex;
            airplayTxt["flags"]      = "0x0";   // statusFlags=0: no PIN
            airplayTxt["model"]      = AirPlayConfig.Model;
            airplayTxt["pk"]         = pkHex;
            airplayTxt["pi"]         = config.PairingId;
            airplayTxt["srcvers"]    = AirPlayConfig.ServerVersion;
            airplayTxt["vv"]         = "2";

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp TXT: features={AirPlayConfig.FeaturesHex} pk={pkHex.Substring(0, 8)}…");

            _airplayReg = await _airplayInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _airplay._tcp registration status: {_airplayReg.Status}");

            // ── _raop._tcp ────────────────────────────────────────────────────
            // Instance name format: <MacAddressNoColons>@<DeviceName>
            string macNc = config.DeviceId.Replace(":", "");
            _raopInstance = new DnssdServiceInstance(
                $"{macNc}@{config.DeviceName}._raop._tcp.local",
                null,
                (ushort)AirPlayConfig.ControlPort)
            {
                DnssdServiceInstanceName = $"{macNc}@{config.DeviceName}._raop._tcp.local"
            };

            var raopTxt = _raopInstance.TextAttributes;
            raopTxt["am"]  = AirPlayConfig.Model;
            raopTxt["et"]  = "0,3,5";   // encryption types: none, FairPlay, MFiSAP
            raopTxt["ft"]  = AirPlayConfig.FeaturesHex;
            raopTxt["md"]  = "0,1,2";   // media: audio, video, image
            raopTxt["pk"]  = pkHex;
            raopTxt["sf"]  = "0x0";     // statusFlags
            raopTxt["tp"]  = "UDP";
            raopTxt["vn"]  = "65537";
            raopTxt["vs"]  = AirPlayConfig.ServerVersion;

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp instance: {macNc}@{config.DeviceName}");

            _raopReg = await _raopInstance.RegisterStreamSocketListenerAsync(
                new StreamSocketListener());

            System.Diagnostics.Debug.WriteLine(
                $"[mDNS] _raop._tcp registration status: {_raopReg.Status}");
        }

        public void Stop()
        {
            _airplayReg?.Dispose();
            _raopReg?.Dispose();
            _airplayInstance = null;
            _raopInstance    = null;
        }
    }
}
