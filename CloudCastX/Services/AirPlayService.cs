using System;
using System.Threading.Tasks;
using Windows.UI.Xaml.Controls;

namespace CloudCast.Services
{
    // Top-level orchestrator: loads config, then starts mDNS advertisement and
    // the HTTP control server in the correct order.
    internal class AirPlayService
    {
        private readonly MediaPlayerElement _player;
        private AirPlayConfig? _config;
        private MdnsAdvertiser? _mdns;
        private AirPlayControlServer? _control;
        private RaopServer? _raop;

        public event Action<string>? StatusChanged;
        public event Action<string>? StreamingStarted;
        public event Action? StreamingStopped;

        public AirPlayService(MediaPlayerElement player)
        {
            _player = player;
        }

        public async Task StartAsync()
        {
            StatusChanged?.Invoke("Loading…");

            // Pre-load the FairPlay lookup tables so they're ready when streaming starts
            try { await Crypto.OmgHaxData.LoadTablesAsync(); }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AirPlay] Table load failed (non-fatal): {ex.Message}");
            }

            _config = AirPlayConfig.Load();

            _control = new AirPlayControlServer(_config, _player);
            _control.StatusChanged   += s  => StatusChanged?.Invoke(s);
            _control.StreamingStarted += d => StreamingStarted?.Invoke(d);
            _control.StreamingStopped += () => StreamingStopped?.Invoke();
            await _control.StartAsync();

            _raop = new RaopServer(_config);
            await _raop.StartAsync();

            _mdns = new MdnsAdvertiser(_config);
            await _mdns.StartAsync();

            StatusChanged?.Invoke($"Waiting for AirPlay — look for \"{_config.DeviceName}\" in your device's AirPlay menu");
        }

        public async Task StopAsync()
        {
            if (_mdns    != null) await _mdns.StopAsync();
            if (_raop    != null) await _raop.StopAsync();
            if (_control != null) await _control.StopAsync();
        }
    }
}
