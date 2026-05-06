using System;
using System.Threading.Tasks;
using Windows.Networking.Sockets;

namespace CloudCast.Services
{
    // RAOP (Remote Audio Output Protocol) server — AirPlay audio streaming.
    //
    // In AirPlay 2, most audio sessions go through the AirPlay control server on
    // port 7000 via the /audioMode endpoint and are delivered as encrypted AAC/ALAC
    // over RTP. The legacy _raop._tcp service (RTSP on port 5000) handles AirPlay 1
    // audio (e.g., older Apple devices, iTunes on macOS Monterey and earlier).
    //
    // This stub listens on RaopPort to prevent "connection refused" errors during
    // mDNS-based device discovery. A full RTSP implementation (ANNOUNCE / SETUP /
    // RECORD / FLUSH / TEARDOWN) should be added here to support AirPlay 1 audio.
    //
    // Phase 4 of the project plan targets a complete RAOP implementation.
    internal class RaopServer
    {
        private readonly AirPlayConfig _config;
        private StreamSocketListener? _listener;

        public RaopServer(AirPlayConfig config) => _config = config;

        public async Task StartAsync()
        {
            _listener = new StreamSocketListener();
            _listener.ConnectionReceived += OnConnection;
            await _listener.BindServiceNameAsync(AirPlayConfig.RaopPort.ToString());
        }

        public Task StopAsync()
        {
            _listener?.Dispose();
            return Task.CompletedTask;
        }

        private async void OnConnection(StreamSocketListener sender,
            StreamSocketListenerConnectionReceivedEventArgs args)
        {
            // Accept and immediately close — prevents the sender from hanging but
            // does not implement the protocol. Replace with an RTSP handler for Phase 4.
            using var socket = args.Socket;
            System.Diagnostics.Debug.WriteLine(
                "[RAOP] Incoming connection from " + args.Socket.Information.RemoteAddress);
            await Task.CompletedTask;
        }
    }
}
