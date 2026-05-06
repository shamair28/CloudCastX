using System;
using CloudCast.Services;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace CloudCast.Views
{
    public sealed partial class MainPage : Page
    {
        private AirPlayService? _service;

        public MainPage()
        {
            this.InitializeComponent();
            this.Loaded += OnLoaded;
            this.Unloaded += OnUnloaded;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            _service = new AirPlayService(VideoPlayer);
            _service.StatusChanged += OnStatusChanged;
            _service.StreamingStarted += OnStreamingStarted;
            _service.StreamingStopped += OnStreamingStopped;
            await _service.StartAsync();
        }

        private async void OnUnloaded(object sender, RoutedEventArgs e)
        {
            if (_service != null)
                await _service.StopAsync();
        }

        private async void OnStatusChanged(string status)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                StatusText.Text = status);
        }

        private async void OnStreamingStarted(string deviceName)
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                StatusPanel.Visibility = Visibility.Collapsed;
                VideoPlayer.Visibility = Visibility.Visible;
                ConnectedDeviceText.Text = deviceName;
            });
        }

        private async void OnStreamingStopped()
        {
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                VideoPlayer.Visibility = Visibility.Collapsed;
                StatusPanel.Visibility = Visibility.Visible;
                StatusText.Text = "Waiting for AirPlay connection…";
                ConnectedDeviceText.Visibility = Visibility.Collapsed;
            });
        }
    }
}
