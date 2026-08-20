using System;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;

namespace Phone2PC.Desktop
{
    public class BleScanner
    {
        private BluetoothLEAdvertisementWatcher _watcher;

        public BleScanner()
        {
            _watcher = new BluetoothLEAdvertisementWatcher();
            // Optional: filter for specific manufacturer data or service UUIDs later.
            // For FIDO, the Service UUID is 0xFFFD.
            
            _watcher.Received += OnAdvertisementReceived;
        }

        public void Start()
        {
            Console.WriteLine("Starting BLE scanner...");
            _watcher.Start();
        }

        public void Stop()
        {
            Console.WriteLine("Stopping BLE scanner...");
            _watcher.Stop();
        }

        private void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            // Just logging the address for now
            Console.WriteLine($"Found BLE Device: {args.BluetoothAddress:X}");
        }
    }
}
