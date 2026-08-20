using System;
using System.Linq;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;

namespace Phone2PC.Desktop
{
    public class BleScanner
    {
        private BluetoothLEAdvertisementWatcher _watcher;
        // The FIDO2 Service UUID is 0xFFFD
        private static readonly Guid FidoServiceUuid = Guid.Parse("0000FFFD-0000-1000-8000-00805F9B34FB");

        public BleScanner()
        {
            _watcher = new BluetoothLEAdvertisementWatcher();

            // Filter only devices advertising the FIDO2 service
            var filter = new BluetoothLEAdvertisementFilter();
            filter.Advertisement.ServiceUuids.Add(FidoServiceUuid);
            _watcher.AdvertisementFilter = filter;

            _watcher.Received += OnAdvertisementReceived;
        }

        public void Start()
        {
            Console.WriteLine("Starting FIDO2 BLE scanner...");
            _watcher.Start();
        }

        public void Stop()
        {
            Console.WriteLine("Stopping FIDO2 BLE scanner...");
            _watcher.Stop();
        }

        private async void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            // Stop watching once we find a FIDO2 device to prevent multiple connection attempts
            _watcher.Stop();

            string deviceName = args.Advertisement.LocalName;
            if (string.IsNullOrEmpty(deviceName)) deviceName = "Unknown FIDO2 Device";

            Console.WriteLine($"\nFound FIDO2 Device: {deviceName} (Address: {args.BluetoothAddress:X})");
            Console.WriteLine($"RSSI: {args.RawSignalStrengthInDBm} dBm");

            await ConnectToDevice(args.BluetoothAddress);
        }

        private async Task ConnectToDevice(ulong bluetoothAddress)
        {
            try
            {
                Console.WriteLine("Connecting...");
                using var device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);

                if (device == null)
                {
                    Console.WriteLine("Failed to connect to device.");
                    return;
                }

                Console.WriteLine($"Connected to {device.Name}. Discovering all services...");
                
                var gattServicesResult = await device.GetGattServicesAsync(BluetoothCacheMode.Uncached);
                if (gattServicesResult.Status != Windows.Devices.Bluetooth.GenericAttributeProfile.GattCommunicationStatus.Success)
                {
                    Console.WriteLine($"Failed to discover services. Status: {gattServicesResult.Status}");
                    return;
                }

                foreach (var service in gattServicesResult.Services)
                {
                    Console.WriteLine($"\nTrying Service: {service.Uuid}");
                    var accessStatus = await service.RequestAccessAsync();
                    Console.WriteLine($" Access Status: {accessStatus}");

                    if (accessStatus == Windows.Devices.Enumeration.DeviceAccessStatus.Allowed)
                    {
                        var charResult = await service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
                        if (charResult.Status == Windows.Devices.Bluetooth.GenericAttributeProfile.GattCommunicationStatus.Success)
                        {
                            Console.WriteLine($" Found {charResult.Characteristics.Count} characteristics.");
                        }
                        else
                        {
                            Console.WriteLine($" Failed to discover characteristics. Status: {charResult.Status}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during connection: {ex.Message}");
            }
        }
    }
}

