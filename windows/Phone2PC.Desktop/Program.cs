using System;
using System.Threading.Tasks;

namespace Phone2PC.Desktop
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Phone2PC Windows Unlock Client");
            
            var scanner = new BleScanner();
            scanner.Start();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            
            scanner.Stop();
        }
    }
}

