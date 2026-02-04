/* sloooooooooooooooow, use the rust one */

using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;

class Program
{
    static long iterations = 1000; // Replace with your own key length, we're going to iterate.
    // the maximum key size of a 32 bit unsigned integer is 2^32 or 4294967295
    static byte[] elfelfSignature = new byte[] { 0x7f, 0x45, 0x4c, 0x46 };
    static byte[] lzmaelfSignature = new byte[] { 0x5d, 0x00, 0x00, 0x80 };
    static byte[] gzipelfSignature = new byte[] { 0x1f, 0x8b };
    static byte[] ubootSig = new byte[] { 0x27, 0x05, 0x19, 0x56 };
    
    static void Main(string[] args)
    {
    
        if (args.Length != 2)
        {
            
            Console.WriteLine("Usage: {0} <key> <filename>", System.AppDomain.CurrentDomain.FriendlyName);
            return;
        }
        string keyarg = args[0];
        int value;
        int realkey;

        if (int.TryParse(keyarg, out value)) // blech
        {
            realkey = value;
        }
        else
        {
            Console.WriteLine($"{keyarg} is not a valid integer.");
            return;
        }
        
        
        string filename = args[1];

        if (!File.Exists(filename))
        {
            Console.WriteLine("File not found.");
            return;
        }
        
        FileInfo fi = new FileInfo(filename);
        long filesize = fi.Length;

        if(filesize > (1024*1024*1024))
        {
            Console.WriteLine("Anything greater than 1 MB will take too long. We're only doing the first 1mb");
            //return;
        }
        byte[] fileBytes = new byte[filesize]; 
        FileStream fs = File.OpenRead(filename);
        
        // Read the file into a byte array., we only want the first 1 mb or this will take until the end of time
        int bytesRead = fs.Read(fileBytes, 0, (1024 * 1024 * 1024));
        //   byte[] fileBytes = File.ReadAllBytes(filename);
        fs.Close();

        // Divide the file into chunks and process them in parallel.
        int chunkSize = fileBytes.Length / Environment.ProcessorCount;
        Task[] tasks = new Task[Environment.ProcessorCount];

        for (int i = 0; i < Environment.ProcessorCount; i++)
        {
            int chunkStart = i * chunkSize;
            int chunkEnd = (i == Environment.ProcessorCount - 1) ? fileBytes.Length : (i + 1) * chunkSize;
            
            tasks[i] = Task.Run(() => {
                for (int j = chunkStart; j < chunkEnd - elfSignature.Length; j++)
                {
                    bool match = true;
                    for (int k = 0; k < elfSignature.Length; k++)
                    {
                        byte xoredByte = (byte)(fileBytes[j + k] ^ realkey);
                        if (xoredByte != elfSignature[k])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        Console.WriteLine("Match found at offset 0x{00000000:X}", j);
                    }
                }
            });
        }

        // Wait for all tasks to complete.
        Task.WaitAll(tasks);

        Console.WriteLine("Done.");
    }
}

