using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
namespace FileEncryption.cs
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("File encryption by Masinator237");
            Console.WriteLine("Decrypt (d) or Encrypt (e) ?");
            string response = Console.ReadLine();
            response = response.ToLower();
            Console.WriteLine("File ?");
            string file = Console.ReadLine();
            Console.WriteLine("Password ?");
            string pass = Console.ReadLine();
            Console.WriteLine("Salt ?");
            string salt = Console.ReadLine();
            if (response == "decrypt" || response == "d")
            {
                Handler.decrypt(file, pass, salt);
            }
            else if (response == "encrypt" || response == "e")
            {
                Handler.encrypt(file, pass, salt);
            }
            Console.ReadLine();
        }
    }
}
