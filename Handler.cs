using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
namespace FileEncryption.cs
{
    class Handler
    {
        private static byte[] encrypt_aes256(byte[] unencrypted, byte[] key, byte[] salt)
        {
            byte[] encrypted = null;
            using (MemoryStream memory_stream = new MemoryStream())
            {
                using (RijndaelManaged aes256 = new RijndaelManaged())
                {
                    aes256.KeySize = 256; //64 chars equals aes256 key size
                    aes256.BlockSize = 128;//block = algorithm(256)/2
                    Rfc2898DeriveBytes rfc_key = new Rfc2898DeriveBytes(key, salt, 2000);
                    aes256.Key = rfc_key.GetBytes(aes256.KeySize / 8);
                    aes256.IV = rfc_key.GetBytes(aes256.BlockSize / 8);
                    aes256.Mode = CipherMode.CBC;//encrypts into blocks
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, aes256.CreateEncryptor(), CryptoStreamMode.Write)) //creates the encryptor
                    {
                        crypto_stream.Write(unencrypted, 0, unencrypted.Length); //writes encrypted bytes to a memory stream
                        crypto_stream.Close();
                    }
                    encrypted = memory_stream.ToArray();
                }
            }
            return encrypted;
        }
        private static byte[] decrypt_aes256(byte[] encrypted, byte[] key, byte[] salt)
        {
            byte[] unencrypted = null;
            using (MemoryStream memory_stream = new MemoryStream())
            {
                using (RijndaelManaged aes256 = new RijndaelManaged())
                {
                    aes256.KeySize = 256; //64 chars equals aes256 key size
                    aes256.BlockSize = 128;//block = algorithm(256)/2
                    Rfc2898DeriveBytes rfc_key = new Rfc2898DeriveBytes(key, salt, 2000);
                    aes256.Key = rfc_key.GetBytes(aes256.KeySize / 8);
                    aes256.IV = rfc_key.GetBytes(aes256.BlockSize / 8);
                    aes256.Mode = CipherMode.CBC;//encrypts into blocks
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, aes256.CreateDecryptor(), CryptoStreamMode.Write)) //creates the decryptor
                    {
                        crypto_stream.Write(encrypted, 0, encrypted.Length); //writes decrypted bytes to a memory stream
                        crypto_stream.Close();
                    }
                    unencrypted = memory_stream.ToArray();
                }
            }
            return unencrypted;
        }

        public static void encrypt(string file, string key, string salt)
        {
            byte[] unencrypted = File.ReadAllBytes(file);
            File.Delete(file);
            byte[] key_bytes = Encoding.UTF8.GetBytes(key);
            key_bytes = SHA256Managed.Create().ComputeHash(key_bytes);
            byte[] salt_bytes = Encoding.UTF8.GetBytes(salt);
            salt_bytes = SHA256Managed.Create().ComputeHash(salt_bytes);
            byte[] encrypted = encrypt_aes256(unencrypted, key_bytes, salt_bytes);
            File.WriteAllBytes(file, encrypted);
        }
         public static void decrypt(string file, string key, string salt)
        {
            byte[] encrypted = File.ReadAllBytes(file);
            File.Delete(file);
            byte[] key_bytes = Encoding.UTF8.GetBytes(key);
            key_bytes = SHA256Managed.Create().ComputeHash(key_bytes);
            byte[] salt_bytes = Encoding.UTF8.GetBytes(salt);
            salt_bytes = SHA256Managed.Create().ComputeHash(salt_bytes);
            byte[] decrypted = decrypt_aes256(encrypted, key_bytes, salt_bytes);
            File.WriteAllBytes(file, decrypted);
        }


    }
}
