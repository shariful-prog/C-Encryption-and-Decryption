using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace XorEncryption
{
    internal class Program
    {

        public const string Secretkey = "AlongSecrectKeyG";
        public const string ivSecret = "qpoUHiRDLgkAliep";


        static void Main(string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            Console.WriteLine("Hello World!");

            Program program = new Program();

            string text = "https://www.javainuse.com/aesgenerator";

            //var sad = Convert.ToBase64String(program.Encrypt(text));
            //Console.WriteLine(text);
            //Console.WriteLine(sad);
            //var dasd = program.Decrypt(sad);
            //Console.WriteLine(dasd);

            var newENcr = program.EncryptNEW2(text);

            Console.WriteLine("Dsd");
        }


        #region XOR Encryption
        string XorEncryption(string text, string key)
        {
            var result = new StringBuilder();
            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ key[c % key.Length]));
            return result.ToString();
        }

        #endregion

        #region AES Encryption

        // ECB Implementation
        //byte[] Encrypt(string input)
        //{
        //    int KEY_SIZE_inBytes = ivSecret.Length;


        //    var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
        //    var hash = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(Secretkey));
        //    var key = new byte[KEY_SIZE_inBytes];
        //    var iv = new byte[KEY_SIZE_inBytes];

        //    Buffer.BlockCopy(hash, 0, key, 0, KEY_SIZE_inBytes);
        //    Buffer.BlockCopy(hash, KEY_SIZE_inBytes, iv, 0, KEY_SIZE_inBytes);

        //    using (var cipher = new AesCryptoServiceProvider().CreateEncryptor(key, iv))
        //    using (var output = new MemoryStream())
        //    {
        //        using (var cryptoStream = new CryptoStream(output, cipher, CryptoStreamMode.Write))
        //        {
        //            var inputBytes = Encoding.UTF8.GetBytes(input);
        //            cryptoStream.Write(inputBytes, 0, inputBytes.Length);
        //        }
        //        return output.ToArray();
        //    }
        //}

        //string Decrypt(string textB)
        //{
        //    byte[] encryptedBytes = Convert.FromBase64String(textB);
        //    int KEY_SIZE_inBytes = ivSecret.Length;

        //    var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
        //    var hash = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(Secretkey));
        //    var key = new byte[KEY_SIZE_inBytes];
        //    var iv = new byte[KEY_SIZE_inBytes];

        //    Buffer.BlockCopy(hash, 0, key, 0, KEY_SIZE_inBytes);
        //    Buffer.BlockCopy(hash, KEY_SIZE_inBytes, iv, 0, KEY_SIZE_inBytes);

        //    using (var cipher = new AesCryptoServiceProvider().CreateDecryptor(key, iv))
        //    using (var source = new MemoryStream(encryptedBytes))
        //    using (var output = new MemoryStream())
        //    {
        //        using (var cryptoStream = new CryptoStream(source, cipher, CryptoStreamMode.Read))
        //        {
        //            cryptoStream.CopyTo(output);
        //        }
        //        return Encoding.UTF8.GetString(output.ToArray());
        //    }
        //}

        //CBC Implementation
        //string EncryptString(string plainText)
        //{
        //    var rnd = new Random();
        //    var iv = new byte[ivSecret.Length];  // For this example, I'll use a random 16-byte key.
        //    rnd.NextBytes(iv);
        //    byte[] array;
        //    string test = "";
        //    using (Aes aes = Aes.Create())
        //    {
        //        var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
        //        aes.Key = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(Secretkey));
        //        //aes.Key = Encoding.UTF8.GetBytes(Secretkey);

        //        aes.IV = iv;
        //        test = Convert.ToBase64String(iv);
        //        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        //        using (MemoryStream memoryStream = new MemoryStream())
        //        {
        //            using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
        //            {
        //                using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
        //                {
        //                    streamWriter.Write(plainText);
        //                }

        //                array = memoryStream.ToArray();
        //            }
        //        }
        //    }

        //    return Convert.ToBase64String(array);
        //}

        #endregion


        //CBC Encryption with IV fixed
        string EncryptNEW2(string plainText)
        {
            byte[] cipherData;
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(Secretkey);
            var iv = new byte[16];  // For this example, I'll use a random 16-byte key.
            iv = Encoding.ASCII.GetBytes(ivSecret);
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                }

                cipherData = ms.ToArray();
            }

            //byte[] combinedData = new byte[aes.IV.Length + cipherData.Length];
            //Array.Copy(aes.IV, 0, combinedData, 0, aes.IV.Length);
            //Array.Copy(cipherData, 0, combinedData, aes.IV.Length, cipherData.Length);
            string cTxt = Convert.ToBase64String(cipherData);
            return cTxt;
        }

    }


}
