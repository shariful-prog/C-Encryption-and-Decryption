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

            var newENcr = program.AES_CBC_Encryption(text);

            Console.WriteLine("Dsd");
        }


        #region XOR Encryption 
        // Same method to encrypt and decrypt string

        string XorEncryption(string text, string key)
        {
            var result = new StringBuilder();
            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ key[c % key.Length]));
            return result.ToString();
        }

        #endregion

        #region AES Encryption

        //CBC Encryption with IV fixed
        string AES_CBC_Encryption(string plainText)
        {
            byte[] cipherData;
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(Secretkey);
            var iv = new byte[16];
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
        #endregion

        #region Decrypt String in Different Enviroment

        //Decrypt in c#
        string Decrypt(string textB)
        {
            byte[] encryptedBytes = Convert.FromBase64String(textB);
            int KEY_SIZE_inBytes = ivSecret.Length;

            var sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
            var hash = sha256CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(Secretkey));
            var key = new byte[KEY_SIZE_inBytes];
            var iv = new byte[KEY_SIZE_inBytes];

            Buffer.BlockCopy(hash, 0, key, 0, KEY_SIZE_inBytes);
            Buffer.BlockCopy(hash, KEY_SIZE_inBytes, iv, 0, KEY_SIZE_inBytes);

            using (var cipher = new AesCryptoServiceProvider().CreateDecryptor(key, iv))
            using (var source = new MemoryStream(encryptedBytes))
            using (var output = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(source, cipher, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(output);
                }
                return Encoding.UTF8.GetString(output.ToArray());
            }


        }



        //Decryption in Javascript
        //        function decrypt(transitmessage, pass)
        //        {
        //            var ciphertext = "EV/frugFASzg9gD9SP6iXX//djrVsuRlCwRcaigY22LKtH/xPgVcTq0Kj8M65OVloQwEyQ/FfWtk3RmjmuqbeQ==";
        //            var key = "AlongSecrectKeyG";
        //            var iv = "qpoUHiRDLgkAliep";

        //            var ciphertextWA = CryptoJS.enc.Base64.parse(ciphertext);
        //            var keyWA = CryptoJS.enc.Utf8.parse(key);
        //            var ivWA = CryptoJS.enc.Utf8.parse(iv);
        //            var ciphertextCP = { ciphertext: ciphertextWA };

        //        var decrypted = CryptoJS.AES.decrypt(
        //            ciphertextCP,
        //            keyWA,
        //            { iv: ivWA }
        //);

        //console.log(decrypted.toString(CryptoJS.enc.Utf8));
        //}




        #endregion




    }


}
