using System.Text.RegularExpressions;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using Newtonsoft.Json;
using RuriLib.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Media;
using System.Diagnostics;

namespace RuriLib
{
    public static class IOManager
    {
        static public void Main(string[] args)
        {
            Console.WriteLine("Put File path : ");
            string SPath = Console.ReadLine();
            LoadConfig(SPath, true);
            //Console.WriteLine("\n[1] encrypt\n[2] decrypt");
            //string switcher = Console.ReadLine();
            //Console.WriteLine("Put File path : ");
            //string SPath = Console.ReadLine();
            //string pattern = @"(?:\/|\\)([\w\d_-]+)(\.)";
            //Match m = Regex.Match(SPath, pattern);
            //string data = File.ReadAllText(SPath);
            //string ToReturn = "";
            //string publickey = "CHECK234";
            //string secretkey = "PKEY4321";
            //byte[] secretkeyByte = { };
            //secretkeyByte = System.Text.Encoding.UTF8.GetBytes(secretkey);
            //byte[] publickeybyte = { };
            //publickeybyte = System.Text.Encoding.UTF8.GetBytes(publickey);
            //MemoryStream ms = null;
            //CryptoStream cs = null;
            //if (switcher == "1")
            //{
            //    try
            //    {
            //        //encrypt
            //        byte[] inputbyteArray = System.Text.Encoding.UTF8.GetBytes(data);
            //        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            //        {
            //            ms = new MemoryStream();
            //            cs = new CryptoStream(ms, des.CreateEncryptor(publickeybyte, secretkeyByte), CryptoStreamMode.Write);
            //            cs.Write(inputbyteArray, 0, inputbyteArray.Length);
            //            cs.FlushFinalBlock();
            //            ToReturn = Convert.ToBase64String(ms.ToArray());
            //        }
            //        Console.Write("\nEncoded String is: \n" + ToReturn);
            //    }
            //    catch (Exception ex)
            //    {
            //        throw new Exception(ex.Message, ex.InnerException);
            //    }
            //}
            //else if (switcher == "2")
            //{
            //    try
            //    {

            //        byte[] inputbyteArray = new byte[data.Replace(" ", "+").Length];
            //        inputbyteArray = Convert.FromBase64String(data.Replace(" ", "+"));
            //        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            //        {
            //            ms = new MemoryStream();
            //            cs = new CryptoStream(ms, des.CreateDecryptor(publickeybyte, secretkeyByte), CryptoStreamMode.Write);
            //            cs.Write(inputbyteArray, 0, inputbyteArray.Length);
            //            cs.FlushFinalBlock();
            //            Encoding encoding = Encoding.UTF8;
            //            ToReturn = encoding.GetString(ms.ToArray());
            //        }
            //        Console.Write("\nDecoded String is: \n" + ToReturn);
            //    }
            //    catch (Exception ae)
            //    {
            //        throw new Exception(ae.Message, ae.InnerException);
            //    }
            //}
            //File.WriteAllText($"C:\\hh\\{m.Groups[1]}-{switcher}.txt", ToReturn);


        }


        /// <summary>
        /// Deserializes a Config object from a loli-formatted string.
        /// </summary>
        /// <param name="config">The loli-formatted string</param>
        /// <returns>An instance of the Config object</returns>
        public static Config DeserializeConfig(string config)
        {
            var split = config.Split(new string[] { "[SETTINGS]", "[SCRIPT]" }, StringSplitOptions.RemoveEmptyEntries);
            return new Config(JsonConvert.DeserializeObject<ConfigSettings>(split[0]), split[1].TrimStart('\r', '\n'));
        }
        /// <summary>
        /// Loads a Config object from a .loli file.
        /// </summary>
        /// <param name="fileName">The config file</param>
        /// <returns>A Config object</returns>
        public static Config LoadConfig(string fileName, bool omega = false)
        {
            if (omega) { return LoadConfigX(fileName); }
            return DeserializeConfig(File.ReadAllText(fileName));
        }

        private static Config LoadConfigX(string fileName)
        {
            return DeserializeConfigX(File.ReadAllText(fileName));
        }

        private static Config DeserializeConfigX(string config)
        {
            if (!config.Contains("ID") && !config.Contains("Body"))
                try
                {
                    byte[] bytes = Convert.FromBase64String(config);
                    config = Encoding.UTF8.GetString(bytes);
                    config = DecryptX(Regex.Match(config, "0x;(.*?)x;0").Groups[1].Value, "THISISOBmodedByForlax");
                }
                catch
                {
                    config = DecryptX(Regex.Match(config, "0x;(.*?)x;0").Groups[1].Value, "0THISISOBmodedByForlaxNIGGAs");
                }
            else
            {
                var bytes = Convert.FromBase64String(BellaCiao(Regex.Match(config, "\"Body\": \"(.*?)\"").Groups[1].Value, 2));
                config = DecryptX(Regex.Match(Encoding.UTF8.GetString(bytes), "x0;(.*?)0;x").Groups[1].Value, "0THISISOBmodedByForlaxNIGGAs");
            }

            string[] array = config.Split(new string[]
                {
                "[SETTINGS]",
                "[SCRIPT]"
                }, StringSplitOptions.RemoveEmptyEntries);
            return new Config(JsonConvert.DeserializeObject<ConfigSettings>(array[0]), array[1].TrimStart(new char[]
            {
                '\r',
                '\n'
            }));
        }

        private static string DecryptX(string cipherText, string passPhrase)
        {
            byte[] array = Convert.FromBase64String(cipherText);
            byte[] salt = array.Take(32).ToArray<byte>();
            byte[] rgbIV = array.Skip(32).Take(32).ToArray<byte>();
            byte[] array2 = array.Skip(64).Take(array.Length - 64).ToArray<byte>();
            string script;
            using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000))
            {
                byte[] bytes = rfc2898DeriveBytes.GetBytes(32);
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.BlockSize = 256;
                    rijndaelManaged.Mode = CipherMode.CBC;
                    rijndaelManaged.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor(bytes, rgbIV))
                    {
                        using (MemoryStream memoryStream = new MemoryStream(array2))
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                            {
                                byte[] array3 = new byte[array2.Length];
                                int count = cryptoStream.Read(array3, 0, array3.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                script = Encoding.UTF8.GetString(array3, 0, count);
                            }
                        }
                    }
                }
            }
            return script;
        }

        public static string BellaCiao(string helpme, int op)
        {
            if (op != 1)
            {
                string str2 = "ay$a5%&jwrtmnh;lasjdf98787OMGFORLAX";
                string str3 = "abc@98797hjkas$&asd(*$%GJMANIGE";
                byte[] buffer = new byte[0];
                buffer = Encoding.UTF8.GetBytes(str3.Substring(0, 8));
                byte[] buffer2 = new byte[0];
                buffer2 = Encoding.UTF8.GetBytes(str2.Substring(0, 8));
                byte[] buffer3 = new byte[helpme.Length / 2];
                for (int i = 0; i < buffer3.Length; i++)
                {
                    buffer3[i] = Convert.ToByte(helpme.Substring(i * 2, 2), 0x10);
                }
                helpme = Encoding.UTF8.GetString(buffer3);
                byte[] buffer4 = new byte[helpme.Replace(" ", "+").Length];
                buffer4 = Convert.FromBase64String(helpme.Replace(" ", "+"));
                using (DESCryptoServiceProvider provider2 = new DESCryptoServiceProvider())
                {
                    MemoryStream stream = new MemoryStream();
                    CryptoStream stream3 = new CryptoStream(stream, provider2.CreateDecryptor(buffer2, buffer), CryptoStreamMode.Write);
                    stream3.Write(buffer4, 0, buffer4.Length);
                    stream3.FlushFinalBlock();
                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            string s = "";
            string str5 = "ay$a5%&jwrtmnh;lasjdf98787OMGFORLAX";
            string str6 = "abc@98797hjkas$&asd(*$%GJMANIGE";
            byte[] rgbIV = new byte[0];
            rgbIV = Encoding.UTF8.GetBytes(str6.Substring(0, 8));
            byte[] rgbKey = new byte[0];
            rgbKey = Encoding.UTF8.GetBytes(str5.Substring(0, 8));
            byte[] bytes = Encoding.UTF8.GetBytes(helpme);
            using (DESCryptoServiceProvider provider = new DESCryptoServiceProvider())
            {
                CryptoStream stream1 = new CryptoStream(new MemoryStream(), provider.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                stream1.Write(bytes, 0, bytes.Length);
                stream1.FlushFinalBlock();
                MemoryStream stream2 = new MemoryStream();
                s = Convert.ToBase64String(stream2.ToArray());
                StringBuilder builder = new StringBuilder();
                byte[] buffer8 = Encoding.UTF8.GetBytes(s);
                int index = 0;
                while (true)
                {
                    if (index >= buffer8.Length)
                    {
                        s = builder.ToString();
                        break;
                    }
                    builder.Append(buffer8[index].ToString("X2"));
                    index++;
                }
            }
            return s;
        }



    }
}





