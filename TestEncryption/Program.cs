using System.Text.RegularExpressions;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;

public class GFGEncryption
{
    public static class Test
    {

        static public void Main(string[] args)
        {

            Console.WriteLine("\n[1] encrypt\n[2] decrypt");
            string switcher = Console.ReadLine();
            Console.WriteLine("Put File path : ");
            string SPath = Console.ReadLine();
            string pattern = @"(?:\/|\\)([\w\d_-]+)(\.)";
            Match m = Regex.Match(SPath, pattern);
            string data = File.ReadAllText(SPath);
            string ToReturn = "";
            string publickey = "CHECK234";
            string secretkey = "PKEY4321";
            byte[] secretkeyByte = { };
            secretkeyByte = System.Text.Encoding.UTF8.GetBytes(secretkey);
            byte[] publickeybyte = { };
            publickeybyte = System.Text.Encoding.UTF8.GetBytes(publickey);
            MemoryStream ms = null;
            CryptoStream cs = null;
            if (switcher == "1")
            {
                    try
                    {
                        //encrypt
                        byte[] inputbyteArray = System.Text.Encoding.UTF8.GetBytes(data);
                        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                        {
                            ms = new MemoryStream();
                            cs = new CryptoStream(ms, des.CreateEncryptor(publickeybyte, secretkeyByte), CryptoStreamMode.Write);
                            cs.Write(inputbyteArray, 0, inputbyteArray.Length);
                            cs.FlushFinalBlock();
                            ToReturn = Convert.ToBase64String(ms.ToArray());
                        }
                    Console.Write("\nEncoded String is: \n" + ToReturn);
                     }
                    catch (Exception ex)
                    {
                        throw new Exception(ex.Message, ex.InnerException);
                    }
            } else if (switcher == "2")
            {
                try
                {
                    //decrypt
                    byte[] inputbyteArray = new byte[data.Replace(" ", "+").Length];
                    inputbyteArray = Convert.FromBase64String(data.Replace(" ", "+"));
                    using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                    {
                        ms = new MemoryStream();
                        cs = new CryptoStream(ms, des.CreateDecryptor(publickeybyte, secretkeyByte), CryptoStreamMode.Write);
                        cs.Write(inputbyteArray, 0, inputbyteArray.Length);
                        cs.FlushFinalBlock();
                        Encoding encoding = Encoding.UTF8;
                        ToReturn = encoding.GetString(ms.ToArray());
                    }
                    Console.Write("\nDecoded String is: \n" + ToReturn);
                }
                catch (Exception ae)
                {
                    throw new Exception(ae.Message, ae.InnerException);
                }
            }
            File.WriteAllText($"C:\\hh\\{m.Groups[1]}-{switcher}.txt", ToReturn);


        }



        }
    }