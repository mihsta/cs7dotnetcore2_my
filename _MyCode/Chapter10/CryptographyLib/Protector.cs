using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Packt.CS7
{
    public static class Protector
    {
        // размер соли должен составлять не менее восьми байт
        // мы будем использовать 16 байт
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");

        // число итераций должно быть не меньше 1000, мы будем использовать
        // 2000 итераций

        private static readonly int iterations = 2000;

        public static string Encrypt(string plainText, string password)
        {
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password , salt, iterations);
            aes.Key = pbkdf2.GetBytes(32); // Установить 256-битный ключ 
            aes.IV = pbkdf2.GetBytes(16); // установить 128-битный вектор инициализации

            var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(),CryptoStreamMode.Write))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
            }
            return Convert.ToBase64String(ms.ToArray());
        }

        public static string Dectypt(string cryptoText, string password)
        {
            byte[] crypoBytes = Convert.FromBase64String(cryptoText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password,salt,iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);
            var ms = new MemoryStream();
            using (var cs = new CryptoStream( ms, aes.CreateDecryptor(),CryptoStreamMode.Write))
            {
                cs.Write(crypoBytes, 0, crypoBytes.Length);
            }
            return Encoding.Unicode.GetString(ms.ToArray());
        }

        private static Dictionary<string,user> Users = new Dictionary<string, user>();

        public static user Register(string username, string password)
        {
            //генерация соли
            var rng = RandomNumberGenerator.Create();
            var saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            var saltText = Convert.ToBase64String(saltBytes);

            // генерация соленого и хешированного пароля
            var sha = SHA256.Create();
            var saltedPassword = password + saltText;
            var saltedhashedPassword = Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));

            var user = new user
            {
                Name = username,
                Salt = saltText,
                SaltedHashedPassword = saltedhashedPassword
            };
            Users.Add(user.Name, user);
            return user;
        }

        public static bool CheckPassword (string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }
            var user = Users[username];
            
            // повторная генерация соленого и хешированного пароля
            var sha = SHA256.Create();
            var saltedPassword = password + user.Salt;
            var saltedhashedPassword = Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));

            return (saltedhashedPassword == user.SaltedHashedPassword);            
        }
    public static string PublicKey;
    public static string ToXmlStringExt(this RSA rsa, bool includePrivateParemeters)
    {
        var p = rsa.ExportParameters(includePrivateParemeters);
        XElement xml;
        if (includePrivateParemeters)
        {
            xml = new XElement("RSAKeyValue"
                , new XElement("Modulus", Convert.ToBase64String(p.Modulus))
                , new XElement("Exponent",Convert.ToBase64String(p.Exponent))
                , new XElement("P",Convert.ToBase64String(p.P))
                , new XElement("Q", Convert.ToBase64String(p.Q))
                , new XElement("DP", Convert.ToBase64String(p.DP))
                , new XElement("DQ", Convert.ToBase64String(p.DQ))
                , new XElement("InverseQ", Convert.ToBase64String(p.InverseQ)));            
        }
        else
        {
            xml = new XElement("RSAKeyValue"
                , new XElement("Modulus", Convert.ToBase64String(p.Modulus))
                , new XElement("Exponent", Convert.ToBase64String(p.Exponent)));
        }
        return xml?.ToString();        
    }

    public static void FromXmlStringExt(this RSA rsa, string paremetersAsXml)
    {
        var xml = XDocument.Parse(paremetersAsXml);
        var root = xml.Element("RSAKeyValue");
        var p = new RSAParameters
        {
            Modulus = Convert.FromBase64String(root.Element("Modulus").Value),
            Exponent = Convert.FromBase64String(root.Element("Exponent").Value)
        };

        if (root.Element("P") != null)
        {
            p.P = Convert.FromBase64String(root.Element("P").Value);
            p.Q = Convert.FromBase64String(root.Element("Q").Value);
            p.DP = Convert.FromBase64String(root.Element("DP").Value);
            p.DQ = Convert.FromBase64String(root.Element("DQ").Value);
            p.InverseQ = Convert.FromBase64String(root.Element("InverseQ").Value);            
        }
        rsa.ImportParameters(p);        
    }

    public static string GenerateSignature(string data)
    {
        byte[] dataBytes = Encoding.Unicode.GetBytes(data);
        var sha = SHA256.Create();
        var hashedData = sha.ComputeHash(dataBytes);
        var rsa = RSA.Create();
        PublicKey = rsa.ToXmlStringExt(false);

        return Convert.ToBase64String(rsa.SignHash(hashedData,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1));        
    }

    public static bool ValidateSignature(string data, string signature)
    {
        byte[] dataBytes = Encoding.Unicode.GetBytes(data);
        var sha = SHA256.Create();
        var hashedData = sha.ComputeHash(dataBytes);
        byte[] signatureBytes = Convert.FromBase64String(signature);

        var rsa = RSA.Create();
        rsa.FromXmlStringExt(PublicKey);
        return rsa.VerifyHash(hashedData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);       
    }

    }
}
