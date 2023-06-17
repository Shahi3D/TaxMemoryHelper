/////////////////////////////////////////////////////////////////
/// This code is not mine and it's from the document provided by
/// Iranian National Tax Administration. You can find the codes 
/// in RC_TICS.IS_V1.1 pdf file.
/////////////////////////////////////////////////////////////////

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Crypto.Paddings;

namespace TaxMemoryHelper
{
    public class CryptoUtilis
    {
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
        }

        public static string NormalJson(
            object obj,
            Dictionary<string, string> header)
        {
            if (obj == null && header == null)
                throw new AccessViolationException();

            Dictionary<string, object> map = null;

            if (obj != null)
            {
                if (obj.GetType() == typeof(string))
                {
                    if (obj.ToString().Trim().StartsWith("["))
                    {
                        obj = ToList<object>((string)obj);
                    }
                    else
                    {
                        obj = JsonConvert.DeserializeObject<object>((string)obj);
                    }
                }
                if (obj.GetType().IsGenericType &&
                    obj.GetType().GetGenericTypeDefinition() == typeof(List<>))
                {
                    PacketsWrapper packetsWrapper = new PacketsWrapper(obj);
                    map = ToDictionary<object>(packetsWrapper);
                }
                else
                {
                    map = ToDictionary<object>(obj);
                }
            }

            if (map == null && header != null)
            {
                map = new Dictionary<string, object>();
                foreach (var headerElem in header)
                    map.Add(headerElem.Key, headerElem.Value.ToString());
            }

            if (map != null && header != null)
            {
                foreach (var headerElem in header)
                    map.Add(headerElem.Key, headerElem.Value);
            }

            Dictionary<String, object> result = new Dictionary<string, object>();

            result = JsonHelper.DeserializeAndFlatten(JsonConvert.SerializeObject(map));

            StringBuilder sb = new StringBuilder();

            HashSet<string> keysSet = new HashSet<string>(result.Keys);

            if (keysSet == null || !keysSet.Any())
            {
                return null;
            }

            var keys = keysSet.OrderBy(x => x).ToList();

            foreach (var key in keys)
            {
                string textValue;
                object value;

                if (result.TryGetValue(key, out value))
                {
                    if (value != null)
                    {
                        if (value.Equals(true) || value.Equals(false) ||
                            value.ToString().Equals("False") || value.ToString().Equals("True"))
                        {
                            textValue = value.ToString().ToLower();
                        }
                        else
                        {
                            textValue = value.ToString();
                        }

                        if (textValue == null || textValue.Equals(""))
                        {
                            textValue = "#";
                        }
                        else
                        {
                            textValue = textValue.Replace("#", "##");
                        }
                    }
                    else
                    {
                        textValue = "#";
                    }
                }
                else
                {
                    textValue = "#";
                }
                sb.Append(textValue).Append("#");
            }

            return sb.Remove(sb.Length - 1, 1).ToString();
        }

        public static string SignData(string stringToBeSigned, string privateKey)
        {
            // add header and footer
            var pem = "-----BEGIN PRIVATE KEY-----\n" + privateKey + "\n-----END PRIVATE KEY-----";

            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter privateKeyParams = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(
                (RsaPrivateCrtKeyParameters)privateKeyParams);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters((RSAParameters)rsaParams);

            var dataBytes = Encoding.UTF8.GetBytes(stringToBeSigned);
            return Convert.ToBase64String(csp.SignData(
                dataBytes, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1));
        }

        public static string AesEncrypt(byte[] payload, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesEngine());

            byte[] baPayload = new byte[0];

            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, iv, baPayload));

            var cipherBytes = new byte[cipher.GetOutputSize(payload.Length)];

            int len = cipher.ProcessBytes(payload, 0, payload.Length, cipherBytes, 0);

            cipher.DoFinal(cipherBytes, len);

            return Convert.ToBase64String(cipherBytes);
        }

        public static byte[] Xor(byte[] left, byte[] right)
        {
            byte[] val = new byte[left.Length];
            for (int i = 0; i < left.Length; i++)
            {
                val[i] = (byte)(left[i] ^ right[i]);
            }
           
            return val;
        }

        public static String EncryptData(string stringToBeEncrypted, string publicKey)
        {
            try
            {
                AsymmetricKeyParameter asymmetricKeyParameter =
                    PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
                
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;

                RSAParameters rsaParameters = new RSAParameters();

                rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();

                RSACng rsa = new RSACng();
                rsa.ImportParameters(rsaParameters);

                string base64 = Convert.ToBase64String(
                    rsa.Encrypt(Encoding.UTF8.GetBytes(stringToBeEncrypted),
                    RSAEncryptionPadding.OaepSHA256));

                if(base64.Length %4 ==3)
                {
                    base64 += "=";
                }else if(base64.Length %4 == 2)
                {
                    base64 += "==";
                }
                return base64;
            }
            catch (Exception ex)
            {
                return "error";
            }
        }

        private static string getKey(string rootKey, string myKey)
        {
            if(rootKey != null)
            {
                return rootKey + "." + myKey;
            }
            else
            {
                return myKey;
            }
        }

        public static Dictionary<string, TValue> ToDictionary<TValue>(object obj)
        {
            var json = JsonConvert.SerializeObject(obj);

            var dictionary = JsonConvert.DeserializeObject<Dictionary<string, TValue>>(json);

            return dictionary;
        }

        public static List<Dictionary<string, object>> ToList<TValue>(string obj)
        {
            var dictionary = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(obj);

            return dictionary;

        }        
    }

    internal class PacketsWrapper
    {
        private object _obj;

        public PacketsWrapper()
        {
        }

        public PacketsWrapper(object obj)
        {
            this._obj = obj;
        }

        public object GetPackets()
        {
            return _obj;
        }

        public void SetPackets(object obj)
        {
            this._obj = obj;
        }
    }
}
