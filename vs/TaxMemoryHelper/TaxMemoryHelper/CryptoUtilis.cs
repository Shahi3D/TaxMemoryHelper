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
