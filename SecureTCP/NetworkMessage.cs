using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public static class NetworkMessage
    {
        public static byte[] Wrap (byte[] data)
        {
            byte[] lengthBytes = BitConverter.GetBytes(data.Length);
            byte[] result = new byte[4 + data.Length];

            Array.Copy(data, 0, result, 0, lengthBytes.Length);
            Array.Copy(data, 0, result, 4, data.Length);
            return result;
        }

        public static byte[] UnWrap (byte[] data)
        {
            byte[] trimmed = new byte[data.Length - 4];
            Array.Copy(data, 4, trimmed, 0, data.Length - 4);
            return trimmed;
        }
    }
}