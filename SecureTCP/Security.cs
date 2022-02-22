using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public static class Security
    {
        public static byte[] VerifiedData(RSA verifier, byte[] data)
        {
            byte[] signature = data.Take(512).ToArray();
            byte[] message = data.Skip(512).ToArray();
            if(!verifier.VerifyData(message, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                throw new BadSignatureException("Bad signature. Wasn't signed by the original key");
            return message;
        }

        public static byte[] SignData(RSA rsa, byte[] data)
        {
            byte[] msgWithSignature = new byte[512 + data.Length];
            byte[] signed = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            Array.Copy(signed, msgWithSignature, 512);
            Array.Copy(data, 0, msgWithSignature, 512, data.Length);
            return msgWithSignature;
        }
    }

    public class BadSignatureException : Exception
    {
        public BadSignatureException(string message) : base(message)
        { }
    }
}
