using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class Crypto
    {
        private Aes encrypter;
        private RSACryptoServiceProvider signer;
        private RSACryptoServiceProvider verifier;

        public Crypto(Aes encrypter, RSACryptoServiceProvider signer, RSACryptoServiceProvider verifier)
        {
            this.encrypter = encrypter;
            this.signer = signer;
            this.verifier = verifier;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] iv = data.Take(16).ToArray();
            byte[] message = data.Skip(16).ToArray();
            return encrypter.DecryptCbc(message, iv);
        }

        public byte[] Encrypt(byte[] data)
        {
            encrypter.GenerateIV();
            return encrypter.EncryptCbc(data, encrypter.IV);
        }

        public byte[] VerifiedData(byte[] data)
        {
            byte[] signature = data.Take(verifier.KeySize / 8).ToArray();
            byte[] message = data.Skip(verifier.KeySize / 8).ToArray();
            if(!verifier.VerifyData(message, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                throw new BadSignatureException("Bad signature. Wasn't signed by the original key");
            return message;
        }

        public byte[] SignData(byte[] data)
        {
            byte[] msgWithSignature = new byte[512 + data.Length];
            byte[] signed = signer.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
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
