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
        private ECDsa signer;
        private ECDsa verifier;
        private int signatureLength;

        public Crypto(Aes encrypter, ECDsa signer, ECDsa verifier)
        {
            this.encrypter = encrypter;
            this.signer = signer;
            this.verifier = verifier;
            signatureLength = signer.GetMaxSignatureSize(DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
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
            byte[] signature = data.Take(signatureLength).ToArray();
            byte[] message = data.Skip(signatureLength).ToArray();
            if(!verifier.VerifyData(message, signature, HashAlgorithmName.SHA512))
                throw new BadSignatureException("Bad signature. Wasn't signed by the original key");
            return message;
        }

        public byte[] SignData(byte[] data)
        {
            byte[] msgWithSignature = new byte[signatureLength + data.Length];
            byte[] signature = signer.SignHash(SHA512.HashData(data), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Array.Copy(signature, msgWithSignature, signatureLength);
            Array.Copy(data, 0, msgWithSignature, signatureLength, data.Length);
            return msgWithSignature;
        }
    }

    public class BadSignatureException : Exception
    {
        public BadSignatureException(string message) : base(message)
        { }
    }
}
