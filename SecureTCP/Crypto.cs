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
            byte[] signature = data.Take(signatureLength).ToArray();
            byte[] iv = data.Skip(signatureLength).Take(16).ToArray();
            byte[] message = data.Skip(16 + signatureLength).ToArray();
            if (!verifier.VerifyHash(SHA512.HashData(message), signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new BadSignatureException("Signature validation failed");
            return encrypter.DecryptCbc(message, iv);
        }

        public byte[] Encrypt(byte[] data)
        {
            encrypter.GenerateIV();
            byte[] encryptedMessage = encrypter.EncryptCbc(data, encrypter.IV).ToArray();
            byte[] signature = signer.SignHash(SHA512.HashData(encryptedMessage), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return signature.Concat ( // Signature
                    encrypter.IV.Concat ( // IV
                     encryptedMessage)).ToArray(); // Encrypted data
        }
    }

    public class BadSignatureException : Exception
    {
        public BadSignatureException(string message) : base(message)
        { }
    }
}
