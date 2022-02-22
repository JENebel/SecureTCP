using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class EncryptionSettings
    {
        public enum AES { AES_128, AES_256 }
        public enum RSA { RSA_1024, RSA_2048, RSA_4096, RSA_8192, RSA_16384 }

        private AES Aes { get; set; }
        private RSA Rsa { get; set; }

        public short AesKeySize
        {
            get
            {
                short aes = 0;
                switch (Aes)
                {
                    case AES.AES_128:
                        aes = 128;
                        break;
                    case AES.AES_256:
                        aes = 256;
                        break;
                    default:
                        break;
                }
                return aes;
            }
        }
        public short RsaKeySize
        { 
            get
            {
                short rsa = 0;
                switch (Rsa)
                {
                    case RSA.RSA_1024:
                        rsa = 1024;
                        break;
                    case RSA.RSA_2048:
                        rsa = 2048;
                        break;
                    case RSA.RSA_4096:
                        rsa = 4096;
                        break;
                    case RSA.RSA_8192:
                        rsa = 8192;
                        break;
                    case RSA.RSA_16384:
                        rsa = 16384;
                        break;
                }
                return rsa;
            }
        }

        public EncryptionSettings()
        {
            Aes = AES.AES_256;
            Rsa = RSA.RSA_4096;
        }

        public EncryptionSettings(AES aes, RSA rsa)
        {
            Aes = aes;
            Rsa = rsa;
        }
    }
}