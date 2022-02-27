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
        public enum AesType { AES_128, AES_256 }
        public enum CurveType { BrainpoolP256, BrainpoolP384, BrainpoolP512, Nist256, Nist384, Nist521 }

        private AesType Aes { get; set; }
        private CurveType Curve { get; set; }

        public short AesKeySize
        {
            get
            {
                switch (Aes)
                {
                    case AesType.AES_128:
                        return 128;
                    case AesType.AES_256:
                        return 256;
                    default:
                        throw new ArgumentException("Not legal AES keySize");
                }
            }
        }

        public ECCurve ECCurve
        { 
            get
            {
                switch (Curve)
                {
                    case CurveType.BrainpoolP256:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    case CurveType.BrainpoolP384:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    case CurveType.BrainpoolP512:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    case CurveType.Nist256:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    case CurveType.Nist384:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    case CurveType.Nist521:
                        return ECCurve.NamedCurves.brainpoolP256r1;
                    default:
                        throw new ArgumentException("Curve does not exist");
                }
            }
        }

        public EncryptionSettings()
        {
            Aes = AesType.AES_256;
            Curve = CurveType.BrainpoolP512;
        }

        public EncryptionSettings(AesType aes, CurveType curve)
        {
            Aes = aes;
            Curve = curve;
        }

        public byte[] ToBytes()
        {
            byte[] ESBytes = new byte[2];
            switch (Aes)
            {
                case AesType.AES_128:
                    ESBytes[0] = 0;
                    break;
                case AesType.AES_256:
                    ESBytes[0] = 1;
                    break;
                default:
                    throw new Exception("AES mode not recognized");
            }
            switch (Curve)
            {
                case CurveType.BrainpoolP256:
                    ESBytes[1] = 0;
                    break;
                case CurveType.BrainpoolP384:
                    ESBytes[1] = 1;
                    break;
                case CurveType.BrainpoolP512:
                    ESBytes[1] = 2;
                    break;
                case CurveType.Nist256:
                    ESBytes[1] = 3;
                    break;
                case CurveType.Nist384:
                    ESBytes[1] = 4;
                    break;
                case CurveType.Nist521:
                    ESBytes[1] = 5;
                    break;
                default:
                    throw new Exception("Curve mode not recognized");
            }
            return ESBytes;
        }

        public static EncryptionSettings FromBytes(byte[] ESBytes)
        {
            AesType aes;
            CurveType curve;
            switch (ESBytes[0])
            {
                case 0:
                    aes = AesType.AES_128;
                    break;
                case 1:
                    aes = AesType.AES_256;
                    break;
                default:
                    throw new Exception("AES mode not recognized");
            }
            switch (ESBytes[1])
            {
                case 0:
                    curve = CurveType.BrainpoolP256;
                    break;
                case 1:
                    curve = CurveType.BrainpoolP384;
                    break;
                case 2:
                    curve = CurveType.BrainpoolP512;
                    break;
                case 3:
                    curve = CurveType.Nist256;
                    break;
                case 4:
                    curve = CurveType.Nist384;
                    break;
                case 5:
                    curve = CurveType.Nist521;
                    break;
                default:
                    throw new Exception("Curve mode not recognized");
            }
            return new EncryptionSettings(aes, curve);
        }
    }
}