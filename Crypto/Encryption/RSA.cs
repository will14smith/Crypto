using System;
using System.Linq;
using System.Numerics;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.Encryption
{
    // Currently only supports PKCS1-v1_5 scheme, OAEP & PSS are unsupported
    public class RSA : ICipher, ISignatureCipher
    {
        private readonly RSAPublicKey pub;
        private readonly RSAPrivateKey priv;

        public RSA(PrivateKey key)
        {
            SecurityAssert.SAssert(key is RSAPrivateKey);

            priv = (RSAPrivateKey)key;
            pub = (RSAPublicKey)priv.PublicKey;
        }
        public RSA(PublicKey key)
        {
            SecurityAssert.SAssert(key is RSAPublicKey);

            pub = (RSAPublicKey)key;
        }

        public byte[] Encrypt(byte[] input)
        {
            var k = pub.Modulus.GetByteLength();
            SecurityAssert.SAssert(input.Length <= k - 11);

            var ps = RandomGenerator.RandomNonZeroBytes(k - input.Length - 3);
            SecurityAssert.SAssert(ps.Length >= 8);

            var em = new byte[k];
            em[0] = 0;
            em[1] = 2;
            Array.Copy(ps, 0, em, 2, ps.Length);
            em[ps.Length + 2] = 0;
            Array.Copy(input, 0, em, ps.Length + 3, input.Length);

            var m = OS2IP(em);
            var c = EncryptPrimative(m, pub);

            return I2OSP(c, k);
        }

        public byte[] Decrypt(byte[] input)
        {
            SecurityAssert.NotNull(priv);

            var k = priv.Modulus.GetByteLength();
            SecurityAssert.SAssert(k >= 11);
            SecurityAssert.SAssert(input.Length == k);

            var c = OS2IP(input);
            var m = DecryptPrimative(c, priv);

            var em = I2OSP(m, k);

            SecurityAssert.SAssert(em[0] == 0 && em[1] == 2);

            var mIdx = 2;
            while (mIdx < k && em[mIdx] != 0) { mIdx++; }

            SecurityAssert.SAssert(mIdx - 2 > 8);
            // advance past zero
            mIdx++;

            var result = new byte[k - mIdx];
            Array.Copy(em, mIdx, result, 0, result.Length);

            return result;
        }

        public byte[] Sign(byte[] input)
        {
            throw new NotImplementedException();
        }
        public bool Verify(byte[] input)
        {
            throw new NotImplementedException();
        }

        private BigInteger EncryptPrimative(BigInteger m, RSAPublicKey key)
        {
            SecurityAssert.SAssert(m >= 0 && m < key.Modulus);

            return BigInteger.ModPow(m, key.Exponent, key.Modulus);
        }
        private BigInteger DecryptPrimative(BigInteger c, RSAPrivateKey key)
        {
            SecurityAssert.SAssert(c >= 0 && c < key.Modulus);

            return BigInteger.ModPow(c, key.PrivateExponent, key.Modulus);
        }

        private byte[] I2OSP(BigInteger x, int length)
        {
            SecurityAssert.SAssert(x.Sign >= 0);
            SecurityAssert.SAssert(x < BigInteger.Pow(256, length));

            var os = new byte[length];

            var i = 1;
            while (x > 0)
            {
                os[length - i] = (byte)(x % 256);

                x = x / 256;

                i++;
            }

            return os;
        }
        private BigInteger OS2IP(byte[] x)
        {
            return x.Aggregate(BigInteger.Zero, (current, t) => current * 256 + t);
        }
    }
}
