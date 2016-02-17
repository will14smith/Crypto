using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.Encryption
{
    // Currently only supports PKCS1-v1_5 scheme, OAEP & PSS are unsupported
    public class RSA : ISignatureCipher
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
            SecurityAssert.NotNull(input);

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
            SecurityAssert.NotNull(input);
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

        public byte[] Sign(byte[] input, IDigest hash)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.NotNull(hash);

            var k = priv.Modulus.GetByteLength();

            var em = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            var m = OS2IP(em);
            var s = SignPrimative(m, priv);

            return I2OSP(s, k);
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.NotNull(signature);
            SecurityAssert.NotNull(hash);

            var k = pub.Modulus.GetByteLength();
            SecurityAssert.SAssert(signature.Length == k);

            var s = OS2IP(signature);
            var m = VerifyPrimative(s, pub);
            var em = I2OSP(m, k);

            var em2 = EMSA_PKCS1_v1_5_Encode(input, k, hash);

            return em.Length == em2.Length && em.SequenceEqual(em2);
        }

        private static BigInteger EncryptPrimative(BigInteger m, RSAPublicKey key)
        {
            SecurityAssert.SAssert(m >= 0 && m < key.Modulus);

            return BigInteger.ModPow(m, key.Exponent, key.Modulus);
        }
        private static BigInteger DecryptPrimative(BigInteger c, RSAPrivateKey key)
        {
            SecurityAssert.SAssert(c >= 0 && c < key.Modulus);

            return BigInteger.ModPow(c, key.PrivateExponent, key.Modulus);
        }
        private static BigInteger SignPrimative(BigInteger m, RSAPrivateKey key)
        {
            return DecryptPrimative(m, key);
        }
        private static BigInteger VerifyPrimative(BigInteger m, RSAPublicKey key)
        {
            return EncryptPrimative(m, key);
        }

        private static byte[] I2OSP(BigInteger x, int length)
        {
            SecurityAssert.SAssert(x.Sign >= 0);
            SecurityAssert.SAssert(x < BigInteger.Pow(256, length));

            var bytes = new List<byte>();

            while (x != 0)
            {
                bytes.Add((byte)(x % 256));

                x /= 256;
            }

            return bytes.AsEnumerable().Reverse().ToArray();
        }
        private static BigInteger OS2IP(IEnumerable<byte> x)
        {
            return x.Aggregate(BigInteger.Zero, (current, b) => current*256 + b);
        }

        private static byte[] EMSA_PKCS1_v1_5_Encode(byte[] input, int emLen, IDigest hash)
        {
            hash.Update(input, 0, input.Length);
            var h = hash.Digest();

            byte[] t;
            using (var mem = new MemoryStream())
            {
                var derWriter = new DERWriter(mem);

                derWriter.Write(new ASN1Sequence(new ASN1Object[]
                {
                    new ASN1Sequence(new ASN1Object[] {
                        hash.Id,
                        new ASN1Null()
                    }),
                    new ASN1OctetString(h)
                }));

                t = mem.ToArray();
            }

            SecurityAssert.SAssert(emLen >= t.Length + 11);

            var ps = new byte[emLen - t.Length - 3];
            SecurityAssert.SAssert(ps.Length >= 8);
            for (var i = 0; i < ps.Length; i++) { ps[i] = 0xff; }

            var em = new byte[emLen];
            em[0] = 0;
            em[1] = 1;
            Array.Copy(ps, 0, em, 2, ps.Length);
            em[ps.Length + 2] = 0;
            Array.Copy(t, 0, em, ps.Length + 3, t.Length);

            return em;
        }

    }
}
