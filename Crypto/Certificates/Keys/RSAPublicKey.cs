using System;
using System.Collections;
using System.IO;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    class RSAPublicKey : PublicKey
    {
        public RSAPublicKey(BigInteger modulus, BigInteger exponent)
        {
            Modulus = modulus;
            Exponent = exponent;
        }

        public BigInteger Modulus { get; }
        public BigInteger Exponent { get; }

        protected override bool Equal(PublicKey key)
        {
            var other = key as RSAPublicKey;
            if (other == null) return false;

            return Modulus == other.Modulus && Exponent == other.Exponent;
        }

        public override byte[] GetBytes()
        {
            var asn1 = new ASN1Sequence(new[]
            {
                new ASN1Integer(Modulus),
                new ASN1Integer(Exponent),
            });

            using (var ms = new MemoryStream())
            {
                new DERWriter(ms).Write(asn1);

                return ms.ToArray();
            }
        }

        protected override int HashCode => HashCodeHelper.ToInt(Modulus ^ Exponent);
    }
}
