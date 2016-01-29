using System;
using System.Numerics;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    internal class RSAPrivateKey : PrivateKey
    {
        public RSAPrivateKey(ASN1Object asn1Key)
        {
            // NOTE: currently only supporting PKCS#1 without optional OtherPrimeInfos

            var keySeq = asn1Key as ASN1Sequence;
            SecurityAssert.NotNull(keySeq);
            SecurityAssert.SAssert(keySeq.Count == 9);

            Modulus = GetInteger(keySeq, 1);
            PublicExponent = GetInteger(keySeq, 2);
            PrivateExponent = GetInteger(keySeq, 3);
            Prime1 = GetInteger(keySeq, 4);
            Prime2 = GetInteger(keySeq, 5);
            Exponent1 = GetInteger(keySeq, 6);
            Exponent2 = GetInteger(keySeq, 7);
            Coefficent = GetInteger(keySeq, 8);

            SecurityAssert.SAssert(Modulus == Prime1 * Prime2);
            SecurityAssert.SAssert(Exponent1 == (PrivateExponent % (Prime1 - 1)));
            SecurityAssert.SAssert(Exponent2 == (PrivateExponent % (Prime2 - 1)));
            // TODO assert Coefficent == ((inverse of q) mod p)
        }

        public override PublicKey PublicKey => new RSAPublicKey(Modulus, PublicExponent);

        public BigInteger Modulus { get; }
        public BigInteger PublicExponent { get; }
        public BigInteger PrivateExponent { get; }
        public BigInteger Prime1 { get; }
        public BigInteger Prime2 { get; }
        public BigInteger Exponent1 { get; }
        public BigInteger Exponent2 { get; }
        public BigInteger Coefficent { get; }

        protected override int HashCode => HashCodeHelper.ToInt(Modulus ^ PublicExponent ^ PrivateExponent ^ Prime1 ^ Prime2 ^ Exponent1 ^ Exponent2 ^ Coefficent);

        private BigInteger GetInteger(ASN1Sequence obj, int index)
        {
            SecurityAssert.SAssert(index >= 0 && index < obj.Elements.Count);

            var elem = obj.Elements[index];
            var intElem = elem as ASN1Integer;
            SecurityAssert.NotNull(intElem);

            return intElem.Value;
        }

        protected override bool Equal(PrivateKey key)
        {
            var other = key as RSAPrivateKey;
            if (other == null) return false;

            return Modulus == other.Modulus
                   && PublicExponent == other.PublicExponent
                   && PrivateExponent == other.PrivateExponent
                   && Prime1 == other.Prime1
                   && Prime2 == other.Prime2
                   && Exponent1 == other.Exponent1
                   && Exponent2 == other.Exponent2
                   && Coefficent == other.Coefficent;
        }
    }
}