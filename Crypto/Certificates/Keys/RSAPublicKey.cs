using System;
using System.Collections;
using System.Numerics;
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
            throw new NotImplementedException();
        }

        protected override int HashCode => HashCodeHelper.ToInt(Modulus ^ Exponent);
    }
}
