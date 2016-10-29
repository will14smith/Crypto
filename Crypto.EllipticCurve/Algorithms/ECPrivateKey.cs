using System.Numerics;
using Crypto.Certificates.Keys;

namespace Crypto.EllipticCurve.Algorithms
{
    public class ECPrivateKey : PrivateKey
    {
        public ECPrivateKey(BigInteger key, ECPublicKey pKey)
        {
            Key = key;
            PublicKey = pKey;
        }

        public BigInteger Key { get; }
        public override PublicKey PublicKey { get; }

        protected override bool Equal(PrivateKey key)
        {
            var other = key as ECPrivateKey;
            return !ReferenceEquals(other, null) && other.Key == Key;
        }

        protected override int HashCode => Key.GetHashCode();
    }
}
