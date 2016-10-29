using System;
using Crypto.Certificates.Keys;
using Crypto.EllipticCurve.Maths;

namespace Crypto.EllipticCurve.Algorithms
{
    public class ECPublicKey : PublicKey
    {
        public Point<PrimeFieldValue> Point { get; }

        public ECPublicKey(Point<PrimeFieldValue> point)
        {
            Point = point;
        }

        protected override int HashCode => Point.GetHashCode();
        protected override bool Equal(PublicKey key)
        {
            var other = key as ECPublicKey;
            return !ReferenceEquals(other, null) && other.Point == Point;
        }

        public override byte[] GetBytes()
        {
            throw new NotImplementedException();
        }
    }
}