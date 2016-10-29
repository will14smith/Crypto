using System;
using System.Numerics;
using Crypto.Utils;

namespace Crypto.EllipticCurve.Maths
{
    public class PrimeField : IField<PrimeFieldValue>
    {
        public BigInteger Prime { get; }

        public PrimeField(BigInteger prime)
        {
            Prime = prime;
        }

        public PrimeFieldValue Int(BigInteger i)
        {
            i = i % Prime;
            if (i < 0)
            {
                i += Prime;
            }

            return new PrimeFieldValue(i);
        }

        public PrimeFieldValue Negate(PrimeFieldValue a)
        {
            return Int(-a.Value);
        }

        public PrimeFieldValue Add(PrimeFieldValue a, PrimeFieldValue b)
        {
            return Int(a.Value + b.Value);
        }

        public PrimeFieldValue Sub(PrimeFieldValue a, PrimeFieldValue b)
        {
            return Int(a.Value - b.Value);
        }

        public PrimeFieldValue Multiply(PrimeFieldValue a, PrimeFieldValue b)
        {
            return Int(a.Value * b.Value);
        }

        public PrimeFieldValue Divide(PrimeFieldValue a, PrimeFieldValue b)
        {
            return Multiply(a, Invert(b));
        }

        private PrimeFieldValue Invert(PrimeFieldValue a)
        {
            var result = ExtendedEuclidean(a.Value, Prime);
            var gcd = result.Item1;
            var x = result.Item2;
            var y = result.Item3;

            SecurityAssert.SAssert((a.Value * x + Prime * y) % Prime == gcd);

            if (gcd != 1)
            {
                // Either n is 0, or p is not a prime number.
                throw new Exception($"{a.Value} has no multiplicative inverse modulo {Prime}");
            }

            return Int(x);
        }

        private void DualAssign<T>(out T a, out T b, T aValue, T bValue)
        {
            a = aValue;
            b = bValue;
        }

        private Tuple<BigInteger, BigInteger, BigInteger> ExtendedEuclidean(BigInteger a, BigInteger b)
        {
            BigInteger s, oldS, t, oldT, r, oldR;

            DualAssign(out s, out oldS, 0, 1);
            DualAssign(out t, out oldT, 1, 0);
            DualAssign(out r, out oldR, b, a);

            while (r != 0)
            {
                var quotient = oldR / r;
                DualAssign(out oldR, out r, r, oldR - quotient * r);
                DualAssign(out oldS, out s, s, oldS - quotient * s);
                DualAssign(out oldT, out t, t, oldT - quotient * t);
            }

            return Tuple.Create(oldR, oldS, oldT);
        }
    }

    public class PrimeFieldValue : IFieldValue, IEquatable<PrimeFieldValue>
    {
        public PrimeFieldValue(BigInteger value)
        {
            Value = value;
        }

        public BigInteger Value { get; }

        public BigInteger ToInt()
        {
            return Value;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as PrimeFieldValue;
            return other != null && Equals(other);
        }

        public bool Equals(PrimeFieldValue other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(PrimeFieldValue left, PrimeFieldValue right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(PrimeFieldValue left, PrimeFieldValue right)
        {
            return !Equals(left, right);
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}