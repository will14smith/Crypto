using System;
using System.Numerics;

namespace Crypto.EllipticCurve.Maths
{
    public class RealField : IField<RealValue>
    {
        public RealValue Int(BigInteger i)
        {
            return new RealValue((decimal)i);
        }

        public RealValue Negate(RealValue a)
        {
            return new RealValue(-a.Value);
        }

        public RealValue Add(RealValue a, RealValue b)
        {
            return new RealValue(a.Value + b.Value);
        }

        public RealValue Sub(RealValue a, RealValue b)
        {
            return new RealValue(a.Value - b.Value);
        }

        public RealValue Multiply(RealValue a, RealValue b)
        {
            return new RealValue(a.Value * b.Value);
        }

        public RealValue Divide(RealValue a, RealValue b)
        {
            return new RealValue(a.Value / b.Value);
        }

        public RealValue Sqrt(RealValue a)
        {
            return new RealValue((decimal)Math.Sqrt((double)a.Value));
        }
    }

    public class RealValue : IFieldValue, IEquatable<RealValue>
    {
        public RealValue(decimal value)
        {
            Value = value;
        }

        public decimal Value { get; }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            var other = obj as RealValue;
            return other != null && Equals(other);
        }

        public bool Equals(RealValue other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Value.Equals(other.Value);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(RealValue left, RealValue right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(RealValue left, RealValue right)
        {
            return !Equals(left, right);
        }

        public BigInteger ToInt()
        {
            return new BigInteger(Value);
        }

        public override string ToString()
        {
            return Value.ToString();
        }
    }
}