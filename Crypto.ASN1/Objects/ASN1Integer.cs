using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1Integer : ASN1Object
    {
        public BigInteger Value { get; }

        public bool IsUInt8 => Value >= byte.MinValue && Value <= byte.MaxValue;
        public bool IsUInt16 => Value >= ushort.MinValue && Value <= ushort.MaxValue;
        public bool IsUInt32 => Value >= uint.MinValue && Value <= uint.MaxValue;

        public ASN1Integer(BigInteger value)
        {
            Value = value;
        }
    }
}
