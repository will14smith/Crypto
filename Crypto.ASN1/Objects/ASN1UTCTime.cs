using System;
using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1UTCTime : ASN1Object
    {
        public ASN1UTCTime(DateTimeOffset value)
        {
            Value = value;
        }

        public DateTimeOffset Value { get; }

        public override BigInteger ByteLength => 13;

        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
