using System;
using System.Collections;
using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1BitString : ASN1Object
    {
        public BitArray Value { get; }

        public ASN1BitString(BitArray value)
        {
            Value = value;
        }

        public ASN1BitString(byte[] value)
        {
            Value = new BitArray(value);
        }

        public override BigInteger ByteLength => (int)Math.Ceiling(Value.Count / 8m) + 1;

        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
