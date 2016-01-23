using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1OctetString : ASN1Object
    {
        public byte[] Value { get; }

        public ASN1OctetString(byte[] value)
        {
            Value = value;
        }

        public override BigInteger ByteLength => Value.Length;
        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
