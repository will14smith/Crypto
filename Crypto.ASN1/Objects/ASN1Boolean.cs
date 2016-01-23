using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1Boolean : ASN1Object
    {
        public bool Value { get; }

        public ASN1Boolean(bool value)
        {
            Value = value;
        }

        public override BigInteger ByteLength => 1;

        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
