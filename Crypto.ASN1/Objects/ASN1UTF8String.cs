using System.Numerics;
using System.Text;

namespace Crypto.ASN1
{
    public class ASN1UTF8String : ASN1Object
    {
        public ASN1UTF8String(string value)
        {
            Value = value;
        }

        public string Value { get; }

        public override BigInteger ByteLength => Encoding.UTF8.GetByteCount(Value);
        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
