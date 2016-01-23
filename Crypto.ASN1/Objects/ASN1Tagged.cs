using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1Tagged : ASN1Object
    {
        public ASN1Tagged(uint tag, IEnumerable<ASN1Object> elements)
            : base(elements)
        {
            Tag = tag;
        }

        public uint Tag { get; }

        public override BigInteger ByteLength => Elements.Aggregate(BigInteger.Zero, (a, x) => a + 1 + x.LengthSize + x.ByteLength);
        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
