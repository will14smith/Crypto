using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Crypto.ASN1
{
    public class ASN1Sequence : ASN1Object
    {
        public ASN1Sequence(IEnumerable<ASN1Object> elems)
            : base(elems)
        {
        }

        public override BigInteger ByteLength => Elements.Aggregate(BigInteger.Zero, (a, x) => a + 1 + x.LengthSize + x.ByteLength);
        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
