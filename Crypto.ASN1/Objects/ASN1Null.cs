using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.ASN1
{
    public class ASN1Null : ASN1Object
    {
        public override BigInteger ByteLength => 0;
        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }
    }
}
