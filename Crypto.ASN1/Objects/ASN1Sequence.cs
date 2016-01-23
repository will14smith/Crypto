using System.Collections.Generic;

namespace Crypto.ASN1
{
    public class ASN1Sequence : ASN1Object
    {
        public ASN1Sequence(IEnumerable<ASN1Object> elems)
            : base(elems)
        {
        }
    }
}
