using System.Collections.Generic;

namespace Crypto.ASN1
{
    public class ASN1Set : ASN1Object
    {
        public ASN1Set(IEnumerable<ASN1Object> elems)
            : base(elems)
        {
        }
    }
}