using System.Collections.Generic;
using System.Linq;

namespace Crypto.ASN1
{
    public class ASN1Set : ASN1Object
    {
        public IReadOnlyList<ASN1Object> Elements { get; }

        public ASN1Set(IEnumerable<ASN1Object> elems)
        {
            Elements = elems.ToList();
        }
    }
}