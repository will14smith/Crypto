using System.Collections.Generic;
using System.Linq;

namespace Crypto.ASN1
{
    public class ASN1Sequence : ASN1Object
    {
        public IReadOnlyList<ASN1Object> Elements { get; }

        public ASN1Sequence(IEnumerable<ASN1Object> elems)
        {
            Elements = elems.ToList();
        }
    }
}
