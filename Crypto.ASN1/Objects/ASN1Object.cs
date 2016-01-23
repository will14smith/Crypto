using System.Collections.Generic;
using System.Linq;

namespace Crypto.ASN1
{
    public abstract class ASN1Object
    {
        protected ASN1Object()
        {
            Elements = new List<ASN1Object>();
        }
        protected ASN1Object(IEnumerable<ASN1Object> elements)
        {
            Elements = elements.ToList();
        }

        public IReadOnlyList<ASN1Object> Elements { get; }
        public int Length => Elements.Count;
    }
}