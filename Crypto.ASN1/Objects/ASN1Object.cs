using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

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
        public int Count => Elements.Count;

        public int LengthSize
        {
            get
            {
                var bl = ByteLength;
                if (ByteLength > 0x7f)
                {
                    return (int)(1 + (Math.Ceiling(BigInteger.Log(bl, 2) / 8d)));
                }

                return 1;
            }
        }

        public abstract BigInteger ByteLength { get; }

        internal abstract void Accept(IASN1ObjectWriter writer);
    }
}