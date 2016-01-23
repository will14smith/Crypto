﻿using System.Collections.Generic;
using System.Linq;

namespace Crypto.ASN1
{
    public class ASN1Tagged : ASN1Object
    {
        public ASN1Tagged(uint tag, IEnumerable<ASN1Object> elements)
        {
            Tag = tag;
            Elements = elements.ToList();
        }

        public uint Tag { get; }
        public IReadOnlyList<ASN1Object> Elements { get; }

    }
}
