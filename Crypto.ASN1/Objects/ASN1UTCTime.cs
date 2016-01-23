using System;

namespace Crypto.ASN1
{
    public class ASN1UTCTime : ASN1Object
    {
        public ASN1UTCTime(DateTimeOffset value)
        {
            Value = value;
        }

        public DateTimeOffset Value { get; }
    }
}
