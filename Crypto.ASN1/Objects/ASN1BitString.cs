using System.Collections;

namespace Crypto.ASN1
{
    public class ASN1BitString : ASN1Object
    {
        public BitArray Value { get; }

        public ASN1BitString(BitArray value)
        {
            Value = value;
        }
    }
}
