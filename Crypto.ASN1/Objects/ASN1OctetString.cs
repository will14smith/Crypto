namespace Crypto.ASN1
{
    public class ASN1OctetString : ASN1Object
    {
        public byte[] Value { get; }

        public ASN1OctetString(byte[] value)
        {
            Value = value;
        }
    }
}
