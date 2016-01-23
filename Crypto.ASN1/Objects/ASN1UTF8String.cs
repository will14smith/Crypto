namespace Crypto.ASN1
{
    public class ASN1UTF8String : ASN1Object
    {
        public ASN1UTF8String(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }
}
