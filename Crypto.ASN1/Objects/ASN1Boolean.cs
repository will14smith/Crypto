namespace Crypto.ASN1
{
    public class ASN1Boolean : ASN1Object
    {
        public bool Value { get; }

        public ASN1Boolean(bool value)
        {
            Value = value;
        }
    }
}
