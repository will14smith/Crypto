namespace Crypto.ASN1
{
    public class ASN1ObjectIdentifier : ASN1Object
    {
        public ASN1ObjectIdentifier(string identifier)
        {
            Identifier = identifier;
        }

        public string Identifier { get; }
    }
}
