using Crypto.ASN1;

namespace Crypto.Certificates
{
    public static class WellKnownObjectIdentifiers
    {
        public static readonly ASN1ObjectIdentifier RSAEncryption = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"); // PKCS#1
    }
}
