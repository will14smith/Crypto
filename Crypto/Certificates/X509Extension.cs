using Crypto.ASN1;

namespace Crypto.Certificates
{
    public class X509Extension
    {
        private readonly string id;
        private readonly bool critical;
        private readonly ASN1Object value;

        public X509Extension(string id, bool critical, ASN1Object value)
        {
            this.id = id;
            this.critical = critical;
            this.value = value;
        }
    }
}