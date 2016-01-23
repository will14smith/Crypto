using System;

namespace Crypto.Certificates
{
    public class X509Validity
    {
        public DateTimeOffset NotBefore { get; }
        public DateTimeOffset NotAfter { get; }

        public X509Validity(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            NotBefore = notBefore;
            NotAfter = notAfter;
        }
    }
}