using Crypto.Certificates;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public class CertificateMessage : HandshakeMessage
    {
        public CertificateMessage(uint length, ASN1Certificate[] certificates) : base(HandshakeType.Certificate, length)
        {
            SecurityAssert.NotNull(certificates);
            SecurityAssert.SAssert(certificates.Length <= 0xFFFFFF);
            Certificates = certificates;
        }

        public ASN1Certificate[] Certificates { get; }
    }
}
