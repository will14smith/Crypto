using System;
using Crypto.Certificates;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class CertificateMessage : HandshakeMessage
    {
        public CertificateMessage(X509Certificate[] certificates) : base(HandshakeType.Certificate)
        {
            SecurityAssert.NotNull(certificates);
            SecurityAssert.SAssert(certificates.Length <= 0xFFFFFF);
            Certificates = certificates;
        }

        public X509Certificate[] Certificates { get; }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
