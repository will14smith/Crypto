using System;
using System.IO;
using System.Linq;
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
            var certificates = Certificates.Select(GetBytes).ToArray();
            var totalLength = certificates.Sum(x => x.Length + 2);

            writer.Write((ushort)totalLength);
            foreach (var cert in certificates)
            {
                writer.WriteVariable(2, cert);
            }
        }

        private byte[] GetBytes(X509Certificate certificate)
        {
            using (var ms = new MemoryStream())
            {
                new X509Writer(ms).WriteCertificate(certificate);
                return ms.ToArray();
            }
        }
    }
}
