using System;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    class CertificateVerifyMessage : HandshakeMessage
    {
        public CertificateVerifyMessage() : base(HandshakeType.CertificateVerify)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
