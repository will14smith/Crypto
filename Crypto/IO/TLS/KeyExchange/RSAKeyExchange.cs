using System.Collections.Generic;
using Crypto.IO.TLS.Messages;

namespace Crypto.IO.TLS
{
    class RSAKeyExchange : KeyExchange
    {
        public override bool RequiresCertificate => true;
        public override bool RequiresKeyExchange => false;

        internal override void InitialiseState(TlsState state)
        {
            var certificate = state.Certificates.GetDefaultCertificate();
            var chain = new[] { certificate };

            state.SetCertificates(certificate, chain);
        }

        internal override IEnumerable<HandshakeMessage> GenerateHandshakeMessages(TlsState state)
        {
            yield return new CertificateMessage(state.CertificateChain);
        }
    }
}