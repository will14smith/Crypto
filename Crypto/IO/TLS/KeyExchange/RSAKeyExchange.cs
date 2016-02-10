using System.Collections.Generic;
using Crypto.IO.TLS.Messages;

namespace Crypto.IO.TLS
{
    class RSAKeyExchange : KeyExchange
    {
        private TlsState state;

        public bool RequiresCertificate => true;
        public bool RequiresKeyExchange => false;

        public void Init(TlsState state)
        {
            this.state = state;

            var certificate = state.Certificates.GetDefaultCertificate();
            var chain = new[] { certificate };

            state.SetCertificates(certificate, chain);
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield return new CertificateMessage(state.CertificateChain);
        }

        public HandshakeMessage ReadClientKeyExchange(byte[] body)
        {
            throw new System.NotImplementedException();
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            throw new System.NotImplementedException();
        }
    }
}