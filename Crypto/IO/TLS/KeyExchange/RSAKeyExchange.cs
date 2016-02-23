using System.Collections.Generic;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class RSAKeyExchange : IKeyExchange
    {
        private TlsState state;

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
            var length = EndianBitConverter.Big.ToUInt16(body, 0);
            SecurityAssert.SAssert(body.Length == length + 2);

            var key = state.Certificates.GetPrivateKey(state.Certificate.SubjectPublicKey);
            var rsa = new RSA();
            rsa.Init(new PrivateKeyParameter(key));

            var preMasterSecret = rsa.Decrypt(body, 2, length);
            SecurityAssert.SAssert(preMasterSecret.Length == 48);
            SecurityAssert.SAssert(preMasterSecret[0] == state.Version.Major && preMasterSecret[1] == state.Version.Minor);

            return new ClientKeyExchangeMessage.RSA(preMasterSecret);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var rsaMessage = message as ClientKeyExchangeMessage.RSA;
            SecurityAssert.NotNull(rsaMessage);

            state.ComputeMasterSecret(rsaMessage.PreMasterSecret);
        }
    }
}