using System.Collections.Generic;
using Crypto.IO.TLS.Messages;

namespace Crypto.IO.TLS
{
    class NullKeyExchange : KeyExchange
    {
        public override bool RequiresCertificate => false;
        public override bool RequiresKeyExchange => false;
        internal override void InitialiseState(TlsState state)
        {
            // nop
        }

        internal override IEnumerable<HandshakeMessage> GenerateHandshakeMessages(TlsState state)
        {
            yield break;
        }
    }
}