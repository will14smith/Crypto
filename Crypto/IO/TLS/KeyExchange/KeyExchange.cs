using System.Collections.Generic;
using Crypto.IO.TLS.Messages;

namespace Crypto.IO.TLS
{
    /*
    Null = 0,
        RSA,
        DH_DSS,
        DH_RSA,
        DHE_DSS,
        DHE_RSA,
        DH_anon
        */

    public abstract class KeyExchange
    {
        public abstract bool RequiresCertificate { get; }
        public abstract bool RequiresKeyExchange { get; }

        internal abstract void InitialiseState(TlsState state);
        internal abstract IEnumerable<HandshakeMessage> GenerateHandshakeMessages(TlsState state);
    }
}
