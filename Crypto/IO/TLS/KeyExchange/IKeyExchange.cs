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

    public interface IKeyExchange
    {
        void Init(TlsState state);
        IEnumerable<HandshakeMessage> GenerateHandshakeMessages();

        HandshakeMessage ReadClientKeyExchange(byte[] body);
        void HandleClientKeyExchange(ClientKeyExchangeMessage message);
    }
}
