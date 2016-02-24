using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class DHKeyExchange : ITlsKeyExchange
    {
        private readonly ITlsKeyExchange innerKeyExchange;
        private TlsState state;

        public DHKeyExchange(ITlsKeyExchange innerKeyExchange)
        {
            SecurityAssert.NotNull(innerKeyExchange);

            this.innerKeyExchange = innerKeyExchange;
        }

        public void Init(TlsState state)
        {
            this.state = state;
            innerKeyExchange.Init(state);
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            return innerKeyExchange.GenerateHandshakeMessages();
        }

        public HandshakeMessage ReadClientKeyExchange(byte[] body)
        {
            throw new NotImplementedException();
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }
    }
}
