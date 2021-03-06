﻿using System.Collections.Generic;
using Crypto.IO.TLS.Messages;

namespace Crypto.IO.TLS
{
    public class NullKeyExchange : ITlsKeyExchange
    {
        public void Init(TlsState state)
        {
            // nop
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            yield break;
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