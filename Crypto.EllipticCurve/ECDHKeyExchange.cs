﻿using System;
using System.Collections.Generic;
using Crypto.Encryption;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Messages;

namespace Crypto.EllipticCurve
{
    public class ECDHKeyExchange : ITlsKeyExchange
    {
        public ECDHKeyExchange()
        {
        }

        public void Init(TlsState state)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            throw new NotImplementedException();
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
