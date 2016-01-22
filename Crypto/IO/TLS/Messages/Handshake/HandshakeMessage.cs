using System;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public abstract class HandshakeMessage : Message
    {
        protected HandshakeMessage(HandshakeType type)
        {
            Type = type;
        }

        public HandshakeType Type { get; }
    }
}
