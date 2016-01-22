using System;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public abstract class HandshakeMessage : Message
    {
        protected HandshakeMessage(HandshakeType type, uint length)
        {
            // length is actually a uint24 but .NET doesn't support them
            SecurityAssert.SAssert(length < 0x1000000);

            Type = type;
            Length = length;
        }

        public HandshakeType Type { get; }
        public uint Length { get; }
    }
}
