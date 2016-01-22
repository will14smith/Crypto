using System;

namespace Crypto.IO.TLS.Messages
{
    public class HelloRequestMessage : HandshakeMessage
    {
        public HelloRequestMessage() : base(HandshakeType.HelloRequest)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
        }
    }
}
