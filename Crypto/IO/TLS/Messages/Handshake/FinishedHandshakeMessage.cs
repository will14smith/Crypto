using System;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    class FinishedHandshakeMessage : HandshakeMessage
    {
        public FinishedHandshakeMessage() : base(HandshakeType.Finished)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
