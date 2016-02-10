using System;
using System.IO;
using System.Numerics;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public abstract class ClientKeyExchangeMessage : HandshakeMessage
    {
        protected ClientKeyExchangeMessage() : base(HandshakeType.ClientKeyExchange)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new System.NotImplementedException();
        }

        public class DH : ClientKeyExchangeMessage
        {
            public DH(byte[] yc)
            {
                SecurityAssert.NotNull(yc);

                Yc = BigIntegerExtensions.FromTlsBytes(yc);
            }

            public BigInteger Yc { get; }
        }
    }
}
