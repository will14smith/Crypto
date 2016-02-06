using System.Numerics;
using Crypto.IO.Signing;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    class SignedKeyExchangeMessage : HandshakeMessage
    {
        private readonly TlsState state;
        private readonly BigInteger p;
        private readonly BigInteger g;
        private readonly BigInteger pub;

        public SignedKeyExchangeMessage(TlsState state, BigInteger p, BigInteger g, BigInteger pub) : base(HandshakeType.ServerKeyExchange)
        {
            this.state = state;
            this.p = p;
            this.g = g;
            this.pub = pub;
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            var innerStream = state.GetSigningStream(writer.BaseStream);
            var innerWriter = new EndianBinaryWriter(writer.BitConverter, innerStream);

            var pBuffer = p.ToByteArray();
            innerWriter.Write((short)pBuffer.Length);
            innerWriter.Write(pBuffer);

            var gBuffer = g.ToByteArray();
            innerWriter.Write((short)gBuffer.Length);
            innerWriter.Write(gBuffer);

            var pubBuffer = pub.ToByteArray();
            innerWriter.Write((short)pubBuffer.Length);
            innerWriter.Write(pubBuffer);

            innerStream.Flush();
            innerStream.WriteTlsSignature();
        }
    }
}
