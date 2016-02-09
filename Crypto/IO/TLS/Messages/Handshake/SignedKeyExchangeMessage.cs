using System.Numerics;
using Crypto.IO.Signing;
using Crypto.Utils;
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

        protected override void Write(EndianBinaryWriter baseWriter)
        {
            var stream = state.GetSignatureStream(baseWriter.BaseStream);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(state.ClientRandom, 0, 32);
            stream.HashAlgorithm.Update(state.ServerRandom, 0, 32);

            var pBuffer = p.ToTlsBytes();
            var gBuffer = g.ToTlsBytes();
            var pubBuffer = pub.ToTlsBytes();

            writer.Write((short)pBuffer.Length);
            writer.Write(pBuffer);
            writer.Write((short)gBuffer.Length);
            writer.Write(gBuffer);
            writer.Write((short)pubBuffer.Length);
            writer.Write(pubBuffer);

            stream.Flush();
            stream.WriteTlsSignature();
        }
    }
}
