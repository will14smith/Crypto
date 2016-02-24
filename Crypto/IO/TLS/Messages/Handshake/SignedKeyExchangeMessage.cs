using System.Numerics;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class SignedKeyExchangeMessage : HandshakeMessage
    {
        private readonly TlsState state;
        public BigInteger P { get; }
        public BigInteger G { get; }
        public BigInteger Y { get; }

        public SignedKeyExchangeMessage(TlsState state, BigInteger p, BigInteger g, BigInteger pub) : base(HandshakeType.ServerKeyExchange)
        {
            this.state = state;

            P = p;
            G = g;
            Y = pub;
        }

        protected override void Write(EndianBinaryWriter baseWriter)
        {
            var stream = state.GetSignatureStream(baseWriter.BaseStream);
            var writer = new EndianBinaryWriter(baseWriter.BitConverter, stream);

            // signature needs these but the output doesn't
            stream.HashAlgorithm.Update(state.ClientRandom, 0, 32);
            stream.HashAlgorithm.Update(state.ServerRandom, 0, 32);

            var pBuffer = P.ToTlsBytes();
            var gBuffer = G.ToTlsBytes();
            var pubBuffer = Y.ToTlsBytes();

            writer.Write((short)pBuffer.Length);
            writer.Write(pBuffer);
            writer.Write((short)gBuffer.Length);
            writer.Write(gBuffer);
            writer.Write((short)pubBuffer.Length);
            writer.Write(pubBuffer);

            stream.Flush();
            stream.WriteTlsSignature(state);
        }
    }
}
