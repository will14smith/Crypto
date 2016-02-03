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
            var innerStream = new SignedStream(writer.BaseStream, state.CipherAlgorithm);
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

            // TODO write sig

            // enum{ none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255) } HashAlgorithm;
            // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;

            // struct { HashAlgorithm hash; SignatureAlgorithm signature; } SignatureAndHashAlgorithm;

            // struct {
            //   SignatureAndHashAlgorithm algorithm;
            //   int16 signature.length
            //   byte[] signature<0..2^16-1>;
            // } DigitallySigned;
            
            throw new System.NotImplementedException();
        }
    }
}
