using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class ClientHelloMessage : HelloMessage
    {
        public ClientHelloMessage(TlsVersion version, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions, CipherSuite[] cipherSuites, CompressionMethod[] compressionMethods)
            : base(HandshakeType.ClientHello, version, randomBytes, sessionId, extensions)
        {
            SecurityAssert.NotNull(cipherSuites);
            SecurityAssert.SAssert(cipherSuites.Length >= 2 && cipherSuites.Length <= 0xFFFE);
            CipherSuites = cipherSuites;

            SecurityAssert.NotNull(compressionMethods);
            SecurityAssert.SAssert(compressionMethods.Length >= 1 && cipherSuites.Length <= 0xFF);
            CompressionMethods = compressionMethods;
        }

        public CipherSuite[] CipherSuites { get; }
        public CompressionMethod[] CompressionMethods { get; }

        protected override void WriteHello(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }

        internal static HandshakeMessage Read(TlsState state, byte[] body)
        {
            using (var stream = new MemoryStream(body))
            {
                var reader = new EndianBinaryReader(EndianBitConverter.Big, stream);

                var version = reader.ReadVersion();
                var randomBytes = reader.ReadBytes(32);
                var sessionId = reader.ReadBytesVariable(1, 0, 32);

                var cipherSuites = reader.ReadUInt16Variable<CipherSuite>(2, 2, 0xFFFE);
                var compressionMethods = reader.ReadBytesVariable<CompressionMethod>(1, 1, 0xFF).ToArray();

                var extensions = new List<HelloExtension>();

                // extensions don't have to be included
                if (stream.Length != stream.Position)
                {
                    var extsLength = reader.ReadUInt16();

                    while (extsLength > 0)
                    {
                        extsLength -= 4;

                        var extType = reader.ReadUInt16();
                        var extLength = reader.ReadUInt16();
                        extsLength -= extLength;

                        var extBuffer = reader.ReadBytes(extLength);

                        extensions.Add(new HelloExtension(extType, extBuffer));
                    }
                }

                return new ClientHelloMessage(version, randomBytes, sessionId, extensions.ToArray(), cipherSuites, compressionMethods);
            }
        }
    }
}
