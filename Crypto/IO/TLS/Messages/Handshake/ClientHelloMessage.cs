using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public class ClientHelloMessage : HelloMessage
    {
        public ClientHelloMessage(uint length, Version version, uint gmtUnixTime, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions, CipherSuite[] cipherSuites, CompressionMethod[] compressionMethods)
            : base(HandshakeType.ClientHello, length, version, gmtUnixTime, randomBytes, sessionId, extensions)
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
    }
}
