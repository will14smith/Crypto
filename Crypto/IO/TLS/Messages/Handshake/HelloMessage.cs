using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public abstract class HelloMessage : HandshakeMessage
    {
        protected HelloMessage(HandshakeType type, TlsVersion version, uint gmtUnixTime, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions) : base(type)
        {
            Version = version;
            GmtUnixTime = gmtUnixTime;

            SecurityAssert.NotNull(randomBytes);
            SecurityAssert.SAssert(randomBytes.Length == 28);
            RandomBytes = randomBytes;

            SecurityAssert.NotNull(sessionId);
            SecurityAssert.SAssert(sessionId.Length >= 0 && sessionId.Length <= 32);
            SessionId = sessionId;

            SecurityAssert.NotNull(extensions);
            SecurityAssert.SAssert(extensions.Length >= 0 && extensions.Length <= 0xFFFF);
            Extensions = extensions;
        }

        public TlsVersion Version { get; }

        // RANDOM
        public uint GmtUnixTime { get; }
        public byte[] RandomBytes { get; }
        // END RANDOM

        public byte[] SessionId { get; }

        public HelloExtension[] Extensions { get; }
    }
}