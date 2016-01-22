using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public abstract class HelloMessage : HandshakeMessage
    {
        protected HelloMessage(HandshakeType type, TlsVersion version, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions) : base(type)
        {
            Version = version;

            SecurityAssert.NotNull(randomBytes);
            SecurityAssert.SAssert(randomBytes.Length == 32);
            RandomBytes = randomBytes;

            SecurityAssert.NotNull(sessionId);
            SecurityAssert.SAssert(sessionId.Length >= 0 && sessionId.Length <= 32);
            SessionId = sessionId;

            SecurityAssert.NotNull(extensions);
            SecurityAssert.SAssert(extensions.Length >= 0 && extensions.Length <= 0xFFFF);
            Extensions = extensions;
        }

        public TlsVersion Version { get; }
        public byte[] RandomBytes { get; }
        public byte[] SessionId { get; }

        public HelloExtension[] Extensions { get; }

        protected sealed override void Write(EndianBinaryWriter writer)
        {
            writer.Write(Version);
            writer.Write(RandomBytes);
            writer.WriteVariable(1, SessionId);
            WriteHello(writer);

            // TODO extensions
            SecurityAssert.SAssert(Extensions.Length == 0);
        }

        protected abstract void WriteHello(EndianBinaryWriter writer);
    }
}