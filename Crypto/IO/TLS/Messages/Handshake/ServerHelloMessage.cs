﻿using Crypto.IO.TLS.Messages.Handshake;

namespace Crypto.IO.TLS.Messages
{
    public class ServerHelloMessage : HelloMessage
    {
        public ServerHelloMessage(uint length, Version version, uint gmtUnixTime, byte[] randomBytes, byte[] sessionId, HelloExtension[] extensions, CipherSuite cipherSuite, CompressionMethod compressionMethod)
            : base(HandshakeType.ServerHello, length, version, gmtUnixTime, randomBytes, sessionId, extensions)
        {
            CipherSuite = cipherSuite;
            CompressionMethod = compressionMethod;
        }

        public CipherSuite CipherSuite { get; }
        public CompressionMethod CompressionMethod { get; }
    }
}