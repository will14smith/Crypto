using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.Certificates;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.IO.TLS.Messages;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    internal class TlsState
    {
        private readonly ITlsNegotiation negotiator = new DefaultTlsNegotiation();

        public TlsState(Stream stream)
        {
            this.stream = stream;

            state = TlsStateType.Initial;
        }

        #region client capabilities

        private TlsVersion clientMaxVersion;
        private CipherSuite[] clientCipherSuites;
        private CompressionMethod[] clientCompressionMethods;
        private HelloExtension[] clientExtensions;

        #endregion

        #region connection properties

        private TlsStateType state;

        public TlsVersion Version { get; private set; }
        private byte[] sessionId;
        private CipherSuite cipherSuite;
        private CompressionMethod compressionMethod;

        private ICipher bulkCipherAlgorithm;
        private IMACAlgorithm macAlgorithm;

        private byte[] masterSecret;
        private byte[] clientRandom;
        private byte[] serverRandom;

        // TODO extensions

        #endregion

        #region handshake

        public void HandleClientHello(ClientHelloMessage message)
        {
            SecurityAssert.SAssert(state == TlsStateType.Initial);
            state = TlsStateType.RecievedClientHello;

            clientMaxVersion = message.Version;
            clientCipherSuites = message.CipherSuites;
            clientCompressionMethods = message.CompressionMethods;
            clientExtensions = message.Extensions;

            clientRandom = message.RandomBytes;

            NegotiateParameters();
        }

        public IEnumerable<HandshakeMessage> GenerateServerHello()
        {
            var messages = new List<HandshakeMessage>();
            //TODO extensions
            messages.Add(new ServerHelloMessage(Version, serverRandom, sessionId, new HelloExtension[0], cipherSuite, compressionMethod));

            var requiresCertificate = false;
            if (requiresCertificate)
            {
                throw new NotImplementedException();
            }

            var requiresKeyExchange = false;
            if (requiresKeyExchange)
            {
                throw new NotImplementedException();
            }

            var requiresClientCertificate = false;
            if (requiresClientCertificate)
            {
                throw new NotImplementedException();
            }

            messages.Add(new ServerHelloDoneMessage());

            return messages;
        }

        private void NegotiateParameters()
        {
            SecurityAssert.SAssert(state == TlsStateType.RecievedClientHello);
            state = TlsStateType.RecievedClientHello;

            // set parameters
            Version = negotiator.DecideVersion(clientMaxVersion);
            cipherSuite = negotiator.DecideCipherSuite(clientCipherSuites);
            compressionMethod = negotiator.DecideCompression(clientCompressionMethods);

            serverRandom = new byte[32];
            // INSECURE RANDOM
            new Random().NextBytes(serverRandom);

            //TODO sessionId
            sessionId = new byte[0];

            //TODO extensions

            //TODO set bulkCipherAlgorithm & macAlgorithm
        }

        #endregion

        #region stream
        private readonly Stream stream;

        public RecordReader GetRecordReader()
        {
            return new PlaintextReader(stream);
        }
        public RecordWriter GetRecordWriter()
        {
            return new PlaintextWriter(stream);
        }

        public void Flush()
        {
            stream.Flush();
        }
        #endregion
    }
}
