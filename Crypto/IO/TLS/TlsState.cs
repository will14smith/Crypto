using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using Crypto.Certificates;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.IO.Signing;
using Crypto.IO.TLS.Messages;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class TlsState
    {
        private readonly ITlsNegotiation negotiator = new DefaultTlsNegotiation();

        public TlsState(Stream stream)
        {
            this.stream = stream;

            state = TlsStateType.Initial;
        }

        public CertificateManager Certificates { get; } = new CertificateManager();

        #region client capabilities

        private TlsVersion clientMaxVersion;
        private CipherSuite[] clientCipherSuites;
        private CompressionMethod[] clientCompressionMethods;
        private HelloExtension[] clientExtensions;

        #endregion

        #region connection properties

        private TlsStateType state;

        public X509Certificate Certificate { get; private set; }
        public X509Certificate[] CertificateChain { get; private set; }

        public IDictionary<string, BigInteger> Params { get; } = new Dictionary<string, BigInteger>();

        public TlsVersion Version { get; private set; }

        private byte[] sessionId;
        private CipherSuite cipherSuite;
        private CompressionMethod compressionMethod;

        public KeyExchange KeyExchange { get; private set; }
        private ICipher cipherAlgorithm;
        private IDigest macAlgorithm;

        private byte[] masterSecret;
        public byte[] ClientRandom { get; private set; }
        public byte[] ServerRandom { get; private set; }

        // TODO extensions

        public void SetCertificates(X509Certificate cert, X509Certificate[] chain)
        {
            SecurityAssert.NotNull(cert);
            SecurityAssert.NotNull(chain);
            SecurityAssert.SAssert(chain.Length > 0);

            Certificate = cert;
            CertificateChain = chain;
        }

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

            ClientRandom = message.RandomBytes;

            NegotiateParameters();
        }

        public IEnumerable<HandshakeMessage> GenerateServerHello()
        {
            SecurityAssert.SAssert(state == TlsStateType.RecievedClientHello);
            state = TlsStateType.SentServerHello;

            var messages = new List<HandshakeMessage>();
            //TODO extensions
            messages.Add(new ServerHelloMessage(Version, ServerRandom, sessionId, new HelloExtension[0], cipherSuite, compressionMethod));

            messages.AddRange(KeyExchange.GenerateHandshakeMessages());

            // TODO optionally ask for client certificate

            messages.Add(new ServerHelloDoneMessage());

            return messages;
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            //TODO update state

            KeyExchange.HandleClientKeyExchange(message);
        }

        private void NegotiateParameters()
        {
            SecurityAssert.SAssert(state == TlsStateType.RecievedClientHello);

            // set parameters
            Version = negotiator.DecideVersion(clientMaxVersion);
            cipherSuite = negotiator.DecideCipherSuite(clientCipherSuites);
            compressionMethod = negotiator.DecideCompression(clientCompressionMethods);

            ServerRandom = RandomGenerator.RandomBytes(32);

            //TODO sessionId
            sessionId = new byte[0];

            //TODO extensions

            cipherAlgorithm = cipherSuite.GetCipher();
            macAlgorithm = cipherSuite.GetMACAlgorithm();

            KeyExchange = cipherSuite.GetKeyExchange();
            KeyExchange.Init(this);
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

        public SignedStream GetSignatureStream(Stream baseStream)
        {
            //TODO pass correct hash & sig algo
            var key = Certificates.GetPrivateKey(Certificate.SubjectPublicKey);
            var signatureAlgo = new RSA(key);

            return new SignedStream(baseStream, signatureAlgo, macAlgorithm);
        }
    }
}