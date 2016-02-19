using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.Certificates;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
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

        #region connection state

        public TlsMode Mode { get; private set; }


        private TlsStateType state;
        public void SetMode(TlsMode mode)
        {
            SecurityAssert.SAssert(state == TlsStateType.Initial);

            Mode = mode;

            switch (mode)
            {
                case TlsMode.Client:
                    state = TlsStateType.SendingClientHello;
                    break;
                case TlsMode.Server:
                    state = TlsStateType.WaitingForClientHello;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode));
            }
        }

        #endregion

        #region connection properties

        public bool Protected { get; private set; }

        public X509Certificate Certificate { get; private set; }
        public X509Certificate[] CertificateChain { get; private set; }

        public IDictionary<string, BigInteger> Params { get; } = new Dictionary<string, BigInteger>();

        public TlsVersion Version { get; private set; }

        private byte[] sessionId;
        private CipherSuite cipherSuite;
        private CompressionMethod compressionMethod;

        public KeyExchange KeyExchange { get; private set; }

        private byte[] masterSecret;
        public byte[] ClientRandom { get; private set; }
        public byte[] ServerRandom { get; private set; }

        private byte[] clientMACKey;
        private byte[] serverMACKey;
        private byte[] clientKey;
        private byte[] serverKey;


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
            SecurityAssert.SAssert(state == TlsStateType.WaitingForClientHello);
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
            state = TlsStateType.SendingServerHello;

            //TODO extensions
            yield return new ServerHelloMessage(Version, ServerRandom, sessionId, new HelloExtension[0], cipherSuite, compressionMethod);

            foreach (var message in KeyExchange.GenerateHandshakeMessages())
            {
                yield return message;
            }

            yield return new ServerHelloDoneMessage();
        }

        public void SentServerHello()
        {
            SecurityAssert.SAssert(state == TlsStateType.SendingServerHello);

            state = TlsStateType.SentServerHello;
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            SecurityAssert.SAssert(state == TlsStateType.SentServerHello);

            state = TlsStateType.RecievedClientKeyExchange;

            KeyExchange.HandleClientKeyExchange(message);
        }

        public void ReceivedChangeCipherSpec()
        {
            SecurityAssert.SAssert(state == TlsStateType.RecievedClientKeyExchange);
            SecurityAssert.SAssert(!Protected);

            Protected = true;
        }

        public void SentChangeCipherSpec()
        {
            throw new NotImplementedException();
        }

        public void ComputeMasterSecret(byte[] preMasterSecret)
        {
            var random = new byte[ClientRandom.Length + ServerRandom.Length];

            Array.Copy(ClientRandom, 0, random, 0, ClientRandom.Length);
            Array.Copy(ServerRandom, 0, random, ClientRandom.Length, ServerRandom.Length);

            var prf = new PRF(new SHA256Digest());

            var secret = prf.Digest(preMasterSecret, "master secret", random).Take(48).ToArray();
            SecurityAssert.SAssert(secret.Length == 48);

            masterSecret = secret;

            Console.WriteLine(HexConverter.ToHex(masterSecret));

            ComputeKeys();
        }

        private void ComputeKeys()
        {
            var cipher = cipherSuite.GetCipher();
            var mac = cipherSuite.GetMACAlgorithm();

            // assuming server
            var prf = new PRF(new SHA256Digest());

            var random = new byte[ServerRandom.Length + ClientRandom.Length];

            Array.Copy(ServerRandom, 0, random, 0, ServerRandom.Length);
            Array.Copy(ClientRandom, 0, random, ServerRandom.Length, ClientRandom.Length);

            var macKeyLength = mac.HashSize / 8;
            var encKeyLength = cipher.KeyLength;

            var keyBlockLength = 2 * macKeyLength + 2 * encKeyLength;

            var keyBlock = prf.Digest(masterSecret, "key expansion", random).Take(keyBlockLength).ToArray();

            int offset = 0;

            clientMACKey = new byte[macKeyLength];
            Array.Copy(keyBlock, offset, clientMACKey, 0, macKeyLength);
            offset += macKeyLength;

            serverMACKey = new byte[macKeyLength];
            Array.Copy(keyBlock, offset, serverMACKey, 0, macKeyLength);
            offset += macKeyLength;

            clientKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, clientKey, 0, encKeyLength);
            offset += encKeyLength;

            serverKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, serverKey, 0, encKeyLength);
            // offset += encKeyLength;

            //TODO get iv (for AEAD)
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

            KeyExchange = cipherSuite.GetKeyExchange();
            KeyExchange.Init(this);
        }

        #endregion

        #region stream

        private readonly Stream stream;

        public RecordReader GetRecordReader()
        {
            return new RecordReader(this, stream);
        }

        public RecordWriter GetRecordWriter()
        {
            return new RecordWriter(this, stream);
        }

        public void Flush()
        {
            stream.Flush();
        }

        #endregion

        public SignedStream GetSignatureStream(Stream baseStream)
        {
            //TODO pass correct sig algo
            var key = Certificates.GetPrivateKey(Certificate.SubjectPublicKey);
            var signatureAlgo = new RSA(key);

            return new SignedStream(baseStream, signatureAlgo, GetMAC());
        }

        public ICipher GetCipher()
        {
            SecurityAssert.SAssert(Protected);

            return cipherSuite.GetCipher();
        }

        public IDigest GetMAC()
        {
            return cipherSuite.GetMACAlgorithm();
        }

        public ICipherParameters GetBlockCipherParameters(bool server)
        {
            return server ? new KeyParameter(serverKey) : new KeyParameter(clientKey);
        }
    }
}