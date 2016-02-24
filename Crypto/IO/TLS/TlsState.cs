﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.Certificates;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.IO.Signing;
using Crypto.IO.TLS.Extensions;
using Crypto.IO.TLS.Messages;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class TlsState
    {
        static TlsState()
        {
            TlsExtensionManager.RegisterExtension(new SignatureAlgorithmExtensionConfiguration());
        }

        public TlsState(Stream stream)
        {
            this.stream = stream;

            RecordReader = new RecordReader(this, stream);
            RecordWriter = new RecordWriter(this, stream);

            state = TlsStateType.Initial;

            handshakeVerify = GetPRFDigest();
            RecordStrategy = GetRecordStrategy();
        }

        #region client capabilities

        private TlsVersion clientMaxVersion;
        private CipherSuite[] clientCipherSuites;
        private CompressionMethod[] clientCompressionMethods;

        #endregion

        #region connection state

        public ConnectionEnd ConnectionEnd { get; private set; }


        private TlsStateType state;

        public void SetMode(ConnectionEnd connectionEnd)
        {
            SecurityAssert.SAssert(state == TlsStateType.Initial);

            ConnectionEnd = connectionEnd;

            switch (connectionEnd)
            {
                case ConnectionEnd.Client:
                    state = TlsStateType.SendingClientHello;
                    break;
                case ConnectionEnd.Server:
                    state = TlsStateType.WaitingForClientHello;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(connectionEnd));
            }
        }

        #endregion

        #region handshake verification

        private readonly IDigest handshakeVerify;
        private byte[] expectedHandshakeVerifyData;

        public void UpdateHandshakeVerify(byte[] buffer, int offset, int length)
        {
            handshakeVerify.Update(buffer, offset, length);
        }

        public void ComputeHandshakeVerify()
        {
            SecurityAssert.SAssert(state == TlsStateType.WaitingForClientFinished);
            SecurityAssert.SAssert(ReadProtected);

            expectedHandshakeVerifyData = handshakeVerify.Clone().Digest();
        }

        #endregion

        #region record properties

        public long ReadSeqNum { get; set; }
        public long WriteSeqNum { get; set; }

        public bool ReadProtected { get; private set; }
        public bool WriteProtected { get; private set; }

        public RecordReader RecordReader { get; }
        public RecordWriter RecordWriter { get; }

        internal IRecordStrategy RecordStrategy { get; private set; }

        private void EnableReadProtection()
        {
            SetProtection(true, WriteProtected);
        }

        private void EnableWriteProtection()
        {
            SetProtection(ReadProtected, true);
        }

        private void SetProtection(bool read, bool write)
        {
            ReadProtected = read;
            WriteProtected = write;

            RecordStrategy = GetRecordStrategy();
        }

        private IRecordStrategy GetRecordStrategy()
        {
            if (!ReadProtected && !WriteProtected)
            {
                return new PlaintextStrategy(this, stream);
            }

            RecordStrategy strategy;
            var cipher = GetCipher();
            if (cipher is BlockCipherAdapter)
            {
                strategy = new BlockCipherStrategy(this, stream);
            }
            else if (cipher is AEADCipherAdapter)
            {
                strategy = new AEADCipherStrategy(this, stream);
            }
            else
            {
                throw new NotImplementedException();
            }


            if (ReadProtected && WriteProtected)
            {
                return strategy;
            }

            var plainText = new PlaintextStrategy(this, stream);

            return new CompositeRecordStrategy(
                ReadProtected ? strategy : plainText,
                WriteProtected ? strategy : plainText);
        }

        #endregion

        #region security parameters

        public IDictionary<string, BigInteger> Params { get; } = new Dictionary<string, BigInteger>();

        public TlsVersion Version { get; private set; }

        private byte[] sessionId;
        private CipherSuite cipherSuite;
        private CompressionMethod compressionMethod;

        public ITlsKeyExchange KeyExchange { get; private set; }

        private byte[] masterSecret;
        public byte[] ClientRandom { get; private set; }
        public byte[] ServerRandom { get; private set; }

        private byte[] clientMACKey;
        private byte[] serverMACKey;
        private byte[] clientKey;
        private byte[] serverKey;
        private byte[] clientIV;
        private byte[] serverIV;

        public void ComputeMasterSecret(byte[] preMasterSecret)
        {
            var random = new byte[ClientRandom.Length + ServerRandom.Length];

            Array.Copy(ClientRandom, 0, random, 0, ClientRandom.Length);
            Array.Copy(ServerRandom, 0, random, ClientRandom.Length, ServerRandom.Length);

            var prf = new PRF(GetPRFDigest());

            var secret = prf.Digest(preMasterSecret, "master secret", random).Take(48).ToArray();

            masterSecret = secret;

            ComputeKeys();
        }

        private void ComputeKeys()
        {
            var cipher = cipherSuite.CreateCipherAlgorithm();
            var mac = CipherSuiteExtensions.CreateDigestAlgorithm(cipherSuite.GetDigestAlgorithm());

            // assuming server
            var prf = new PRF(GetPRFDigest());

            var random = new byte[ServerRandom.Length + ClientRandom.Length];

            Array.Copy(ServerRandom, 0, random, 0, ServerRandom.Length);
            Array.Copy(ClientRandom, 0, random, ServerRandom.Length, ClientRandom.Length);

            var macKeyLength = mac.HashSize / 8;
            var encKeyLength = cipher.KeySize;
            // for AEAD - TODO is it constant?
            var implicitIVLength = 4;

            var keyBlockLength = 2 * macKeyLength + 2 * encKeyLength + 2 * implicitIVLength;

            var keyBlock = prf.Digest(masterSecret, "key expansion", random).Take(keyBlockLength).ToArray();

            var offset = 0;

            if (cipherSuite.IsBlock())
            {
                clientMACKey = new byte[macKeyLength];
                Array.Copy(keyBlock, offset, clientMACKey, 0, macKeyLength);
                offset += macKeyLength;

                serverMACKey = new byte[macKeyLength];
                Array.Copy(keyBlock, offset, serverMACKey, 0, macKeyLength);
                offset += macKeyLength;
            }

            clientKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, clientKey, 0, encKeyLength);
            offset += encKeyLength;

            serverKey = new byte[encKeyLength];
            Array.Copy(keyBlock, offset, serverKey, 0, encKeyLength);
            offset += encKeyLength;

            if (cipherSuite.IsAEAD())
            {
                clientIV = new byte[implicitIVLength];
                Array.Copy(keyBlock, offset, clientIV, 0, implicitIVLength);
                offset += implicitIVLength;

                serverIV = new byte[implicitIVLength];
                Array.Copy(keyBlock, offset, serverIV, 0, implicitIVLength);
            }
        }

        #endregion

        #region extensions

        private readonly Dictionary<ushort, ITlsExtension> extensions
            = new Dictionary<ushort, ITlsExtension>();

        private bool TryGetExtension<T>(ushort key, out T ext)
            where T : class, ITlsExtension
        {
            ITlsExtension tmp;

            if (!extensions.TryGetValue(key, out tmp))
            {
                ext = default(T);
                return false;
            }

            ext = tmp as T;
            return ext != null;
        }

        private void HandleClientExtensions(IEnumerable<HelloExtension> clientExtensions)
        {
            foreach (var clientExtension in clientExtensions)
            {
                var extensionFactory = TlsExtensionManager.LookupFactory(clientExtension.Type);
                if (extensionFactory != null)
                {
                    extensions.Add(clientExtension.Type, extensionFactory(this, clientExtension.Data));
                }
            }
        }
        private IEnumerable<HelloExtension> GenerateExtensionsHello()
        {
            return extensions.Select(extension => extension.Value.GenerateHello()).Where(hello => hello != null);
        }

        #endregion

        #region certificates

        public CertificateManager Certificates { get; } = new CertificateManager();

        public X509Certificate Certificate { get; private set; }
        public X509Certificate[] CertificateChain { get; private set; }

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

        private readonly ITlsNegotiation negotiator = new DefaultTlsNegotiation();

        public void HandleClientHello(ClientHelloMessage message)
        {
            SecurityAssert.SAssert(state == TlsStateType.WaitingForClientHello);
            state = TlsStateType.RecievedClientHello;

            clientMaxVersion = message.Version;
            clientCipherSuites = message.CipherSuites;
            clientCompressionMethods = message.CompressionMethods;
            HandleClientExtensions(message.Extensions);

            ClientRandom = message.RandomBytes;

            NegotiateParameters();
        }

        public IEnumerable<HandshakeMessage> GenerateServerHello()
        {
            SecurityAssert.SAssert(state == TlsStateType.RecievedClientHello);
            state = TlsStateType.SendingServerHello;

            var helloExtensions = GenerateExtensionsHello().ToArray();
            yield return new ServerHelloMessage(Version, ServerRandom, sessionId, helloExtensions, cipherSuite, compressionMethod);

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
            SecurityAssert.SAssert(!ReadProtected && !WriteProtected);

            EnableReadProtection();

            state = TlsStateType.WaitingForClientFinished;
        }

        public void SentChangeCipherSpec()
        {
            SecurityAssert.SAssert(state == TlsStateType.Active);
            SecurityAssert.SAssert(!WriteProtected);

            EnableWriteProtection();
        }

        public void VerifyFinished(FinishedHandshakeMessage message)
        {
            SecurityAssert.SAssert(state == TlsStateType.WaitingForClientFinished);
            SecurityAssert.SAssert(ReadProtected);
            SecurityAssert.SAssert(!WriteProtected);

            var prf = new PRF(GetPRFDigest());

            var finishedLabel = ConnectionEnd != ConnectionEnd.Server ? "server finished" : "client finished";
            var expectedData =
                prf.Digest(masterSecret, finishedLabel, expectedHandshakeVerifyData)
                    .Take(FinishedHandshakeMessage.VerifyDataLength)
                    .ToArray();

            SecurityAssert.HashAssert(message.VerifyData, expectedData);

            state = TlsStateType.Active;
        }

        public FinishedHandshakeMessage GenerateFinishedMessage()
        {
            var prf = new PRF(GetPRFDigest());

            var handshakeVerifyHash = handshakeVerify.Clone().Digest();
            var finishedLabel = ConnectionEnd == ConnectionEnd.Server ? "server finished" : "client finished";

            var verifyData =
                prf.Digest(masterSecret, finishedLabel, handshakeVerifyHash)
                    .Take(FinishedHandshakeMessage.VerifyDataLength)
                    .ToArray();

            return new FinishedHandshakeMessage(verifyData);
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

            KeyExchange = cipherSuite.CreateKeyExchange();
            KeyExchange.Init(this);
        }

        #endregion

        #region stream

        private readonly Stream stream;

        public void Flush()
        {
            stream.Flush();
        }

        public SignedStream GetSignatureStream(Stream baseStream)
        {
            var algos = GetSigningAlgorithms();

            var digestAlgorithm = CipherSuiteExtensions.CreateDigestAlgorithm(algos.Item1);
            var signatureAlgorithm = CipherSuiteExtensions.CreateSignatureAlgorithm(algos.Item2);

            var key = Certificates.GetPrivateKey(Certificate.SubjectPublicKey);
            signatureAlgorithm.Init(new PrivateKeyParameter(key));

            return new SignedStream(baseStream, signatureAlgorithm, digestAlgorithm);
        }

        internal Tuple<TlsHashAlgorithm, TlsSignatureAlgorithm> GetSigningAlgorithms()
        {
            TlsHashAlgorithm hashAlgo;
            TlsSignatureAlgorithm signatureAlgo;

            SignatureAlgorithmExtension ext;
            if (TryGetExtension(SignatureAlgorithmExtension.Type, out ext))
            {
                hashAlgo = ext.GetDigestAlgorithm();
                signatureAlgo = ext.GetSignatureAlgorithm();
            }
            else
            {
                hashAlgo = cipherSuite.GetDigestAlgorithm();
                signatureAlgo = cipherSuite.GetSignatureAlgorithm();
            }

            return Tuple.Create(hashAlgo, signatureAlgo);
        }

        #endregion

        #region digest

        public IDigest GetPRFDigest()
        {
            return new SHA256Digest();
        }

        public IDigest GetMAC(bool reader)
        {
            SecurityAssert.SAssert(ReadProtected || !reader);
            SecurityAssert.SAssert(WriteProtected || reader);

            var digest = CipherSuiteExtensions.CreateDigestAlgorithm(cipherSuite.GetDigestAlgorithm());

            var key = reader
                ? (ConnectionEnd == ConnectionEnd.Server ? clientMACKey : serverMACKey)
                : (ConnectionEnd == ConnectionEnd.Server ? serverMACKey : clientMACKey);

            return new HMAC(digest, key);
        }

        #endregion

        #region cipher

        public ICipher GetCipher()
        {
            return cipherSuite.CreateCipherAlgorithm();
        }

        public ICipherParameters GetBlockCipherParameters(bool reader)
        {
            SecurityAssert.SAssert(ReadProtected || !reader);
            SecurityAssert.SAssert(WriteProtected || reader);

            var key = reader
                ? (ConnectionEnd == ConnectionEnd.Server ? clientKey : serverKey)
                : (ConnectionEnd == ConnectionEnd.Server ? serverKey : clientKey);

            return new KeyParameter(key);
        }

        public ICipherParameters GetAEADParameters(bool reader, byte[] aad, byte[] nonceExplicit)
        {
            SecurityAssert.SAssert(ReadProtected || !reader);
            SecurityAssert.SAssert(WriteProtected || reader);

            byte[] key, nonceImplicit;
            if (reader)
            {
                if (ConnectionEnd == ConnectionEnd.Server)
                {
                    key = clientKey;
                    nonceImplicit = clientIV;
                }
                else
                {
                    key = serverKey;
                    nonceImplicit = serverIV;
                }
            }
            else
            {
                if (ConnectionEnd == ConnectionEnd.Server)
                {
                    key = serverKey;
                    nonceImplicit = serverIV;
                }
                else
                {
                    key = clientKey;
                    nonceImplicit = clientIV;
                }
            }

            var nonce = new byte[nonceImplicit.Length + nonceExplicit.Length];
            Array.Copy(nonceImplicit, 0, nonce, 0, nonceImplicit.Length);
            Array.Copy(nonceExplicit, 0, nonce, nonceImplicit.Length, nonceExplicit.Length);

            return new AADParameter(new IVParameter(new KeyParameter(key), nonce), aad);
        }

        #endregion
    }
}