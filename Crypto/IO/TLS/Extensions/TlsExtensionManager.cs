using System;
using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.IO.TLS.Extensions
{
    public delegate ITlsExtension ExtensionFactory(TlsState state, byte[] helloData);

    public class TlsExtensionManager
    {
        #region static

        private static readonly TlsExtensionManager Instance = new TlsExtensionManager();

        private static readonly IList<TlsExtensionConfiguration> Extensions = new List<TlsExtensionConfiguration>();
        private static readonly IDictionary<ushort, ExtensionFactory> HelloExtensionFactories = new Dictionary<ushort, ExtensionFactory>();

        private TlsExtensionManager() { }

        public static void RegisterExtension(TlsExtensionConfiguration extensionConfiguration)
        {
            extensionConfiguration.Configure(Instance);
            Extensions.Add(extensionConfiguration);
        }

        public static ExtensionFactory LookupFactory(ushort type)
        {
            ExtensionFactory result;
            if (HelloExtensionFactories.TryGetValue(type, out result))
            {
                return result;
            }

            return null;
        }
        #endregion

        #region Instance

        public void RegisterSuite<T>(T cipherSuite, TlsCipherAlgorithm cipher, TlsHashAlgorithm digest, TlsSignatureAlgorithm signature, TlsKeyExchange exchange)
            where T : struct
        {
            SecurityAssert.SAssert(typeof(T).IsEnum);

            // yay...
            var x = (CipherSuite)(ushort)(ValueType)cipherSuite;

            RegisterSuite(x, cipher, digest, signature, exchange);
        }

        public void RegisterSuite(CipherSuite cipherSuite, TlsCipherAlgorithm cipher, TlsHashAlgorithm digest, TlsSignatureAlgorithm signature, TlsKeyExchange exchange)
        {
            CipherSuiteExtensions.RegisterSuite(cipherSuite, cipher, digest, signature, exchange);
        }
        public void RegisterCipher(TlsCipherAlgorithm algorithm, Func<ICipher> factory)
        {
            CipherSuiteExtensions.RegisterCipher(algorithm, factory);
        }
        public void RegisterHash(TlsHashAlgorithm algorithm, Func<IDigest> factory)
        {
            CipherSuiteExtensions.RegisterHash(algorithm, factory);
        }
        public void RegisterSignature(TlsSignatureAlgorithm algorithm, Func<ISignatureCipher> factory)
        {
            CipherSuiteExtensions.RegisterSignature(algorithm, factory);
        }
        public void RegisterKeyExchange(TlsKeyExchange keyExchange, Func<ITlsKeyExchange> factory)
        {
            CipherSuiteExtensions.RegisterKeyExchange(keyExchange, factory);
        }

        public void RegisterHelloExtension(ushort type, ExtensionFactory factory)
        {
            HelloExtensionFactories.Add(type, factory);
        }

        public void RegisterPublicKeyReader(ASN1ObjectIdentifier algorithm, Func<IPublicKeyReader> factory)
        {
            KeyReaderRegistry.Register(algorithm, factory);
        }

        #endregion
    }
}