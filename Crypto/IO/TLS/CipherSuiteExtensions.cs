using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Encryption;
using Crypto.Encryption.Block;
using Crypto.Encryption.Modes;
using Crypto.Hashing;

namespace Crypto.IO.TLS
{
    internal static class CipherSuiteExtensions
    {
        private static readonly ISet<CipherSuite> Suites = new HashSet<CipherSuite>();
        private static readonly Dictionary<CipherSuite, TlsCipherAlgorithm> CipherMapping = new Dictionary<CipherSuite, TlsCipherAlgorithm>();
        private static readonly Dictionary<CipherSuite, TlsHashAlgorithm> DigestMapping = new Dictionary<CipherSuite, TlsHashAlgorithm>();
        private static readonly Dictionary<CipherSuite, TlsSignatureAlgorithm> SignatureMapping = new Dictionary<CipherSuite, TlsSignatureAlgorithm>();
        private static readonly Dictionary<CipherSuite, TlsKeyExchange> KeyExchangeMapping = new Dictionary<CipherSuite, TlsKeyExchange>();

        private static readonly ISet<TlsCipherAlgorithm> CipherAlgorithms = new HashSet<TlsCipherAlgorithm>();
        private static readonly Dictionary<TlsCipherAlgorithm, Func<ICipher>> CipherFactories = new Dictionary<TlsCipherAlgorithm, Func<ICipher>>();

        private static readonly ISet<TlsHashAlgorithm> HashAlgorithms = new HashSet<TlsHashAlgorithm>();
        private static readonly Dictionary<TlsHashAlgorithm, Func<IDigest>> DigestFactories = new Dictionary<TlsHashAlgorithm, Func<IDigest>>();

        private static readonly ISet<TlsSignatureAlgorithm> SignatureAlgorithms = new HashSet<TlsSignatureAlgorithm>();
        private static readonly Dictionary<TlsSignatureAlgorithm, Func<ISignatureCipher>> SignatureFactories = new Dictionary<TlsSignatureAlgorithm, Func<ISignatureCipher>>();

        private static readonly ISet<TlsKeyExchange> KeyExchanges = new HashSet<TlsKeyExchange>();
        private static readonly Dictionary<TlsKeyExchange, Func<ITlsKeyExchange>> KeyExchangeFactories = new Dictionary<TlsKeyExchange, Func<ITlsKeyExchange>>();

        // 

        static CipherSuiteExtensions()
        {
            // ciphers
            RegisterCipher(TlsCipherAlgorithm.Null, () => new NullCipher());
            RegisterCipher(TlsCipherAlgorithm.RC4_128, () => new RC4Cipher(128));
            RegisterCipher(TlsCipherAlgorithm.THREEDES_EDE_CBC, () => new BlockCipherAdapter(new ThreeDESCipher(ThreeDESKeyOptions.Option1)));
            RegisterCipher(TlsCipherAlgorithm.AES_128_CBC, () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(128))));
            RegisterCipher(TlsCipherAlgorithm.AES_256_CBC, () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(256))));

            // hashes
            RegisterHash(TlsHashAlgorithm.None, () => new NullDigest());
            // TODO RegisterHash(TlsHashAlgorithm.MD5, () => { throw new NotImplementedException(); });
            RegisterHash(TlsHashAlgorithm.SHA1, () => new SHA1Digest());
            // TODO RegisterHash(TlsHashAlgorithm.SHA224, () => { throw new NotImplementedException(); });
            RegisterHash(TlsHashAlgorithm.SHA256, () => new SHA256Digest());
            // TODO RegisterHash(TlsHashAlgorithm.SHA384, () => { throw new NotImplementedException(); });
            // TODO RegisterHash(TlsHashAlgorithm.SHA512, () => { throw new NotImplementedException(); });

            // signatures
            RegisterSignature(TlsSignatureAlgorithm.Anonymous, () => new NullCipher());
            RegisterSignature(TlsSignatureAlgorithm.RSA, () => new RSA());
            // TODO RegisterSignature(TlsSignatureAlgorithm.DSA, () => { throw new NotImplementedException(); });

            // key exchanges
            RegisterKeyExchange(TlsKeyExchange.Null, () => new NullKeyExchange());
            RegisterKeyExchange(TlsKeyExchange.RSA, () => new RSAKeyExchange());
            // TODO RegisterKeyExchange(TlsKeyExchange.DH_DSS, () => { throw new NotImplementedException(); });
            RegisterKeyExchange(TlsKeyExchange.DH_RSA, () => new DHKeyExchange(new RSAKeyExchange()));
            // TODO RegisterKeyExchange(TlsKeyExchange.DHE_DSS, () => { throw new NotImplementedException(); });
            RegisterKeyExchange(TlsKeyExchange.DHE_RSA, () => new DHEKeyExchange(new RSAKeyExchange()));
            // TODO RegisterKeyExchange(TlsKeyExchange.DH_anon, () => { throw new NotImplementedException(); });

            // suites
            RegisterSuite(CipherSuite.TLS_NULL_WITH_NULL_NULL, TlsCipherAlgorithm.Null, TlsHashAlgorithm.None, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.Null);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_MD5, TlsCipherAlgorithm.Null, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_SHA, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_SHA256, TlsCipherAlgorithm.Null, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5, TlsCipherAlgorithm.RC4_128, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, TlsCipherAlgorithm.THREEDES_EDE_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256, TlsCipherAlgorithm.AES_128_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256, TlsCipherAlgorithm.AES_256_CBC, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
        }

        #region helpers
        public static bool IsBlock(this CipherSuite suite)
        {
            return suite.CreateCipherAlgorithm() is BlockCipherAdapter;
        }
        public static bool IsAEAD(this CipherSuite suite)
        {
            return suite.CreateCipherAlgorithm() is AEADCipherAdapter;
        }
        #endregion

        #region registration
        internal static void RegisterSuite(CipherSuite suite, TlsCipherAlgorithm cipher, TlsHashAlgorithm digest, TlsSignatureAlgorithm signature, TlsKeyExchange exchange)
        {
            Suites.Add(suite);

            CipherMapping.Add(suite, cipher);
            DigestMapping.Add(suite, digest);
            SignatureMapping.Add(suite, signature);
            KeyExchangeMapping.Add(suite, exchange);
        }

        internal static void RegisterCipher(TlsCipherAlgorithm algo, Func<ICipher> factory)
        {
            if (!CipherAlgorithms.Add(algo))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            CipherFactories.Add(algo, factory);
        }
        internal static void RegisterHash(TlsHashAlgorithm algo, Func<IDigest> factory)
        {
            if (!HashAlgorithms.Add(algo))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            DigestFactories.Add(algo, factory);
        }

        internal static void RegisterSignature(TlsSignatureAlgorithm algo, Func<ISignatureCipher> factory)
        {
            if (!SignatureAlgorithms.Add(algo))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            SignatureFactories.Add(algo, factory);
        }

        internal static void RegisterKeyExchange(TlsKeyExchange algo, Func<ITlsKeyExchange> factory)
        {
            if (!KeyExchanges.Add(algo))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            KeyExchangeFactories.Add(algo, factory);
        }
        #endregion

        #region resolvers
        public static ICipher CreateCipherAlgorithm(this CipherSuite suite)
        {
            return CipherFactories[CipherMapping[suite]]();
        }

        public static TlsHashAlgorithm GetDigestAlgorithm(this CipherSuite suite)
        {
            return DigestMapping[suite];
        }
        public static IDigest CreateDigestAlgorithm(TlsHashAlgorithm algo)
        {
            return DigestFactories[algo]();
        }

        public static TlsSignatureAlgorithm GetSignatureAlgorithm(this CipherSuite suite)
        {
            return SignatureMapping[suite];
        }
        public static ISignatureCipher CreateSignatureAlgorithm(TlsSignatureAlgorithm algo)
        {
            return SignatureFactories[algo]();
        }

        public static ITlsKeyExchange CreateKeyExchange(this CipherSuite suite)
        {
            return KeyExchangeFactories[KeyExchangeMapping[suite]]();
        }
        #endregion

        public static IEnumerable<CipherSuite> GetSupportedCipherSuites()
        {
            return Suites.Where(IsSupported);
        }

        private static bool IsSupported(CipherSuite suite)
        {
            // suite
            if (!Suites.Contains(suite)) { return false; }
            // cipher
            if (!CipherMapping.ContainsKey(suite)) { return false; }
            if (!IsSupported(CipherMapping[suite])) { return false; }
            // digest
            if (!DigestMapping.ContainsKey(suite)) { return false; }
            if (!IsSupported(DigestMapping[suite])) { return false; }
            // signature
            if (!SignatureMapping.ContainsKey(suite)) { return false; }
            if (!IsSupported(SignatureMapping[suite])) { return false; }
            // keyexchange
            if (!KeyExchangeMapping.ContainsKey(suite)) { return false; }
            if (!IsSupported(KeyExchangeMapping[suite])) { return false; }

            return true;
        }
        public static bool IsSupported(TlsCipherAlgorithm algo)
        {
            return CipherAlgorithms.Contains(algo);
        }
        public static bool IsSupported(TlsHashAlgorithm algo)
        {
            return HashAlgorithms.Contains(algo);
        }
        public static bool IsSupported(TlsSignatureAlgorithm algo)
        {
            return SignatureAlgorithms.Contains(algo);
        }
        public static bool IsSupported(TlsKeyExchange algo)
        {
            return KeyExchanges.Contains(algo);
        }
    }
}