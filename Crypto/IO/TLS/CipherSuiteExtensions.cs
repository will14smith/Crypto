using System;
using System.Collections.Generic;
using Crypto.Encryption;
using Crypto.Encryption.Block;
using Crypto.Encryption.Modes;
using Crypto.Hashing;

namespace Crypto.IO.TLS
{
    internal static class CipherSuiteExtensions
    {
        private static readonly ISet<CipherSuite> Suites = new HashSet<CipherSuite>();
        private static readonly Dictionary<CipherSuite, Func<ICipher>> CipherFactories = new Dictionary<CipherSuite, Func<ICipher>>();
        private static readonly Dictionary<CipherSuite, TlsHashAlgorithm> DigestMapping = new Dictionary<CipherSuite, TlsHashAlgorithm>();
        private static readonly Dictionary<CipherSuite, TlsSignatureAlgorithm> SignatureMapping = new Dictionary<CipherSuite, TlsSignatureAlgorithm>();
        private static readonly Dictionary<CipherSuite, TlsKeyExchange> KeyExchangeMapping = new Dictionary<CipherSuite, TlsKeyExchange>();

        private static readonly ISet<TlsHashAlgorithm> HashAlgorithms = new HashSet<TlsHashAlgorithm>();
        private static readonly Dictionary<TlsHashAlgorithm, Func<IDigest>> DigestFactories = new Dictionary<TlsHashAlgorithm, Func<IDigest>>();

        private static readonly ISet<TlsSignatureAlgorithm> SignatureAlgorithms = new HashSet<TlsSignatureAlgorithm>();
        private static readonly Dictionary<TlsSignatureAlgorithm, Func<ISignatureCipher>> SignatureFactories = new Dictionary<TlsSignatureAlgorithm, Func<ISignatureCipher>>();

        private static readonly ISet<TlsKeyExchange> KeyExchanges = new HashSet<TlsKeyExchange>();
        private static readonly Dictionary<TlsKeyExchange, Func<IKeyExchange>> KeyExchangeFactories = new Dictionary<TlsKeyExchange, Func<IKeyExchange>>();

        // 

        static CipherSuiteExtensions()
        {
            // ciphers
            Func<ICipher> nullCipher = () => new NullCipher();
            Func<ICipher> rc4 = () => new RC4Cipher(128);
            Func<ICipher> threeDes = () => new BlockCipherAdapter(new ThreeDESCipher(ThreeDESKeyOptions.Option1));
            Func<ICipher> aes128 = () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(128)));
            Func<ICipher> aes256 = () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(256)));

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
            RegisterSuite(CipherSuite.TLS_NULL_WITH_NULL_NULL, nullCipher, TlsHashAlgorithm.None, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.Null);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_MD5, nullCipher, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_SHA, nullCipher, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_NULL_SHA256, nullCipher, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5, rc4, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA, rc4, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DH_DSS);
            RegisterSuite(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DH_RSA);
            RegisterSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.DSA, TlsKeyExchange.DHE_DSS);
            RegisterSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.RSA, TlsKeyExchange.DHE_RSA);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5, rc4, TlsHashAlgorithm.MD5, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, threeDes, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA, aes128, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA, aes256, TlsHashAlgorithm.SHA1, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256, aes128, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
            RegisterSuite(CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256, aes256, TlsHashAlgorithm.SHA256, TlsSignatureAlgorithm.Anonymous, TlsKeyExchange.DH_anon);
        }

        #region helpers
        public static bool IsBlock(this CipherSuite suite)
        {
            return suite.GetCipherAlgorithm() is BlockCipherAdapter;
        }
        public static bool IsAEAD(this CipherSuite suite)
        {
            return suite.GetCipherAlgorithm() is AEADCipherAdapter;
        }
        #endregion

        #region registration
        internal static void RegisterSuite(CipherSuite suite, Func<ICipher> cipher, TlsHashAlgorithm digest, TlsSignatureAlgorithm signature, TlsKeyExchange exchange)
        {
            Suites.Add(suite);

            CipherFactories.Add(suite, cipher);
            DigestMapping.Add(suite, digest);
            SignatureMapping.Add(suite, signature);
            KeyExchangeMapping.Add(suite, exchange);
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

        internal static void RegisterKeyExchange(TlsKeyExchange algo, Func<IKeyExchange> factory)
        {
            if (!KeyExchanges.Add(algo))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            KeyExchangeFactories.Add(algo, factory);
        }
        #endregion

        #region resolvers
        public static ICipher GetCipherAlgorithm(this CipherSuite suite)
        {
            return CipherFactories[suite]();
        }

        public static IDigest GetDigestAlgorithm(this CipherSuite suite)
        {
            return GetDigestAlgorithm(DigestMapping[suite]);
        }
        public static IDigest GetDigestAlgorithm(TlsHashAlgorithm algo)
        {
            return DigestFactories[algo]();
        }

        public static ISignatureCipher GetSignatureAlgorithm(this CipherSuite suite)
        {
            return GetSignatureAlgorithm(SignatureMapping[suite]);
        }
        public static ISignatureCipher GetSignatureAlgorithm(TlsSignatureAlgorithm algo)
        {
            return SignatureFactories[algo]();
        }

        public static IKeyExchange GetKeyExchange(this CipherSuite suite)
        {
            return KeyExchangeFactories[KeyExchangeMapping[suite]]();
        }
        #endregion

        public static IEnumerable<CipherSuite> GetSupportedCipherSuites()
        {
            return Suites;
        }

        public static bool IsSupported(TlsHashAlgorithm algo)
        {
            return HashAlgorithms.Contains(algo);
        }
        public static bool IsSupported(TlsSignatureAlgorithm algo)
        {
            return SignatureAlgorithms.Contains(algo);
        }
    }
}