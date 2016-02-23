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
        private static readonly Dictionary<CipherSuite, Func<ICipher>> CipherFactories
            = new Dictionary<CipherSuite, Func<ICipher>>();
        private static readonly Dictionary<CipherSuite, Func<IDigest>> DigestFactories
            = new Dictionary<CipherSuite, Func<IDigest>>();
        private static readonly Dictionary<CipherSuite, Func<ISignatureCipher>> SignatureFactories
            = new Dictionary<CipherSuite, Func<ISignatureCipher>>();
        private static readonly Dictionary<CipherSuite, Func<IKeyExchange>> KeyExchangeFactories
            = new Dictionary<CipherSuite, Func<IKeyExchange>>();

        static CipherSuiteExtensions()
        {
            // ciphers
            RegisterCiphers(new[]
            {
                CipherSuite.TLS_NULL_WITH_NULL_NULL
                , CipherSuite.TLS_RSA_WITH_NULL_MD5
                , CipherSuite.TLS_RSA_WITH_NULL_SHA
                , CipherSuite.TLS_RSA_WITH_NULL_SHA256
            }, () => new NullCipher());

            RegisterCiphers(new[]
            {
                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5
            }, () => new RC4Cipher(128));

            RegisterCiphers(new[]
            {
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
            }, () => new BlockCipherAdapter(new CBCBlockCipher(new ThreeDESCipher(ThreeDESKeyOptions.Option1))));

            RegisterCiphers(new[]
            {
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256
            }, () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(128))));

            RegisterCiphers(new[]
            {
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256
            }, () => new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(256))));

            // digests
            RegisterDigests(new[]
            {
                CipherSuite.TLS_NULL_WITH_NULL_NULL
            }, () => new NullDigest());

            RegisterDigests(new[]
            {
                CipherSuite.TLS_RSA_WITH_NULL_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5
            }, () => new MD5Digest());

            RegisterDigests(new[]
            {
                CipherSuite.TLS_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA
            }, () => new SHA1Digest());

            RegisterDigests(new[]
            {
                CipherSuite.TLS_RSA_WITH_NULL_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
            }, () => new SHA256Digest());

            // signatures
            RegisterSignatures(new[]
            {
                CipherSuite.TLS_RSA_WITH_NULL_MD5,
                CipherSuite.TLS_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_WITH_NULL_SHA256,
                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            }, () => new RSA());

            RegisterSignatures(new[]
            {
                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
            }, () => { throw new NotImplementedException(); });

            // key exchanges
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_NULL_WITH_NULL_NULL
            }, () => new NullKeyExchange());

            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_RSA_WITH_NULL_MD5,
                CipherSuite.TLS_RSA_WITH_NULL_SHA,
                CipherSuite.TLS_RSA_WITH_NULL_SHA256,
                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
            }, () => new RSAKeyExchange());
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                // DH_DSS
            }, () => { throw new NotImplementedException(); });
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                // DH_RSA
            }, () => new DHKeyExchange(new RSAKeyExchange()));
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                // DHE_DSS
            }, () => { throw new NotImplementedException(); });
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                // DHE_RSA
            }, () => new DHEKeyExchange(new RSAKeyExchange()));
            RegisterKeyExchanges(new[]
            {
                CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5,
                CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                // DH_anon
            }, () => { throw new NotImplementedException(); });
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
        internal static void RegisterSuite(CipherSuite cipherSuite, Func<ICipher> cipher, Func<IDigest> digest,
            Func<ISignatureCipher> signature, Func<IKeyExchange> exchange)
        {
            RegisterCiphers(new[] { cipherSuite }, cipher);
            RegisterDigests(new[] { cipherSuite }, digest);
            RegisterSignatures(new[] { cipherSuite }, signature);
            RegisterKeyExchanges(new[] { cipherSuite }, exchange);
        }

        internal static void RegisterCiphers(CipherSuite[] cipherSuites, Func<ICipher> func)
        {
            foreach (var suite in cipherSuites)
            {
                CipherFactories.Add(suite, func);
            }
        }

        internal static void RegisterDigests(CipherSuite[] cipherSuites, Func<IDigest> func)
        {
            foreach (var suite in cipherSuites)
            {
                DigestFactories.Add(suite, func);
            }
        }

        internal static void RegisterSignatures(CipherSuite[] cipherSuites, Func<ISignatureCipher> func)
        {
            foreach (var suite in cipherSuites)
            {
                SignatureFactories.Add(suite, func);
            }
        }

        internal static void RegisterKeyExchanges(CipherSuite[] cipherSuites, Func<IKeyExchange> func)
        {
            foreach (var suite in cipherSuites)
            {
                KeyExchangeFactories.Add(suite, func);
            }
        }
        #endregion

        #region resolvers
        public static ICipher GetCipherAlgorithm(this CipherSuite suite)
        {
            return CipherFactories[suite]();
        }

        public static IDigest GetDigestAlgorithm(this CipherSuite suite)
        {
            return DigestFactories[suite]();
        }

        public static ISignatureCipher GetSignatureAlgorithm(this CipherSuite suite)
        {
            return SignatureFactories[suite]();
        }

        public static IKeyExchange GetKeyExchange(this CipherSuite suite)
        {
            return KeyExchangeFactories[suite]();
        }
        #endregion
    }
}