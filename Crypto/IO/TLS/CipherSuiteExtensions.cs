using System;
using System.Security.Cryptography;
using Crypto.Encryption;
using Crypto.Hashing;

namespace Crypto.IO.TLS
{
    internal static class CipherSuiteExtensions
    {
        public static ICipher GetCipher(this CipherSuite suite)
        {
            switch (suite)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                    return new NullCipher();

                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                    return new RC4Cipher(128);

                case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
                    return new ThreeDESCipher(ThreeDESKeyOptions.Option1, CipherBlockMode.CBC);

                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
                    return new AESCipher(128, CipherBlockMode.CBC);

                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
                    return new AESCipher(256, CipherBlockMode.CBC);

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static IMACAlgorithm GetMACAlgorithm(this CipherSuite suite)
        {
            switch (suite)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                    return new NullMACAlgorithm();

                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                    return new MD5MACAlgorithm();

                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
                    return new SHA1MACAlgorithm();

                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
                    return new SHA256MACAlgorithm();

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static KeyExchange GetKeyExchange(this CipherSuite suite)
        {
            switch (suite)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                    return KeyExchange.Null;

                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.RSA;

                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.DH_DSS;

                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.DH_RSA;

                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.DHE_DSS;

                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.DHE_RSA;

                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
                    return KeyExchange.DH_anon;

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }
    }
}
