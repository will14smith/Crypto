using System;
using System.Security.Cryptography;
using Crypto.Encryption;
using Crypto.Encryption.Modes;
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
                    return new BlockModeCipher(new ThreeDESCipher(ThreeDESKeyOptions.Option1), new CBCBlockMode());

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
                    return new BlockModeCipher(new AESCipher(128), new CBCBlockMode());

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
                    return new BlockModeCipher(new AESCipher(256), new CBCBlockMode());

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static IDigest GetMACAlgorithm(this CipherSuite suite)
        {
            switch (suite)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                    return new NullDigest();

                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                    return new MD5Digest();

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
                    return new SHA1Digest();

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
                    return new SHA256Digest();

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static KeyExchange GetKeyExchange(this CipherSuite suite)
        {
            switch (suite)
            {
                case CipherSuite.TLS_NULL_WITH_NULL_NULL:
                    return new NullKeyExchange();

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
                    return new RSAKeyExchange();

                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                    // DH_DSS
                    throw new NotImplementedException();

                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                    // DH_RSA
                    throw new NotImplementedException();

                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                    // DHE_DSS
                    throw new NotImplementedException();

                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                    // DHE_RSA
                    return new DHEKeyExchange(new RSAKeyExchange());

                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
                    // DH_anon
                    throw new NotImplementedException();

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }
    }
}
