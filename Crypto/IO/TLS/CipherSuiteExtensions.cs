﻿using System;
using Crypto.Encryption;
using Crypto.Encryption.AEAD;
using Crypto.Encryption.Block;
using Crypto.Encryption.Modes;
using Crypto.Hashing;

namespace Crypto.IO.TLS
{
    internal static class CipherSuiteExtensions
    {
        public static bool IsBlock(this CipherSuite suite)
        {
            return suite.GetCipher() is BlockCipherAdapter;
        }
        public static bool IsAEAD(this CipherSuite suite)
        {
            return suite.GetCipher() is AEADCipherAdapter;
        }

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
                    return new BlockCipherAdapter(new CBCBlockCipher(new ThreeDESCipher(ThreeDESKeyOptions.Option1)));

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
                    return new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(128)));

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
                    return new BlockCipherAdapter(new CBCBlockCipher(new AESCipher(256)));

                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
                    return new AEADCipherAdapter(new GCMCipher(new AESCipher(128)));

                case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
                    return new AEADCipherAdapter(new GCMCipher(new AESCipher(256)));

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static IDigest GetDigestAlgorithm(this CipherSuite suite)
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
                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
                    return new SHA256Digest();

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }

        public static IKeyExchange GetKeyExchange(this CipherSuite suite)
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
                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                    return new RSAKeyExchange();

                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
                    // DH_DSS
                    throw new NotImplementedException();

                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
                    // DH_RSA
                    return new DHKeyExchange(new RSAKeyExchange());

                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
                    // DHE_DSS
                    throw new NotImplementedException();

                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                    // DHE_RSA
                    return new DHEKeyExchange(new RSAKeyExchange());

                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
                    // DH_anon
                    throw new NotImplementedException();

                default:
                    throw new ArgumentOutOfRangeException(nameof(suite), suite, null);
            }
        }
    }
}
