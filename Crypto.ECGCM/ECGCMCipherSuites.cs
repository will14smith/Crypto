﻿namespace Crypto.ECGCM
{
    public enum ECGCMCipherSuites : ushort
    {
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D,
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031,
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032,
    }
}
