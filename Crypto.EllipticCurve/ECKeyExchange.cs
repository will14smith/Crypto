using System;
using Crypto.IO.TLS;

namespace Crypto.EllipticCurve
{
    public static class ECKeyExchange
    {
        public static readonly TlsKeyExchange ECDH_ECDSA = new Guid("24626f9e-a1ab-4c82-a451-0ce5d037f95b");
        public static readonly TlsKeyExchange ECDHE_ECDSA = new Guid("ee1d80cb-b0aa-43e2-a7ab-aa101526e772");
        public static readonly TlsKeyExchange ECDH_RSA = new Guid("38625bef-1dea-4634-a474-9c8d82f5b7a3");
        public static readonly TlsKeyExchange ECDHE_RSA = new Guid("795e147f-5a41-4059-8b3f-e7a56884abb2");
        public static readonly TlsKeyExchange ECDH_anon = new Guid("b5181359-5681-45f5-8dcf-d4cbe41028c9");
    }
}
