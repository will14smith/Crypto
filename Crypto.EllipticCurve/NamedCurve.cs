using System;
using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.EllipticCurve.Maths;
using Crypto.EllipticCurve.Maths.Curves;

namespace Crypto.EllipticCurve
{
    public static class NamedCurves
    {
        private static readonly Dictionary<NamedCurve, Func<PrimeDomainParameters>> CurvesByEnum = new Dictionary<NamedCurve, Func<PrimeDomainParameters>>();
        private static readonly Dictionary<ASN1ObjectIdentifier, Func<PrimeDomainParameters>> CurvesByOID = new Dictionary<ASN1ObjectIdentifier, Func<PrimeDomainParameters>>();

        static NamedCurves()
        {
            Register(NamedCurve.secp256k1, new ASN1ObjectIdentifier("1.3.132.0.10"), () => Secp256K1.Parameters);
        }

        public static void Register(NamedCurve name, ASN1ObjectIdentifier oid, Func<PrimeDomainParameters> func)
        {
            CurvesByEnum.Add(name, func);
            CurvesByOID.Add(oid, func);
        }

        public static PrimeDomainParameters Get(NamedCurve curve)
        {
            return CurvesByEnum[curve]();
        }
        public static PrimeDomainParameters Get(ASN1ObjectIdentifier curve)
        {
            return CurvesByOID[curve]();
        }
    }

    public enum NamedCurve
    {
        sect163k1 = 1,
        sect163r1 = 2,
        sect163r2 = 3,

        sect193r1 = 4,
        sect193r2 = 5,
        sect233k1 = 6,

        sect233r1 = 7,
        sect239k1 = 8,
        sect283k1 = 9,

        sect283r1 = 10,
        sect409k1 = 11,
        sect409r1 = 12,

        sect571k1 = 13,
        sect571r1 = 14,
        secp160k1 = 15,

        secp160r1 = 16,
        secp160r2 = 17,
        secp192k1 = 18,

        secp192r1 = 19,
        secp224k1 = 20,
        secp224r1 = 21,

        secp256k1 = 22,
        secp256r1 = 23,
        secp384r1 = 24,

        secp521r1 = 25,

        arbitrary_explicit_prime_curves = 0xFF01,
        arbitrary_explicit_char2_curves = 0xFF02,
    }
}
