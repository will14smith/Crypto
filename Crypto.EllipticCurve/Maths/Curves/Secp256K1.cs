using System.Numerics;
using Crypto.Utils;

namespace Crypto.EllipticCurve.Maths.Curves
{
    public class Secp256K1
    {
        public static PrimeDomainParameters Parameters;

        static Secp256K1()
        {
            var prime = BigIntegerExtensions.FromTlsHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
            var field = new PrimeField(prime);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(0), field.Int(7));

            Parameters = new PrimeDomainParameters(
                p: prime,
                a: curve.A.Value,
                b: curve.B.Value,
                g: PointUtils.FromBinary(curve, HexConverter.FromHex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")),
                n: BigIntegerExtensions.FromTlsHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
                h: 1);
        }
    }
}
