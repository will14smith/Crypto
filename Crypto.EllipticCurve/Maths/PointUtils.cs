using System;
using System.Linq;
using Crypto.Utils;

namespace Crypto.EllipticCurve.Maths
{
    public class PointUtils
    {
        public static Point<T> FromBinary<T>(Curve<T> curve, byte[] b)
            where T : IFieldValue
        {
            SecurityAssert.NotNull(b);
            SecurityAssert.SAssert(b.Length > 1 && b.Length % 2 == 1);

            var type = b[0];
            // only support uncompressed points for now
            SecurityAssert.SAssert(type == 0x04);

            var len = (b.Length - 1) / 2;

            var x = curve.Field.Int(BigIntegerExtensions.FromTlsBytes(b.Skip(1).Take(len)));
            var y = curve.Field.Int(BigIntegerExtensions.FromTlsBytes(b.Skip(1 + len).Take(len)));

            var p = new Point<T>(x, y);
            SecurityAssert.SAssert(curve.IsPointOnCurve(p));

            return p;
        }
    }
}