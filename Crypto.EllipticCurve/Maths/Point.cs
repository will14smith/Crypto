using System;

namespace Crypto.EllipticCurve.Maths
{
    public class Point<TFieldValue>
        where TFieldValue : IFieldValue
    {
        public TFieldValue X { get; }
        public TFieldValue Y { get; }

        public Point(TFieldValue x, TFieldValue y)
        {
            X = x;
            Y = y;
        }

        public static Point<TFieldValue> Add(Curve<TFieldValue> curve, Point<TFieldValue> a, Point<TFieldValue> b)
        {
            if (a == null) { return b; }
            if (b == null) { return a; }

            var field = curve.Field;

            TFieldValue m;

            if (a == b)
            {
                var mt = field.Add(field.Multiply(field.Int(3), field.Multiply(a.X, a.X)), curve.A);
                var mb = field.Multiply(field.Int(2), a.Y);
                m = field.Divide(mt, mb);
            }
            else
            {
                var mt = field.Sub(a.Y, b.Y);
                var mb = field.Sub(a.X, b.X);
                m = field.Divide(mt, mb);
            }

            var x = field.Sub(field.Sub(field.Multiply(m, m), a.X), b.X);
            var y = field.Add(b.Y, field.Multiply(m, field.Sub(x, b.X)));

            return new Point<TFieldValue>(x, field.Negate(y));
        }

        public static Point<TFieldValue> Multiply(Curve<TFieldValue> curve, TFieldValue a, Point<TFieldValue> b)
        {
            var i = a.ToInt();

            if (i < 0)
            {
                throw new NotImplementedException();
            }

            Point<TFieldValue> result = null;

            while (i > 0)
            {
                if ((i & 1) == 1)
                {
                    result = Add(curve, result, b);
                }

                b = Add(curve, b, b);

                i >>= 1;
            }

            return result;
        }
    }
}