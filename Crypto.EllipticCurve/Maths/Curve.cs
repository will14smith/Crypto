using System;

namespace Crypto.EllipticCurve.Maths
{
    public class Curve<TFieldValue>
        where TFieldValue : IFieldValue
    {
        public IField<TFieldValue> Field { get; }

        public TFieldValue A { get; }
        public TFieldValue B { get; }

        public Curve(IField<TFieldValue> field, TFieldValue a, TFieldValue b)
        {
            Field = field;

            A = a;
            B = b;
        }

        public override string ToString()
        {
            return $"y^2 = x^3 + {A}x + {B}";
        }

        public bool IsPointOnCurve(Point<TFieldValue> point)
        {
            var x = point.X;
            var y = point.Y;

            var lhs = Field.Multiply(y, y);
            var rhs = Field.Add(Field.Add(Field.Multiply(Field.Multiply(x, x), x), Field.Multiply(A, x)), B);

            return Equals(lhs, rhs);
        }
    }
}
