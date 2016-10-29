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
    }
}
