using System.Numerics;

namespace Crypto.EllipticCurve.Maths
{
    public interface IField<TFieldValue>
        where TFieldValue : IFieldValue
    {
        TFieldValue Int(BigInteger i);

        TFieldValue Negate(TFieldValue a);

        TFieldValue Add(TFieldValue a, TFieldValue b);
        TFieldValue Sub(TFieldValue a, TFieldValue b);
        TFieldValue Multiply(TFieldValue a, TFieldValue b);
        TFieldValue Divide(TFieldValue a, TFieldValue b);
    }
}