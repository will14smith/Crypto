using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.EllipticCurve.Maths
{
    public class PrimeDomainParameters
    {
        public PrimeField Field { get; }
        public Curve<PrimeFieldValue> Curve { get; }

        public Point<PrimeFieldValue> Generator { get; set; }
        public BigInteger Order { get; set; }
        public BigInteger Cofactor { get; set; }


        public PrimeDomainParameters(BigInteger p, BigInteger a, BigInteger b, Point<PrimeFieldValue> g, BigInteger n, BigInteger h)
        {
            Field = new PrimeField(p);
            Curve = new Curve<PrimeFieldValue>(Field, Field.Int(a), Field.Int(b));

            Generator = g;
            Order = n;
            Cofactor = h;
        }
    }
}
