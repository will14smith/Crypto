using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.ASN1;
using Crypto.EllipticCurve.Maths;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;

namespace Crypto.EllipticCurve.Algorithms
{
    class ECDSA : ISignatureCipher
    {
        private BigInteger dA;
        private BigInteger n;
        private int ln;
        private Point<RealValue> G;
        private Curve<RealValue> curve;

        public void Init(ICipherParameters parameters)
        {
            // TODO 
            n = BigInteger.Zero;
            ln = 0;

            throw new NotImplementedException();
        }

        public byte[] Sign(byte[] input, IDigest hash)
        {
            // e = HASH(input)
            hash.Update(input, 0, input.Length);
            var e = hash.Digest();

            // z = the Ln leftmost bits of e, where Ln is the bit length of the group order n.
            var z = ToZ(e, ln);

            // k = rand(1, n-1)
            var k = RandomGenerator.Random(n);

            // (x1, y1) = k * G
            var c = Point<RealValue>.Multiply(curve, k, G);

            // r = x1 % n
            var r = BigInteger.Remainder(c.X.ToInt(), n);

            // if r == 0 go to step 3
            // TODO

            // s = (1/k)(z + rdA) mod n
            var s = BigInteger.Remainder((1 / k) * (z + r * dA), n);

            // if s == 0 go to step 3
            // TODO

            // return ASN1 SEQUENCE [r INTEGER, s INTEGER]
            using (var buffer = new MemoryStream())
            {
                var derWriter = new DERWriter(buffer);

                derWriter.Write(new ASN1Sequence(new[]
                {
                    new ASN1Integer(r),
                    new ASN1Integer(s),
                }));

                return buffer.ToArray();
            }
        }

        private BigInteger ToZ(byte[] bytes, int i)
        {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            // check QA != O
            // check QA is on curve
            // check n*QA = O

            // check r and s are in [1, n-1]
            // e = HASH(input)
            // z = the Ln leftmost bits of e.#
            // w = 1/s (mod n)
            // u1 = zw (mod n)
            // u2 = rw (mod n)
            // (x1, y2) = u1 * G + u2 * QA
            // return r == x1 (mod n)

            throw new NotImplementedException();
        }
    }
}
