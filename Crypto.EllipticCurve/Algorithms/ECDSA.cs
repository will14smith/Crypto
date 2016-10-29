using System;
using System.IO;
using System.Numerics;
using Crypto.ASN1;
using Crypto.EllipticCurve.Maths;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.EllipticCurve.Algorithms
{
    public class ECDSA : ISignatureCipher
    {
        private int ln;
        private PrimeField nField;

        private PrimeDomainParameters domain;
        private Point<PrimeFieldValue> publicKey;
        private BigInteger? privateKey;



        public void Init(ICipherParameters parameters)
        {
            var ecParams = parameters as ECCipherParameters;
            if (ecParams == null)
            {
                throw new InvalidCastException("Expecting parameters of type ECCipherParameters");
            }

            domain = ecParams.Domain;
            publicKey = ecParams.PublicKey.Point;
            privateKey = ecParams.PrivateKey?.Key;

            ln = domain.Order.GetBitLength();
            nField = new PrimeField(domain.Order);
        }

        public byte[] Sign(byte[] input, IDigest hash)
        {
            if (!privateKey.HasValue)
            {
                throw new InvalidOperationException("ECDSA not initialised with private key");
            }

            // e = HASH(input)
            hash.Update(input, 0, input.Length);
            var e = hash.Digest();

            // z = the Ln leftmost bits of e, where Ln is the bit length of the group order n.
            var z = ToZ(e, ln).Value;

            // k = rand(1, n-1) <-- step 3
            var k = domain.Curve.Field.Int(RandomGenerator.Random(domain.Order - 1));

            // (x1, y1) = k * G
            var c = Point<PrimeFieldValue>.Multiply(domain.Curve, k, domain.Generator);

            // r = x1 % n
            var r = nField.Int(c.X.ToInt()).ToInt();

            // if r == 0 go to step 3
            if (r == 0)
            {
                throw new NotImplementedException();
            }

            // s = (1/k)(z + rdA) mod n
            var kInv = nField.Divide(nField.Int(1), k);
            var s = nField.Multiply(kInv, nField.Int(z + r * privateKey.Value)).ToInt();

            // if s == 0 go to step 3
            if (s == 0)
            {
                throw new NotImplementedException();
            }

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

        private PrimeFieldValue ToZ(byte[] bytes, int i)
        {
            if (i / 8 != bytes.Length)
            {
                throw new NotImplementedException();
            }

            return domain.Field.Int(BigIntegerExtensions.FromTlsBytes(bytes));
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            PrimeFieldValue r, s;

            using (var buffer = new MemoryStream(signature))
            {
                var reader = new DERReader(buffer);

                var seq = reader.Read() as ASN1Sequence;
                SecurityAssert.NotNull(seq);
                SecurityAssert.SAssert(seq.Count == 2);

                var ri = seq.Elements[0] as ASN1Integer;
                SecurityAssert.NotNull(ri);
                r = nField.Int(ri.Value);
                SecurityAssert.SAssert(r.Value == ri.Value);

                var si = seq.Elements[1] as ASN1Integer;
                SecurityAssert.NotNull(si);
                s = nField.Int(si.Value);
                SecurityAssert.SAssert(s.Value == si.Value);
            }

            // check QA != O
            // check QA is on curve
            SecurityAssert.SAssert(domain.Curve.IsPointOnCurve(publicKey));
            // check n*QA = O
            // check r and s are in [1, n-1]

            // e = HASH(input)
            hash.Update(input, 0, input.Length);
            var e = hash.Digest();

            // z = the Ln leftmost bits of e, where Ln is the bit length of the group order n.
            var z = ToZ(e, ln);

            // w = 1/s (mod n)
            var w = nField.Divide(nField.Int(1), s);

            // u1 = zw (mod n)
            var u1 = nField.Multiply(w, z);

            // u2 = rw (mod n)
            var u2 = nField.Multiply(w, r);

            // (x1, y2) = u1 * G + u2 * QA
            var point = Point<PrimeFieldValue>.Add(domain.Curve,
                    a: Point<PrimeFieldValue>.Multiply(domain.Curve, u1, domain.Generator),
                    b: Point<PrimeFieldValue>.Multiply(domain.Curve, u2, publicKey));

            // return r == x1 (mod n)
            return r == point.X;
        }
    }
}
