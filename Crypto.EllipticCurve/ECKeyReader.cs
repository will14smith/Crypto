using System.Collections;
using System.IO;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.EllipticCurve.Algorithms;
using Crypto.EllipticCurve.Maths;
using Crypto.Utils;

namespace Crypto.EllipticCurve
{
    public class ECKeyReader : IPublicKeyReader
    {
        public PublicKey Read(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            SecurityAssert.SAssert(algorithm.Algorithm == ECExtensionConfiguration.IdEcPublicKey);
            SecurityAssert.SAssert(algorithm.Parameters.Count == 1);

            // not supporting implicitlyCA => OID or SEQ

            var parameter = algorithm.Parameters[0];
            Curve<PrimeFieldValue> curve;

            if (parameter is ASN1ObjectIdentifier)
            {
                curve = CurveFromNamed(parameter as ASN1ObjectIdentifier);
            }
            else if (parameter is ASN1Sequence)
            {
                curve = CurveFromParameters(parameter as ASN1Sequence);
            }
            else
            {
                SecurityAssert.SAssert(false);
                return null;
            }

            var data = bits.ToArray();
            var point = PointUtils.FromBinary(curve, data);

            return new ECPublicKey(point);
        }

        private Curve<PrimeFieldValue> CurveFromNamed(ASN1ObjectIdentifier oid)
        {
            throw new System.NotImplementedException();
        }

        private Curve<PrimeFieldValue> CurveFromParameters(ASN1Sequence seq)
        {
            SecurityAssert.SAssert(seq.Count == 5 || seq.Count == 6);

            var version = seq.Elements[0] as ASN1Integer;
            SecurityAssert.NotNull(version);
            SecurityAssert.SAssert(version.Value == 1);

            var fieldId = seq.Elements[1] as ASN1Sequence;
            SecurityAssert.NotNull(fieldId);
            SecurityAssert.SAssert(fieldId.Count == 2);

            var fieldType = fieldId.Elements[0] as ASN1ObjectIdentifier;
            SecurityAssert.NotNull(fieldType);
            // only support prime field at the moment
            SecurityAssert.SAssert(fieldType == new ASN1ObjectIdentifier("1.2.840.10045.1.1"));

            var prime = fieldId.Elements[1] as ASN1Integer;
            SecurityAssert.NotNull(prime);

            var curveSeq = seq.Elements[2] as ASN1Sequence;
            SecurityAssert.NotNull(curveSeq);
            SecurityAssert.SAssert(curveSeq.Count == 2 || curveSeq.Count == 3);

            var a = curveSeq.Elements[0] as ASN1OctetString;
            SecurityAssert.NotNull(a);
            var b = curveSeq.Elements[1] as ASN1OctetString;
            SecurityAssert.NotNull(b);

            // curve[2] == seed BIT STRING OPTIONAL

            // generator OCTET STRING
            // order INTEGER
            // cofactor INTEGER OPTIONAL

            var field = new PrimeField(prime.Value);

            var av = field.Int(BigIntegerExtensions.FromTlsBytes(a.Value));
            var bv = field.Int(BigIntegerExtensions.FromTlsBytes(b.Value));

            return new Curve<PrimeFieldValue>(field, av, bv);
        }
    }
}