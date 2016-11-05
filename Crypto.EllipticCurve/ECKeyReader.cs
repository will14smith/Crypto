using System;
using System.Collections;
using System.IO;
using System.Linq;
using Crypto.ASN1;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.EllipticCurve.Algorithms;
using Crypto.EllipticCurve.Maths;
using Crypto.Utils;

namespace Crypto.EllipticCurve
{
    public class ECKeyReader : IPublicKeyReader, IPrivateKeyReader
    {
        public PublicKey Read(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            SecurityAssert.SAssert(algorithm.Algorithm == ECExtensionConfiguration.IdEcPublicKey);
            SecurityAssert.SAssert(algorithm.Parameters.Count == 1);

            // not supporting implicitlyCA => OID or SEQ

            var parameters = CurveFromASN(algorithm.Parameters[0]);

            var data = bits.ToArray();
            var point = PointUtils.FromBinary(parameters.Curve, data);

            return new ECPublicKey(point);
        }

        private PrimeDomainParameters CurveFromASN(ASN1Object parameter)
        {
            if (parameter is ASN1Tagged)
            {
                var tagged = (ASN1Tagged)parameter;
                SecurityAssert.SAssert(tagged.Count == 1);

                return CurveFromASN(tagged.Elements[0]);
            }

            if (parameter is ASN1ObjectIdentifier)
            {
                return CurveFromNamed(parameter as ASN1ObjectIdentifier);
            }

            if (parameter is ASN1Sequence)
            {
                return CurveFromParameters(parameter as ASN1Sequence);
            }

            SecurityAssert.SAssert(false);
            return null;
        }

        private PrimeDomainParameters CurveFromNamed(ASN1ObjectIdentifier oid)
        {
            return NamedCurves.Get(oid);

            throw new System.NotImplementedException();
        }

        private PrimeDomainParameters CurveFromParameters(ASN1Sequence seq)
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

            var av = BigIntegerExtensions.FromTlsBytes(a.Value);
            var bv = BigIntegerExtensions.FromTlsBytes(b.Value);

            var field = new PrimeField(prime.Value);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(av), field.Int(bv));

            // generator OCTET STRING
            var gbin = seq.Elements[3] as ASN1OctetString;
            SecurityAssert.NotNull(gbin);
            SecurityAssert.SAssert(gbin.Count > 1 && (gbin.Count % 2 == 1));

            var g = PointUtils.FromBinary(curve, gbin.Value);

            // order INTEGER
            var n = seq.Elements[4] as ASN1Integer;
            SecurityAssert.NotNull(n);

            // cofactor INTEGER OPTIONAL
            
            return new PrimeDomainParameters(
                prime.Value,
                av,
                bv,
                g,
                n.Value);
        }

        public Option<PrivateKey> TryRead(byte[] input)
        {
            var pems = PEMReader.TryConvertFromBase64(input);

            var keyPem = pems.SingleOrDefault(x => x.Name == "EC PRIVATE KEY");
            if (keyPem == null)
            {
                return Option.None<PrivateKey>();
            }

            ASN1Object asn1;
            using (var ms = new MemoryStream(keyPem.RawData))
            {
                asn1 = new DERReader(ms).Read();
            }

            SecurityAssert.SAssert(asn1 is ASN1Sequence && asn1.Count >= 2 && asn1.Count <= 4);

            var version = asn1.Elements[0] as ASN1Integer;
            SecurityAssert.SAssert(version != null && version.Value == 1);

            var privateKey = asn1.Elements[1] as ASN1OctetString;
            SecurityAssert.NotNull(privateKey);

            var key = BigIntegerExtensions.FromTlsBytes(privateKey.Value);

            // TODO
            var ecParams = CurveFromASN(asn1.Elements[2]);
            var pubPoint = asn1.Elements[3] as ASN1BitString;

            var pubKey = new ECPublicKey(new Point<PrimeFieldValue>(new PrimeFieldValue(0), new PrimeFieldValue(0)));

            return Option.Some<PrivateKey>(new ECPrivateKey(key, pubKey));
        }
    }
}