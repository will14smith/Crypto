using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto.ASN1;
using Crypto.Certificates.Keys;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public class X509Reader
    {
        private readonly byte[] input;

        public X509Reader(byte[] input)
        {
            this.input = DERReadingHelper.TryConvertFromBase64(input).Item2;
        }

        // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf for reading the DER format
        // https://www.ietf.org/rfc/rfc5280.txt for fields in certificate
        // https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for fields in private key (PKCS#1)
        // https://lapo.it/asn1js javascript parser / visualizer

        public X509Certificate ReadCertificate()
        {
            using (var ms = new MemoryStream(input))
            {
                var reader = new DERReader(ms);
                var asn1 = reader.Read();

                return ReadFromASN1(asn1);
            }
        }

        private X509Certificate ReadFromASN1(ASN1Object asn1)
        {
            var root = ToSeq(asn1, 3, 3);

            // TBSCert
            var tbsCertSeq = ToSeq(GetElement(root, 0), 7, 10);

            var taggedVersion = GetElement<ASN1Tagged>(tbsCertSeq, 0);
            SecurityAssert.SAssert(taggedVersion.Tag == 0 && taggedVersion.Count == 1);
            var versionInt = GetElement<ASN1Integer>(taggedVersion, 0);
            SecurityAssert.SAssert(versionInt.Value >= 0 && versionInt.Value <= 2);
            var version = (byte)(versionInt.Value + 1);

            var serialNumber = GetElement<ASN1Integer>(tbsCertSeq, 1).Value;
            SecurityAssert.SAssert(serialNumber >= 0);

            var signatureAlgorithm = ReadAlgorithmIdentifer(GetElement(tbsCertSeq, 2));

            var issuer = ReadName(GetElement(tbsCertSeq, 3));

            var validitySeq = ToSeq(GetElement(tbsCertSeq, 4), 2, 2);
            var notBefore = GetElement(validitySeq, 0).GetTime();
            var notAfter = GetElement(validitySeq, 1).GetTime();
            var validity = new X509Validity(notBefore, notAfter);

            var subject = ReadName(GetElement(tbsCertSeq, 5));

            var subjectPublicKeyInfo = ToSeq(GetElement(tbsCertSeq, 6), 2, 2);
            var subjectPublicKeyAlgorithm = ReadAlgorithmIdentifer(GetElement(subjectPublicKeyInfo, 0));
            var subjectPublicKeyBits = GetElement<ASN1BitString>(subjectPublicKeyInfo, 1).Value;
            var subjectPublicKey = ReadPublicKey(subjectPublicKeyAlgorithm, subjectPublicKeyBits);

            var extensions = new List<X509Extension>();

            if (version >= 2)
            {
                //TODO issuerUniqueID  
                //TODO subjectUniqueID 
            }

            if (version >= 3)
            {
                var extensionsOffset = 7;
                while (true)
                {
                    if (extensionsOffset >= tbsCertSeq.Count) break;

                    var obj = GetElement(tbsCertSeq, extensionsOffset++);
                    var tagged = obj as ASN1Tagged;
                    if (tagged == null || tagged.Tag != 3)
                    {
                        continue;
                    }

                    SecurityAssert.SAssert(tagged.Count == 1);

                    var extensionsSeq = ToSeq(tagged.Elements[0]);
                    extensions = ReadExtensions(extensionsSeq);

                    break;
                }
            }

            // TODO check root[1] == signature

            // TODO read & store signature
            var signature = GetElement<ASN1BitString>(root, 2).Value;

            return new X509Certificate(version, serialNumber, validity, issuer, subject, subjectPublicKeyAlgorithm, subjectPublicKey, signatureAlgorithm, signature, extensions);
        }

        private X509AlgorithmIdentifier ReadAlgorithmIdentifer(ASN1Object asn1)
        {
            var seq = ToSeq(asn1, 1);

            var algorithmOid = GetElement<ASN1ObjectIdentifier>(seq, 0);
            var parameters = seq.Elements.Skip(1).ToList();

            return new X509AlgorithmIdentifier(algorithmOid.Identifier, parameters);
        }

        private X509Name ReadName(ASN1Object asn1)
        {
            var result = new Dictionary<string, ASN1Object>();

            var rdnSeq = ToSeq(asn1, 1);

            foreach (var rdn in rdnSeq.Elements)
            {
                var rdnSet = ToSet(rdn, 1);
                foreach (var attr in rdnSet.Elements)
                {
                    var attrSeq = ToSeq(attr, 2, 2);

                    var type = GetElement<ASN1ObjectIdentifier>(attrSeq, 0);
                    var value = GetElement(attrSeq, 1);

                    result.Add(type.Identifier, value);
                }
            }

            return new X509Name(result);
        }

        private PublicKey ReadPublicKey(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            // currently only supporting RSA
            SecurityAssert.SAssert(algorithm.Algorithm == WellKnownObjectIdentifiers.RSAEncryption);
            SecurityAssert.SAssert(algorithm.Parameters.Count == 1 && algorithm.Parameters[0] is ASN1Null);

            var dataLength = (int)Math.Ceiling(bits.Length / 8m);
            var data = bits.GetBytes(0, dataLength);

            ASN1Object asn1;
            using (var ms = new MemoryStream(data))
            {
                asn1 = new DERReader(ms).Read();
            }

            var keySeq = asn1 as ASN1Sequence;
            SecurityAssert.SAssert(keySeq != null && keySeq.Count == 2);

            var modulusInt = keySeq.Elements[0] as ASN1Integer;
            SecurityAssert.SAssert(modulusInt != null);
            var exponentInt = keySeq.Elements[1] as ASN1Integer;
            SecurityAssert.SAssert(exponentInt != null);

            return new RSAPublicKey(modulusInt.Value, exponentInt.Value);
        }

        private List<X509Extension> ReadExtensions(ASN1Sequence seq)
        {
            var extensions = new List<X509Extension>();

            foreach (var extInfo in seq.Elements)
            {
                var extSeq = ToSeq(extInfo, 2, 3);

                var id = GetElement<ASN1ObjectIdentifier>(extSeq, 0).Identifier;
                var critical = extSeq.Count == 3 && GetElement<ASN1Boolean>(extSeq, 1).Value;
                var value = GetElement<ASN1OctetString>(extSeq, extInfo.Count - 1).Value;
                ASN1Object asn1Value;
                using (var ms = new MemoryStream(value))
                {
                    asn1Value = new DERReader(ms).Read();
                }

                extensions.Add(new X509Extension(id, critical, asn1Value));
            }

            return extensions;
        }

        // helpers
        private ASN1Sequence ToSeq(ASN1Object asn1, int minLength = 0, int maxLength = int.MaxValue)
        {
            var seq = asn1 as ASN1Sequence;

            SecurityAssert.NotNull(seq);
            SecurityAssert.SAssert(seq.Count >= minLength && seq.Count <= maxLength);

            return seq;
        }
        private ASN1Set ToSet(ASN1Object asn1, int minLength = 0, int maxLength = int.MaxValue)
        {
            var seq = asn1 as ASN1Set;

            SecurityAssert.NotNull(seq);
            SecurityAssert.SAssert(seq.Count >= minLength && seq.Count <= maxLength);

            return seq;
        }

        private ASN1Object GetElement(ASN1Object asn1, int index)
        {
            SecurityAssert.SAssert(index >= 0 && index < asn1.Count);

            return asn1.Elements[index];
        }
        private T GetElement<T>(ASN1Object asn1, int index)
            where T : ASN1Object
        {
            var obj = GetElement(asn1, index) as T;
            SecurityAssert.NotNull(obj);

            return obj;
        }
    }
}
