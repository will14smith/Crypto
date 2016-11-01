using System;
using System.Collections;
using System.IO;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    public class RSAKeyReader : IPublicKeyReader
    {
        public PublicKey Read(X509AlgorithmIdentifier algorithm, BitArray bits)
        {
            SecurityAssert.SAssert(algorithm.Algorithm == WellKnownObjectIdentifiers.RSAEncryption);
            SecurityAssert.SAssert(algorithm.Parameters.Count == 1 && algorithm.Parameters[0] is ASN1Null);

            var data = bits.ToArray();

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
    }
}