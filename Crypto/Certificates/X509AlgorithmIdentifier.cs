using System.Collections.Generic;
using System.Linq;
using Crypto.ASN1;

namespace Crypto.Certificates
{
    public class X509AlgorithmIdentifier
    {
        public X509AlgorithmIdentifier(ASN1ObjectIdentifier algorithm, IEnumerable<ASN1Object> parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters.ToList();
        }

        public ASN1ObjectIdentifier Algorithm { get; }
        public IReadOnlyList<ASN1Object> Parameters { get; }
    }
}