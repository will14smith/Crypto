using System.Collections.Generic;
using System.Linq;
using Crypto.ASN1;

namespace Crypto.Certificates
{
    public class X509AlgorithmIdentifier
    {
        public X509AlgorithmIdentifier(string algorithm, IEnumerable<ASN1Object> parameters)
        {
            Algorithm = algorithm;
            Parameters = parameters.ToList();
        }

        public string Algorithm { get; }
        public IReadOnlyList<ASN1Object> Parameters { get; }
    }
}