using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Crypto.ASN1;
using Crypto.IO;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public class X509Reader
    {
        private static readonly Regex HeaderRegex = new Regex("^-----BEGIN ([A-Z ]*)-----", RegexOptions.Compiled | RegexOptions.Multiline);
        private byte[] input;

        public X509Reader(byte[] input)
        {
            var strInput = Encoding.UTF8.GetString(input).Replace("\r", "").Replace("\n", "");
            var header = HeaderRegex.Match(strInput);
            if (header.Success)
            {
                var title = header.Groups[1].Value;
                var footer = $"-----END {title}-----";
                if (strInput.EndsWith(footer))
                {
                    input = Convert.FromBase64String(strInput
                        .Replace(header.Value, "")
                        .Replace(footer, ""));
                }
            }

            this.input = input;
        }

        // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf for reading the DER format
        // https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt for fields in certificate
        // https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for fields in private key (PKCS#1)
        // https://lapo.it/asn1js javascript parser / visualizer

        public X509Certificate ReadCertificate()
        {
            using (var ms = new MemoryStream())
            {
                var reader = new DERReader(ms);
                var asn1 = reader.Read();

                throw new NotImplementedException();
            }
        }
    }
}
