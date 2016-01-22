using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Crypto.IO;
using Crypto.Utils;

namespace Crypto.Certificates
{
    class X509Reader
    {
        private static readonly Regex HeaderRegex = new Regex("^-----BEGIN ([A-Z ]*)-----", RegexOptions.Compiled | RegexOptions.Multiline);

        private readonly MemoryStream input;
        private readonly EndianBinaryReader reader;

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

            this.input = new MemoryStream(input);
            reader = new EndianBinaryReader(EndianBitConverter.Big, this.input);
        }

        // http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf for reading the DER format
        // https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt for what fields to read
        // https://lapo.it/asn1js javascript parser / visualizer

        public void Read()
        {
            var id = reader.ReadByte();
            var tagClass = (ASN1Class)(id >> 6);
            var primitive = (id & 0x20) == 0;
            var tagNumber = (ASN1UniversalTag)(id & 0x1F);

            var length = ReadLength();
        }

        private int ReadLength()
        {
            var initial = reader.ReadByte();
            if (initial == 0x80)
            {
                throw new NotSupportedException("Indefinite length isn't supported in DER");
            }

            if (initial < 0x80)
            {
                return initial;
            }

            var count = initial & 0x7F;
            var bytes = reader.ReadBytes(count);

            // in big endian order
            return bytes.Aggregate(0, (current, b) => (current << 8) | b);
        }
    }
}
