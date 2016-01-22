using System;
using System.IO;
using System.Linq;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.ASN1
{
    public class DERReader
    {
        private readonly EndianBinaryReader reader;

        public DERReader(Stream stream)
        {
            reader = new EndianBinaryReader(EndianBitConverter.Big, stream);
        }

        public ASN1Object Read()
        {
            throw new NotImplementedException();
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
