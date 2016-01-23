using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
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
            var id = reader.ReadByte();

            var tagClass = (ASN1Class)(id >> 6);
            var constructed = (id & 0x20) != 0;
            var tagNumber = id & 0x1F;

            switch (tagClass)
            {
                case ASN1Class.Universal:
                    return ReadUniversal(constructed, (ASN1UniversalTag)tagNumber);

                case ASN1Class.Context:
                    return ReadContext(constructed, (uint)tagNumber);

                default:
                    throw new NotImplementedException();
            }
        }

        private ASN1Object ReadContext(bool constructed, uint tag)
        {
            var length = ReadLength();

            if (!constructed)
            {
                return new ASN1TaggedPrimitive(tag, reader.ReadBytes((int)length));
            }

            var elems = ReadObjects(length);

            return new ASN1Tagged(tag, elems);
        }

        private uint ReadLength()
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
            return bytes.Aggregate(0u, (current, b) => (current << 8) | b);
        }

        private IEnumerable<ASN1Object> ReadObjects(uint length)
        {
            var startPosition = reader.BaseStream.Position;
            var endPosition = startPosition + length;

            var elems = new List<ASN1Object>();

            while (reader.BaseStream.Position < endPosition)
            {
                elems.Add(Read());
            }

            if (reader.BaseStream.Position > endPosition)
            {
                throw new InvalidOperationException("Read past end of sequence");
            }

            return elems;
        }

        #region universal

        private ASN1Object ReadUniversal(bool constructed, ASN1UniversalTag tag)
        {
            if (tag == ASN1UniversalTag.LongForm)
            {
                throw new NotImplementedException();
            }

            var length = ReadLength();

            // ignoring:
            // * 8.5 Encoding of a real value 
            
            if (!constructed)
            {
                switch (tag)
                {
                    case ASN1UniversalTag.Boolean:
                        return ReadBoolean(length);
                    case ASN1UniversalTag.Integer:
                    case ASN1UniversalTag.Enumerated:
                        return ReadInteger(length);
                    case ASN1UniversalTag.BitString:
                        return ReadPrimitiveBitString(length);
                    case ASN1UniversalTag.OctetString:
                        return ReadPrimitiveOctetString(length);
                    case ASN1UniversalTag.Null:
                        return new ASN1Null();
                    case ASN1UniversalTag.ObjectIdentifier:
                        return ReadObjectIdentifier(length);
                    case ASN1UniversalTag.UTF8String:
                        return ReadUTF8String(length);
                    case ASN1UniversalTag.UTCTime:
                        return ReadUTCTime(length);
                }
            }
            else
            {
                switch (tag)
                {
                    case ASN1UniversalTag.Sequence:
                        return ReadSequence(length);
                    case ASN1UniversalTag.Set:
                        return ReadSet(length);
                    case ASN1UniversalTag.UTCTime:
                        return ReadUTCTime(length);
                }
            }

            throw new NotImplementedException();
        }


        private ASN1Boolean ReadBoolean(uint length)
        {
            SecurityAssert.SAssert(length == 1);

            var value = reader.ReadByte();

            return new ASN1Boolean(value != 0);
        }

        private ASN1Integer ReadInteger(uint length)
        {
            var bytes = reader.ReadBytes((int)length);
            // convert to little endian
            Array.Reverse(bytes);

            var value = new BigInteger(bytes);

            return new ASN1Integer(value);
        }

        private ASN1BitString ReadPrimitiveBitString(uint length)
        {
            var unused = reader.ReadByte();
            var bytes = reader.ReadBytes((int)(length - 1));

            var value = new BitArray(bytes);
            value.Length -= unused;

            return new ASN1BitString(value);
        }

        private ASN1OctetString ReadPrimitiveOctetString(uint length)
        {
            var bytes = reader.ReadBytes((int)length);

            return new ASN1OctetString(bytes);
        }

        private ASN1Object ReadObjectIdentifier(uint length)
        {
            var bytes = reader.ReadBytes((int) length);
            
            return new ASN1ObjectIdentifier(ASN1ObjectIdentifier.Format(bytes));
        }

        private ASN1UTF8String ReadUTF8String(uint length)
        {
            var bytes = reader.ReadBytes((int)length);
            var value = Encoding.UTF8.GetString(bytes);

            return new ASN1UTF8String(value);
        }

        private ASN1Sequence ReadSequence(uint length)
        {
            var elems = ReadObjects(length);

            return new ASN1Sequence(elems);
        }
        private ASN1Set ReadSet(uint length)
        {
            var elems = ReadObjects(length);

            return new ASN1Set(elems);
        }

        private ASN1UTCTime ReadUTCTime(uint length)
        {
            SecurityAssert.SAssert(length == 13);

            var bytes = reader.ReadBytes((int)length);
            var str = Encoding.UTF8.GetString(bytes);

            SecurityAssert.SAssert(str.Length == 13);
            SecurityAssert.SAssert(str[12] == 'Z');

            var year = 2000 + int.Parse(str.Substring(0, 2));
            var month = int.Parse(str.Substring(2, 2));
            var day = int.Parse(str.Substring(4, 2));
            var hour = int.Parse(str.Substring(6, 2));
            var minute = int.Parse(str.Substring(8, 2));
            var second = int.Parse(str.Substring(10, 2));

            var value = new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);

            return new ASN1UTCTime(value);
        }

        #endregion
    }
}