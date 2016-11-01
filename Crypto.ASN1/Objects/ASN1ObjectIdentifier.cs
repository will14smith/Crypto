using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using Crypto.Utils;

namespace Crypto.ASN1
{
    public class ASN1ObjectIdentifier : ASN1Object, IEquatable<ASN1ObjectIdentifier>
    {
        public ASN1ObjectIdentifier(string identifier)
        {
            Identifier = identifier;
        }

        public string Identifier { get; }

        public override BigInteger ByteLength => GetBytes(Identifier).Length;

        internal override void Accept(IASN1ObjectWriter writer)
        {
            writer.Write(this);
        }

        public static string Format(byte[] bytes)
        {
            SecurityAssert.NotNull(bytes);
            SecurityAssert.SAssert(bytes.Length > 0);

            var oid = new StringBuilder();
            var firstOctet = bytes[0];
            var index = 1;

            oid.AppendFormat("{0}.{1}", firstOctet / 40, firstOctet % 40);

            while (index < bytes.Length)
            {
                var value = new BigInteger();

                while (true)
                {
                    var b = bytes[index++];

                    if ((b & 0x80) == 0)
                    {
                        value = value << 7 | b;
                        break;
                    }

                    if (index == bytes.Length)
                    {
                        SecurityAssert.SAssert(false);
                    }

                    value = value << 7 | (b & 0x7F);
                }

                oid.AppendFormat(".{0}", value);
            }

            return oid.ToString();
        }

        public static byte[] GetBytes(string oid)
        {
            SecurityAssert.NotNull(oid);
            SecurityAssert.SAssert(oid.Length > 0);

            var parts = oid.Split('.').Select(BigInteger.Parse).ToArray();
            SecurityAssert.SAssert(parts.Length >= 2);

            var bytes = new List<byte>();

            SecurityAssert.SAssert(parts[0] >= 0 && parts[0] <= 6);
            SecurityAssert.SAssert(parts[1] >= 0 && parts[1] < 40);

            var firstByte = parts[0] * 40 + parts[1];
            SecurityAssert.SAssert(firstByte < 256);
            bytes.Add((byte)firstByte);

            for (var i = 2; i < parts.Length; i++)
            {
                SecurityAssert.SAssert(parts[i] >= 0);

                bytes.AddRange(EncodeBase128(parts[i]).Reverse());
            }

            return bytes.ToArray();
        }

        /// <summary>
        /// encoding in LITTLE endian order
        /// </summary>
        private static IEnumerable<byte> EncodeBase128(BigInteger value)
        {
            SecurityAssert.SAssert(value >= 0);

            yield return (byte)(value & 0x7f);

            value = value >> 7;
            while (value > 0)
            {
                yield return (byte)((value & 0x7f) | 0x80);
                value = value >> 7;
            }
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((ASN1ObjectIdentifier)obj);
        }

        public bool Equals(ASN1ObjectIdentifier other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            if (Count != 0 || other.Count != 0)
            {
                throw new NotImplementedException();
            }

            return string.Equals(Identifier, other.Identifier);
        }

        public override int GetHashCode()
        {
            return Identifier?.GetHashCode() ?? 0;
        }

        public static bool operator ==(ASN1ObjectIdentifier left, ASN1ObjectIdentifier right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(ASN1ObjectIdentifier left, ASN1ObjectIdentifier right)
        {
            return !Equals(left, right);
        }
    }
}
