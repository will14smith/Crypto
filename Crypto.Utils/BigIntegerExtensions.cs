using System.Collections.Generic;
using System.Numerics;
using System.Linq;

namespace Crypto.Utils
{
    public static class BigIntegerExtensions
    {
        public static int GetByteLength(this BigInteger val)
        {
            var bytes = val.ToByteArray();
            var length = bytes.Length;

            while (length > 1 && bytes[length - 1] == 0)
            {
                length--;
            }

            return length;
        }
        public static int GetBitLength(this BigInteger val)
        {
            var length = 0;

            do
            {
                length++;
            } while ((val >>= 1) != 0);

            return length;
        }

        public static byte[] ToTlsBytes(this BigInteger val)
        {
            var bytes = new List<byte>();

            while (val != 0)
            {
                bytes.Add((byte)(val % 256));

                val /= 256;
            }

            return bytes.AsEnumerable().Reverse().ToArray();
        }

        public static BigInteger FromTlsBytes(IEnumerable<byte> bytes)
        {
            return bytes.Aggregate(BigInteger.Zero, (current, b) => current * 256 + b);
        }

        public static BigInteger FromTlsHex(string hex)
        {
            return FromTlsBytes(HexConverter.FromHex(hex));
        }
    }
}
