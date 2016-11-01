using System;
using System.Collections;
using System.IO;

namespace Crypto.Utils
{
    public static class BitArrayExtensions
    {
        public static byte GetByte(this BitArray arr, int offset)
        {
            var endPoint = Math.Min(arr.Length, offset + 8);

            byte value = 0;
            var shift = 0;
            for (var i = offset; i < endPoint; i++)
            {
                value |= (byte)((arr[i] ? 1 : 0) << shift++);
            }

            return value;
        }

        public static byte[] GetBytes(this BitArray arr, int offset, int length)
        {
            SecurityAssert.SAssert(arr.Length + 7 > offset + length * 8);

            var buffer = new byte[length];

            for (var i = 0; i < length; i++)
            {
                buffer[i] = arr.GetByte(offset + i * 8);
            }

            return buffer;
        }

        public static byte[] ToArray(this BitArray arr)
        {
            var dataLength = (int)Math.Ceiling(arr.Length / 8m);

            return arr.GetBytes(0, dataLength);
        }
    }
}
