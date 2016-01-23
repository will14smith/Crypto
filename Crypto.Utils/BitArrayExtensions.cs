using System;
using System.Collections;

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
    }
}
