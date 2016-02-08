using System;

namespace Crypto
{
    public class RandomGenerator
    {
        public static int Random()
        {
            return new Random().Next();
        }
        public static int Random(int min, int max)
        {
            return new Random().Next(min, max);
        }

        public static byte[] RandomBytes(int length)
        {
            var bytes = new byte[length];

            new Random().NextBytes(bytes);

            return bytes;
        }

        public static byte[] RandomNonZeroBytes(int length)
        {
            var bytes = new byte[length];

            for (var i = 0; i < length; i++)
            {
                bytes[i] = (byte)Random(1, 255);
            }

            return bytes;
        }
    }
}
