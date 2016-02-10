using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Crypto.Utils;

namespace Crypto
{
    public class RandomGenerator
    {
        private static List<int> smallPrimes;

        static RandomGenerator()
        {
            smallPrimes = SievePrimes(1000000);

        }

        public static int Random()
        {
            return new Random().Next();
        }
        public static int Random(int min, int max)
        {
            return new Random().Next(min, max);
        }
        public static BigInteger Random(BigInteger max)
        {
            var bits = (int)Math.Ceiling(BigInteger.Log(max, 2) / 8) * 8;

            BigInteger val;
            do
            {
                val = RandomBig(bits);
            } while (val > max);

            return val;
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

        public static BigInteger RandomBig(int bits)
        {
            SecurityAssert.SAssert(bits > 0 && bits % 8 == 0);
            var value = RandomBytes(bits / 8);

            // make sure it is positive
            if ((value[value.Length - 1] & 0x80) != 0)
            {
                Array.Resize(ref value, value.Length + 1);
            }

            return new BigInteger(value);
        }

        public static BigInteger RandomPrime(int bits)
        {
            SecurityAssert.SAssert(bits > 2);

            BigInteger value;
            do
            {
                value = RandomBig(bits);
                // make sure it is odd
                value |= 1;

                // k = 50, P(not prime) = 2^-100
            } while (!IsProbablyPrime(value, 50));

            return value;
        }

        private static List<int> SievePrimes(int max)
        {
            SecurityAssert.SAssert(max > 1);

            var maxSqrt = (int)Math.Ceiling(Math.Sqrt(max));
            var a = new BitArray(max + 1, true);

            for (var i = 2; i < maxSqrt; i++)
            {
                if (a[i])
                {
                    var j = i * i;
                    while (j <= max)
                    {
                        a[j] = false;
                        j += i;
                    }
                }
            }

            var list = new List<int>();

            for (var i = 2; i <= max; i++)
            {
                if (a[i])
                {
                    list.Add(i);
                }
            }

            return list;
        }

        private static bool IsProbablyPrime(BigInteger n, int k)
        {
            // preselection using small primes
            if (smallPrimes.Any(p => n % p == 0))
            {
                return false;
            }

            // n - 1 = 2^r * d;
            var r = 0;
            var d = n - 1;
            while (d % 2 == 0)
            {
                r++;
                d /= 2;
            }

            for (var i = 0; i < k; i++)
            {
                // a = random [2, n-2]
                var a = Random(n - 4) + 2;

                var x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1) { continue; }

                for (var j = 1; j < r; j++)
                {
                    x = BigInteger.ModPow(x, 2, n);

                    if (x == 1)
                    {
                        return false;
                    }

                    if (x == n - 1)
                    {
                        break;
                    }
                }

                if (x != n - 1)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
