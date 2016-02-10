using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Hashing
{
    public class PRF
    {
        private readonly IDigest digest;

        public PRF(IDigest digest)
        {
            this.digest = digest;
        }

        public IEnumerable<byte> Digest(byte[] secret, string label, byte[] seed)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);

            var properSeed = new byte[labelBytes.Length + seed.Length];
            Array.Copy(labelBytes, 0, properSeed, 0, labelBytes.Length);
            Array.Copy(seed, 0, properSeed, labelBytes.Length, seed.Length);

            return P_hash(secret, properSeed);
        }

        private IEnumerable<byte> P_hash(byte[] secret, byte[] seed)
        {
            var hmac = new HMAC(digest, secret);

            var a = seed;

            while (true)
            {
                hmac.Reset();
                hmac.Update(a, 0, a.Length);
                a = hmac.Digest();

                hmac.Reset();
                hmac.Update(a, 0, a.Length);
                hmac.Update(seed, 0, seed.Length);

                var b = hmac.Digest();
                foreach (var x in b)
                {
                    yield return x;
                }
            }
        }
    }
}
