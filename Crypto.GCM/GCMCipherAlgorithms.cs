using System;
using Crypto.IO.TLS;

namespace Crypto.GCM
{
    public static class GCMCipherAlgorithms
    {
        public static readonly TlsCipherAlgorithm AES_128_GCM = new Guid("b1c19d95-0267-483a-9f82-677084dfb1a0");
        public static readonly TlsCipherAlgorithm AES_256_GCM = new Guid("853b3628-b0b9-4f50-80bd-768179cd17d3");
    }
}
