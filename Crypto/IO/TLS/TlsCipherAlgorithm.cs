using System;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// key exchanges aren't assigned numerical values.
    /// using GUIDs to identify them internally
    /// </summary>
    public struct TlsCipherAlgorithm
    {
        public static readonly TlsCipherAlgorithm Null = Guid.Empty;
        public static readonly TlsCipherAlgorithm RC4_128 = new Guid("bf158769-3e13-47fb-8ea8-6504e66416f9");
        public static readonly TlsCipherAlgorithm THREEDES_EDE_CBC = new Guid("1a465446-2f63-4fc7-9b29-1d28c1330312");
        public static readonly TlsCipherAlgorithm AES_128_CBC = new Guid("d8c56aa7-5bd4-42de-bde6-ebdc91233b6f");
        public static readonly TlsCipherAlgorithm AES_256_CBC = new Guid("d7379964-bad9-4574-b93c-9fac61831563");
        
        public TlsCipherAlgorithm(Guid id)
        {
            Id = id;
        }

        public Guid Id { get; }

        public override bool Equals(object obj)
        {
            if (!(obj is TlsCipherAlgorithm))
            {
                return false;
            }

            var other = (TlsCipherAlgorithm)obj;

            return Id == other.Id;
        }
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TlsCipherAlgorithm(Guid id)
        {
            return new TlsCipherAlgorithm(id);
        }

    }
}
