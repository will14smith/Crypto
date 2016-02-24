namespace Crypto.IO.TLS
{
    public struct TlsHashAlgorithm
    {
        public static readonly TlsHashAlgorithm None = 0;
        public static readonly TlsHashAlgorithm MD5 = 1;
        public static readonly TlsHashAlgorithm SHA1 = 2;
        public static readonly TlsHashAlgorithm SHA224 = 3;
        public static readonly TlsHashAlgorithm SHA256 = 4;
        public static readonly TlsHashAlgorithm SHA384 = 5;
        public static readonly TlsHashAlgorithm SHA512 = 6;

        public TlsHashAlgorithm(byte id)
        {
            Id = id;
        }

        public byte Id { get; }

        public override bool Equals(object obj)
        {
            var other = obj as TlsHashAlgorithm?;

            return Id == other?.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TlsHashAlgorithm(byte id)
        {
            return new TlsHashAlgorithm(id);
        }
    }
}
