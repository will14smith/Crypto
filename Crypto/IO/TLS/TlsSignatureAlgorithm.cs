namespace Crypto.IO.TLS
{
    public struct TlsSignatureAlgorithm
    {
        public static readonly TlsSignatureAlgorithm Anonymous = 0;
        public static readonly TlsSignatureAlgorithm RSA = 1;
        public static readonly TlsSignatureAlgorithm DSA = 2;

        public TlsSignatureAlgorithm(byte id)
        {
            Id = id;
        }

        public byte Id { get; }

        public override bool Equals(object obj)
        {
            var other = obj as TlsSignatureAlgorithm?;

            return Id == other?.Id;
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TlsSignatureAlgorithm(byte id)
        {
            return new TlsSignatureAlgorithm(id);
        }
    }
}