namespace Crypto.Certificates.Keys
{
    public abstract class PrivateKey
    {
        public abstract PublicKey PublicKey { get; }
        
        public override bool Equals(object obj)
        {
            var other = obj as PrivateKey;
            return other != null && Equals(other);
        }

        public override int GetHashCode()
        {
            return HashCode;
        }

        protected abstract bool Equal(PrivateKey key);
        protected abstract int HashCode { get; }
    }
}