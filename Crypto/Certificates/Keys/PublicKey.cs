using System.Collections;

namespace Crypto.Certificates.Keys
{
    public abstract class PublicKey
    {
        protected abstract int HashCode { get; }

        public override bool Equals(object obj)
        {
            var other = obj as PublicKey;
            return other != null && Equal(other);
        }

        public override int GetHashCode()
        {
            return HashCode;
        }

        protected abstract bool Equal(PublicKey key);
        public abstract byte[] GetBytes();
    }
}