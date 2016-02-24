using System;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// key exchanges aren't assigned numerical values.
    /// using GUIDs to identify them internally
    /// </summary>
    public struct TlsKeyExchange
    {
        public static readonly TlsKeyExchange Null = Guid.Empty;
        public static readonly TlsKeyExchange RSA = new Guid("d0090317-fca1-4a7b-9bf5-c9821b0e144f");
        public static readonly TlsKeyExchange DH_DSS = new Guid("c4b7c6cd-0fed-4df4-afe0-871ccb745a45");
        public static readonly TlsKeyExchange DH_RSA = new Guid("0db39a14-54d2-422b-b6b5-974492ee1166");
        public static readonly TlsKeyExchange DHE_DSS = new Guid("9f63e60f-a949-470f-964b-991ac446955a");
        public static readonly TlsKeyExchange DHE_RSA = new Guid("2d8cdb3e-42bb-4db9-ac0e-713c723eeffc");
        public static readonly TlsKeyExchange DH_anon = new Guid("09087dcc-f2e6-43b8-9a6c-d3a071f006a2");

        public TlsKeyExchange(Guid id)
        {
            Id = id;
        }

        public Guid Id { get; }

        public override bool Equals(object obj)
        {
            if (!(obj is TlsKeyExchange))
            {
                return false;
            }

            var other = (TlsKeyExchange)obj;

            return Id == other.Id;
        }
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

        public static implicit operator TlsKeyExchange(Guid id)
        {
            return new TlsKeyExchange(id);
        }
    }
}
