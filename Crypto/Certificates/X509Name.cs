using System.Collections.Generic;
using System.Linq;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public class X509Name
    {
        internal readonly IReadOnlyDictionary<string, ASN1Object> Values;

        public X509Name(IDictionary<string, ASN1Object> values)
        {
            Values = values.ToDictionary(x => x.Key, x => x.Value);
        }

        public ASN1Object Get(string oid, bool throwOnMissing = true)
        {
            ASN1Object result;
            if (Values.TryGetValue(oid, out result))
            {
                return result;
            }

            if (throwOnMissing)
            {
                SecurityAssert.SAssert(false);
            }

            return null;
        }

        public string CommonName => Get(CommonObjectIdentifiers.CommonName).FromDirectoryString();
        public string SerialNumber => Get(CommonObjectIdentifiers.SerialNumber).FromPrintableString();
        public string CountryName => Get(CommonObjectIdentifiers.CountryName).FromPrintableString();
        public string StateOrProvinceName => Get(CommonObjectIdentifiers.StateOrProvinceName).FromDirectoryString();
        public string OrganizationName => Get(CommonObjectIdentifiers.OrganizationName).FromDirectoryString();
        public string OrganizationUnitName => Get(CommonObjectIdentifiers.OrganizationUnitName).FromDirectoryString();
    }

    public static class CommonObjectIdentifiers
    {
        public static readonly string CommonName = "2.5.4.3";
        public static readonly string SerialNumber = "2.5.4.5";
        public static readonly string CountryName = "2.5.4.6";
        public static readonly string StateOrProvinceName = "2.5.4.8";
        public static readonly string OrganizationName = "2.5.4.10";
        public static readonly string OrganizationUnitName = "2.5.4.11";
    }
}