using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Crypto.Utils;

namespace Crypto.Certificates
{
    public static class PEMReader
    {
        private static readonly Regex HeaderRegex = new Regex(@"\G-----BEGIN ([A-Z ]*)-----", RegexOptions.Compiled | RegexOptions.Multiline);

        public static IReadOnlyList<PEMData> TryConvertFromBase64(byte[] input)
        {
            var result = new List<PEMData>();
            var str = Encoding.UTF8.GetString(input).Replace("\r", "").Replace("\n", "");

            var idx = 0;
            while (idx < str.Length)
            {
                var pemResult = TryReadPEM(str, idx);
                if (!pemResult.HasValue)
                {
                    return new PEMData[0];
                }

                if (idx == pemResult.Value.Item2)
                {
                    return new PEMData[0];
                }

                result.Add(pemResult.Value.Item1);
                idx = pemResult.Value.Item2;
            }

            return result;
        }

        private static Option<Tuple<PEMData, int>> TryReadPEM(string input, int offset = 0)
        {
            var header = HeaderRegex.Match(input, offset);
            if (!header.Success)
            {
                return Option.None<Tuple<PEMData, int>>();
            }

            var dataStartIndex = offset + header.Length;


            var title = header.Groups[1].Value;
            var footer = $"-----END {title}-----";
            var footerIndex = input.IndexOf(footer, dataStartIndex, StringComparison.Ordinal);

            if (footerIndex < 0)
            {
                return Option.None<Tuple<PEMData, int>>();
            }

            var dataStr = input.Substring(dataStartIndex, footerIndex - dataStartIndex);
            var data = Convert.FromBase64String(dataStr);

            var pemData = new PEMData(title, data);
            var endIndex = footerIndex + footer.Length;

            return Option.Some(Tuple.Create(pemData, endIndex));
        }
    }

    public class PEMData
    {
        public PEMData(string name, byte[] rawData)
        {
            Name = name;
            RawData = rawData;
        }

        public string Name { get; }
        public byte[] RawData { get; }
    }
}
