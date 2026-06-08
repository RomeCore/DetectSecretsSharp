using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for public IPv4 addresses, excluding private/reserved ranges.
    /// </summary>
    public class IpPublicDetector : RegexBasedDetector
    {
        public override string SecretType => "Public IP (ipv4)";

        private static readonly Regex PublicIpRegex = new Regex(
            @"(?<![\w.])" +
            @"(" +
            @"(?!192\.168\.|127\.|10\.|169\.254\.|172\.(?:1[6-9]|2[0-9]|3[01]))" +
            @"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}" +
            @"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])" +
            @"(?::\d{1,5})?" +
            @")" +
            @"(?![\w.])",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        protected override IEnumerable<Regex> DenyList => new[]
        {
            PublicIpRegex,
        };
    }
}
