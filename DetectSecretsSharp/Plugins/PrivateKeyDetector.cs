using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for private key headers in files.
    /// </summary>
    public class PrivateKeyDetector : RegexBasedDetector
    {
        public override string SecretType => "Private Key";

        private static readonly string[] PrivateKeyMarkers =
        {
            @"BEGIN DSA PRIVATE KEY",
            @"BEGIN EC PRIVATE KEY",
            @"BEGIN OPENSSH PRIVATE KEY",
            @"BEGIN PGP PRIVATE KEY BLOCK",
            @"BEGIN PRIVATE KEY",
            @"BEGIN RSA PRIVATE KEY",
            @"BEGIN SSH2 ENCRYPTED PRIVATE KEY",
            @"PuTTY-User-Key-File-2",
        };

        protected override IEnumerable<Regex> DenyList => BuildRegexes();

        private static IEnumerable<Regex> BuildRegexes()
        {
            foreach (var marker in PrivateKeyMarkers)
            {
                yield return new Regex(marker, RegexOptions.Compiled);
            }
        }
    }
}
