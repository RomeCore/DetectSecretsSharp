using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for NPM tokens (.npmrc _authToken).
    /// </summary>
    public class NpmDetector : RegexBasedDetector
    {
        public override string SecretType => "NPM tokens";

        private static readonly Regex NpmRegex = new Regex(
            @"\/\/.+\/:_authToken=\s*((npm_.+)|([A-Fa-f0-9-]{36})).*",
            RegexOptions.Compiled);

        protected override IEnumerable<Regex> DenyList => new[] { NpmRegex };

        public override IEnumerable<string> AnalyzeString(string str)
        {
            var match = NpmRegex.Match(str);
            if (match.Success)
            {
                // Return the last non-empty group (the actual token value)
                for (int i = match.Groups.Count - 1; i >= 1; i--)
                {
                    string val = match.Groups[i].Value;
                    if (!string.IsNullOrEmpty(val))
                    {
                        yield return val;
                        yield break;
                    }
                }
            }
        }
    }
}
