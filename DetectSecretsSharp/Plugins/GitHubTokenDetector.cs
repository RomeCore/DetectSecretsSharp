using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for GitHub tokens.
    /// ref: https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
    /// </summary>
    public class GitHubTokenDetector : RegexBasedDetector
    {
        public override string SecretType => "GitHub Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
                RegexOptions.Compiled)
        };
    }
}
