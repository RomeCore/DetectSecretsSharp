using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for Artifactory credentials (API tokens and encrypted passwords).
    /// </summary>
    public class ArtifactoryDetector : RegexBasedDetector
    {
        public override string SecretType => "Artifactory Credentials";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // Artifactory API tokens begin with AKC
            new Regex(
                @"(?:\s|=|:|""|^)AKC[a-zA-Z0-9]{10,}(?:\s|""|$)",
                RegexOptions.Compiled),

            // Artifactory encrypted passwords begin with AP[A-Z]
            new Regex(
                @"(?:\s|=|:|""|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|""|$)",
                RegexOptions.Compiled),
        };
    }
}
