using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for GitLab tokens of various types.
    /// </summary>
    public class GitLabTokenDetector : RegexBasedDetector
    {
        public override string SecretType => "GitLab Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // Personal Access Token - glpat
            // Deploy Token - gldt
            // Feed Token - glft
            // OAuth Access Token - glsoat
            // Runner Token - glrt
            new Regex(
                @"(glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?!\w)",
                RegexOptions.Compiled),

            // Runner Registration Token
            new Regex(
                @"GR1348941[A-Za-z0-9_\-]{20,50}(?!\w)",
                RegexOptions.Compiled),

            // CI/CD Token
            new Regex(
                @"glcbt-([0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50}(?!\w)",
                RegexOptions.Compiled),

            // Incoming Mail Token
            new Regex(
                @"glimt-[A-Za-z0-9_\-]{25}(?!\w)",
                RegexOptions.Compiled),

            // Trigger Token
            new Regex(
                @"glptt-[A-Za-z0-9_\-]{40}(?!\w)",
                RegexOptions.Compiled),

            // Agent Token
            new Regex(
                @"glagent-[A-Za-z0-9_\-]{50,1024}(?!\w)",
                RegexOptions.Compiled),

            // GitLab OAuth Application Secret
            new Regex(
                @"gloas-[A-Za-z0-9_\-]{64}(?!\w)",
                RegexOptions.Compiled),
        };
    }
}
