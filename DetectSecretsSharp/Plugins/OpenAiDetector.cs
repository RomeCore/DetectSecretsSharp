using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for OpenAI tokens.
    /// User api keys (legacy): 'sk-[20 alnum]T3BlbkFJ[20 alnum]'
    /// Project-based api keys: 'sk-[project-name]-[20 alnum]T3BlbkFJ[20 alnum]'
    /// ref: https://community.openai.com/t/what-are-the-valid-characters-for-the-apikey/288643
    /// </summary>
    public class OpenAiDetector : RegexBasedDetector
    {
        public override string SecretType => "OpenAI Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            new Regex(
                @"sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
                RegexOptions.Compiled)
        };
    }
}
