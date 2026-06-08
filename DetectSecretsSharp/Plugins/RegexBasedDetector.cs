using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Parent class for regular-expression based detectors.
    /// 
    /// To create a new regex-based detector, subclass this and set <see cref="SecretType"/>
    /// with a description and <see cref="DenyList"/> with a sequence of compiled regular expressions.
    /// </summary>
    public abstract class RegexBasedDetector : DetectorBase
    {
        /// <summary>
        /// A sequence of compiled regular expressions that define the patterns to detect.
        /// </summary>
        protected abstract IEnumerable<Regex> DenyList { get; }

        /// <summary>
        /// Analyzes a string using all regex patterns in <see cref="DenyList"/>.
        /// Yields all matching secret values.
        /// </summary>
        public override IEnumerable<string> AnalyzeString(string str)
        {
            foreach (Regex regex in DenyList)
            {
                MatchCollection matches = regex.Matches(str);

                foreach (Match match in matches)
                {
                    if (match.Groups.Count > 1)
                    {
                        // If there are capture groups, yield each non-empty group value
                        for (int i = 1; i < match.Groups.Count; i++)
                        {
                            string value = match.Groups[i].Value;
                            if (!string.IsNullOrEmpty(value))
                                yield return value;
                        }
                    }
                    else
                    {
                        yield return match.Value;
                    }
                }
            }
        }

        /// <summary>
        /// Builds a regex pattern for matching secret assignments in configuration files.
        /// 
        /// Format: <![CDATA[<prefix_regex>(-|_|)<secret_keyword_regex> <assignment> <secret_regex>]]>
        /// Assignment includes: =, :, :=, =>, ::
        /// Key name and value support optional quotes and square brackets.
        /// </summary>
        /// <param name="prefixRegex">Regex pattern for the prefix (e.g. application name).</param>
        /// <param name="secretKeywordRegex">Regex pattern for the secret keyword (e.g. "password", "token").</param>
        /// <param name="secretRegex">Regex pattern for the secret value.</param>
        /// <returns>A compiled Regex that matches the assignment pattern.</returns>
        public static Regex BuildAssignmentRegex(
            string prefixRegex,
            string secretKeywordRegex,
            string secretRegex)
        {
            string begin = @"(?:(?<=\W)|(?<=^))";
            string optQuote = @"(?:""|'|)";
            string optOpenSquareBracket = @"(?:\[|)";
            string optCloseSquareBracket = @"(?:\]|)";
            string optDashUnderscore = @"(?:_|-|)";
            string optSpace = @"(?: *)";
            string assignment = @"(?:=|:|:=|=>| +|::)";

            string pattern =
                begin +
                optOpenSquareBracket +
                optQuote +
                prefixRegex +
                optDashUnderscore +
                secretKeywordRegex +
                optQuote +
                optCloseSquareBracket +
                optSpace +
                assignment +
                optSpace +
                optQuote +
                secretRegex +
                optQuote;

            return new Regex(
                pattern,
                RegexOptions.Compiled | RegexOptions.IgnoreCase);
        }
    }
}
