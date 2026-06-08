using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for secret-sounding variable names (password, secret, api_key, etc.)
    /// using a variety of assignment patterns.
    /// </summary>
    public class KeywordDetector : DetectorBase
    {
        public override string SecretType => "Secret Keyword";

        private readonly Regex _keywordExclude;

        // All values should be lowercase
        private static readonly string[] DenyListKeywords =
        {
            "api_?key",
            "auth_?key",
            "service_?key",
            "account_?key",
            "db_?key",
            "database_?key",
            "priv_?key",
            "private_?key",
            "client_?key",
            "db_?pass",
            "database_?pass",
            "key_?pass",
            "password",
            "passwd",
            "pwd",
            "secret",
            "contraseña",
            "contrasena",
        };

        private const string Closing = @"[]'""]{0,2}";
        private const string AffixRegex = @"\w*";
        private const string OptionalWhitespace = @"\s*";
        private const string OptionalNonWhitespace = @"[^\s]{0,50}?";
        private const string Quote = @"['""`]";
        private const string SquareBrackets = @"(\[[0-9]*\])";

        private static readonly string DenyListPattern;
        private static readonly string DenyListWithPrefix;
        private static readonly string SecretPattern;

        // All regex patterns
        private static readonly Regex FollowedByColonEqualSignsRegex;
        private static readonly Regex FollowedByColonRegex;
        private static readonly Regex FollowedByColonQuotesRequiredRegex;
        private static readonly Regex FollowedByEqualSignsOptionalBracketsOptionalAtSignQuotesRequiredRegex;
        private static readonly Regex FollowedByOptionalAssignQuotesRequiredRegex;
        private static readonly Regex FollowedByEqualSignsRegex;
        private static readonly Regex FollowedByEqualSignsQuotesRequiredRegex;
        private static readonly Regex PrecededByEqualComparisonSignsQuotesRequiredRegex;
        private static readonly Regex FollowedByQuotesAndSemicolonRegex;
        private static readonly Regex FollowedByArrowFunctionSignQuotesRequiredRegex;

        // Regex -> group number mappings
        private static readonly Dictionary<Regex, int> ConfigDenyListRegexToGroup;
        private static readonly Dictionary<Regex, int> GolangDenyListRegexToGroup;
        private static readonly Dictionary<Regex, int> CommonCDenyListRegexToGroup;
        private static readonly Dictionary<Regex, int> CPlusPlusRegexToGroup;
        private static readonly Dictionary<Regex, int> QuotesRequiredDenyListRegexToGroup;

        private static readonly Dictionary<FileType, Dictionary<Regex, int>> RegexByFileType;

        static KeywordDetector()
        {
            DenyListPattern = $"({string.Join("|", DenyListKeywords)}){AffixRegex}";
            DenyListWithPrefix = $"{AffixRegex}{DenyListPattern}";
            SecretPattern = @"(?=[^\v\'""]*)(?=\w+)[^\v\'""]*[^\v,\'""`]";

            FollowedByColonEqualSignsRegex = new Regex(
                $@"{DenyListPattern}({Closing})?{OptionalWhitespace}:={OptionalWhitespace}({Quote}?)({SecretPattern})(\3)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByColonRegex = new Regex(
                $@"{DenyListPattern}({Closing})?:{OptionalWhitespace}({Quote}?)({SecretPattern})(\3)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByColonQuotesRequiredRegex = new Regex(
                $@"{DenyListPattern}({Closing})?:({OptionalWhitespace})({Quote})({SecretPattern})(\4)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByEqualSignsOptionalBracketsOptionalAtSignQuotesRequiredRegex = new Regex(
                $@"{DenyListPattern}({SquareBrackets})?{OptionalWhitespace}[!=]{{1,2}}{OptionalWhitespace}(@)?("")({SecretPattern})(\5)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByOptionalAssignQuotesRequiredRegex = new Regex(
                $@"{DenyListPattern}(.assign)?\(("")({SecretPattern})(\3)",
                RegexOptions.Compiled);

            FollowedByEqualSignsRegex = new Regex(
                $@"{DenyListPattern}({Closing})?{OptionalWhitespace}(={{1,3}}|!==?){OptionalWhitespace}({Quote}?)({SecretPattern})(\4)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByEqualSignsQuotesRequiredRegex = new Regex(
                $@"{DenyListPattern}({Closing})?{OptionalWhitespace}(={{1,3}}|!==?){OptionalWhitespace}({Quote})({SecretPattern})(\4)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            PrecededByEqualComparisonSignsQuotesRequiredRegex = new Regex(
                $@"({Quote})({SecretPattern})(\1){OptionalWhitespace}[!=]{{2,3}}{OptionalWhitespace}{DenyListWithPrefix}",
                RegexOptions.Compiled);

            FollowedByQuotesAndSemicolonRegex = new Regex(
                $@"{DenyListPattern}{OptionalNonWhitespace}{OptionalWhitespace}({Quote})({SecretPattern})(\2);",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            FollowedByArrowFunctionSignQuotesRequiredRegex = new Regex(
                $@"{DenyListPattern}({Closing})?{OptionalWhitespace}=>?{OptionalWhitespace}({Quote})({SecretPattern})(\3)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            // Build regex->group mappings
            ConfigDenyListRegexToGroup = new Dictionary<Regex, int>
            {
                [FollowedByColonRegex] = 4,
                [PrecededByEqualComparisonSignsQuotesRequiredRegex] = 2,
                [FollowedByEqualSignsRegex] = 5,
                [FollowedByQuotesAndSemicolonRegex] = 3,
            };

            GolangDenyListRegexToGroup = new Dictionary<Regex, int>
            {
                [FollowedByColonEqualSignsRegex] = 4,
                [PrecededByEqualComparisonSignsQuotesRequiredRegex] = 2,
                [FollowedByEqualSignsRegex] = 5,
                [FollowedByQuotesAndSemicolonRegex] = 3,
            };

            CommonCDenyListRegexToGroup = new Dictionary<Regex, int>
            {
                [FollowedByEqualSignsOptionalBracketsOptionalAtSignQuotesRequiredRegex] = 6,
            };

            CPlusPlusRegexToGroup = new Dictionary<Regex, int>
            {
                [FollowedByOptionalAssignQuotesRequiredRegex] = 4,
                [FollowedByEqualSignsQuotesRequiredRegex] = 5,
            };

            QuotesRequiredDenyListRegexToGroup = new Dictionary<Regex, int>
            {
                [FollowedByColonQuotesRequiredRegex] = 5,
                [PrecededByEqualComparisonSignsQuotesRequiredRegex] = 2,
                [FollowedByEqualSignsQuotesRequiredRegex] = 5,
                [FollowedByQuotesAndSemicolonRegex] = 3,
                [FollowedByArrowFunctionSignQuotesRequiredRegex] = 4,
            };

            RegexByFileType = new Dictionary<FileType, Dictionary<Regex, int>>
            {
                [FileType.Go] = GolangDenyListRegexToGroup,
                [FileType.ObjectiveC] = CommonCDenyListRegexToGroup,
                [FileType.CSharp] = CommonCDenyListRegexToGroup,
                [FileType.C] = CommonCDenyListRegexToGroup,
                [FileType.CPlusPlus] = CPlusPlusRegexToGroup,
                [FileType.Cls] = QuotesRequiredDenyListRegexToGroup,
                [FileType.Java] = QuotesRequiredDenyListRegexToGroup,
                [FileType.JavaScript] = QuotesRequiredDenyListRegexToGroup,
                [FileType.Python] = QuotesRequiredDenyListRegexToGroup,
                [FileType.Swift] = QuotesRequiredDenyListRegexToGroup,
                [FileType.Terraform] = QuotesRequiredDenyListRegexToGroup,
                [FileType.Yaml] = ConfigDenyListRegexToGroup,
                [FileType.Config] = ConfigDenyListRegexToGroup,
                [FileType.Ini] = ConfigDenyListRegexToGroup,
                [FileType.Properties] = ConfigDenyListRegexToGroup,
                [FileType.Toml] = ConfigDenyListRegexToGroup,
            };
        }

        public KeywordDetector(string keywordExclude = null)
        {
            if (!string.IsNullOrEmpty(keywordExclude))
            {
                _keywordExclude = new Regex(keywordExclude, RegexOptions.IgnoreCase);
            }
        }

        public override IEnumerable<string> AnalyzeString(string str)
        {
            if (_keywordExclude != null && _keywordExclude.IsMatch(str))
                yield break;

            // Default to quotes-required patterns
            var attempts = new[] { QuotesRequiredDenyListRegexToGroup };

            bool hasResults = false;
            foreach (var denylistRegexToGroup in attempts)
            {
                foreach (var kvp in denylistRegexToGroup)
                {
                    var match = kvp.Key.Match(str);
                    if (match.Success)
                    {
                        hasResults = true;
                        yield return match.Groups[kvp.Value].Value;
                    }
                }

                if (hasResults)
                    yield break;
            }
        }

        public override HashSet<PotentialSecret> AnalyzeLine(
            string filename,
            string line,
            int lineNumber = 0,
            CodeSnippet context = null)
        {
            var filetype = FileTypeDetector.DetermineFileType(filename);

            var denylistRegexToGroup = RegexByFileType.ContainsKey(filetype)
                ? RegexByFileType[filetype]
                : QuotesRequiredDenyListRegexToGroup;

            return AnalyzeLineWithRegex(line, filename, lineNumber, context, denylistRegexToGroup);
        }

        private HashSet<PotentialSecret> AnalyzeLineWithRegex(
            string line,
            string filename,
            int lineNumber,
            CodeSnippet context,
            Dictionary<Regex, int> denylistRegexToGroup)
        {
            var output = new HashSet<PotentialSecret>();

            if (_keywordExclude != null && _keywordExclude.IsMatch(line))
                return output;

            foreach (var kvp in denylistRegexToGroup)
            {
                var match = kvp.Key.Match(line);
                if (match.Success)
                {
                    string secretValue = match.Groups[kvp.Value].Value;

                    if (!string.IsNullOrEmpty(secretValue))
                    {
                        bool isVerified = false;
                        if (context != null)
                        {
                            try
                            {
                                var verifiedResult = Verify(secretValue, context);
                                isVerified = verifiedResult == VerifiedResult.VerifiedTrue;
                            }
                            catch { }
                        }

                        output.Add(new PotentialSecret(
                            type: SecretType,
                            filename: filename,
                            secret: secretValue,
                            lineNumber: lineNumber,
                            isVerified: isVerified));
                    }
                }
            }

            return output;
        }
    }
}
