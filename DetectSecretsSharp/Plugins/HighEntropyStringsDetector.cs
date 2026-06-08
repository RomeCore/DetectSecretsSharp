using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Base class for high-entropy string detection (base64, hex, etc).
    /// Uses Shannon entropy to find random-looking strings that may be secrets.
    /// </summary>
    public abstract class HighEntropyStringsDetector : DetectorBase
    {
        /// <summary>Characters that make up the charset for entropy calculation.</summary>
        public string Charset { get; }

        /// <summary>Minimum entropy threshold (0.0 to 8.0).</summary>
        public double EntropyLimit { get; }

        /// <summary>Regex to find quoted strings matching the charset.</summary>
        protected Regex StringRegex { get; private set; }

        protected HighEntropyStringsDetector(string charset, double limit)
        {
            if (limit < 0 || limit > 8)
                throw new ArgumentException("Limit must be between 0.0 and 8.0", nameof(limit));

            Charset = charset ?? throw new ArgumentNullException(nameof(charset));
            EntropyLimit = limit;

            // Require quoted strings to reduce noise
            StringRegex = new Regex(
                $"(['\"])([{Regex.Escape(charset)}]+)(\\1)",
                RegexOptions.Compiled);
        }

        public override IEnumerable<string> AnalyzeString(string str)
        {
            var matches = StringRegex.Matches(str);
            foreach (Match match in matches)
            {
                if (match.Groups.Count > 1)
                {
                    // Group 2 is the captured string content (between quotes)
                    yield return match.Groups[2].Value;
                }
            }
        }

        public override HashSet<PotentialSecret> AnalyzeLine(
            string filename,
            string line,
            int lineNumber = 0,
            CodeSnippet context = null)
        {
            var output = base.AnalyzeLine(filename, line, lineNumber, context);

            // Filter by entropy limit
            return new HashSet<PotentialSecret>(
                output.Where(secret =>
                    secret.SecretValue != null &&
                    CalculateShannonEntropy(secret.SecretValue) > EntropyLimit));
        }

        /// <summary>
        /// Calculates the Shannon entropy of a given string.
        /// </summary>
        public virtual double CalculateShannonEntropy(string data)
        {
            if (string.IsNullOrEmpty(data))
                return 0;

            double entropy = 0.0;
            foreach (char x in Charset)
            {
                double pX = (double)CountChar(data, x) / data.Length;
                if (pX > 0)
                    entropy += -pX * Math.Log(pX, 2);
            }

            return entropy;
        }

        private static int CountChar(string data, char c)
        {
            int count = 0;
            foreach (char ch in data)
            {
                if (ch == c) count++;
            }
            return count;
        }

        public override string FormatScanResult(PotentialSecret secret)
        {
            if (secret?.SecretValue == null)
                return "True";

            double entropy = Math.Round(CalculateShannonEntropy(secret.SecretValue), 3);
            if (entropy < EntropyLimit)
                return $"False ({entropy})";

            return $"True  ({entropy})";
        }

        /// <summary>
        /// Temporarily replaces the regex with a non-quoted version for adhoc scanning.
        /// </summary>
        public IDisposable UseNonQuotedRegex(bool isExactMatch = true)
        {
            return new NonQuotedRegexScope(this, isExactMatch);
        }

        private class NonQuotedRegexScope : IDisposable
        {
            private readonly HighEntropyStringsDetector _detector;
            private readonly Regex _oldRegex;

            public NonQuotedRegexScope(HighEntropyStringsDetector detector, bool isExactMatch)
            {
                _detector = detector;
                _oldRegex = detector.StringRegex;

                string regexPattern = $"([{Regex.Escape(detector.Charset)}]+)";
                if (isExactMatch)
                    regexPattern = "^" + regexPattern + "$";

                detector.StringRegex = new Regex(regexPattern);
            }

            public void Dispose()
            {
                _detector.StringRegex = _oldRegex;
            }
        }
    }

    /// <summary>
    /// Scans for random-looking base64 encoded strings.
    /// Default entropy limit: 4.5
    /// </summary>
    public class Base64HighEntropyStringDetector : HighEntropyStringsDetector
    {
        public override string SecretType => "Base64 High Entropy String";

        public Base64HighEntropyStringDetector(double limit = 4.5)
            : base(
                charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/\\-_=",
                limit: limit)
        {
        }
    }

    /// <summary>
    /// Scans for random-looking hex encoded strings.
    /// Default entropy limit: 3.0
    /// </summary>
    public class HexHighEntropyStringDetector : HighEntropyStringsDetector
    {
        public override string SecretType => "Hex High Entropy String";

        public HexHighEntropyStringDetector(double limit = 3.0)
            : base(
                charset: "abcdefABCDEF0123456789",
                limit: limit)
        {
        }

        public override double CalculateShannonEntropy(string data)
        {
            double entropy = base.CalculateShannonEntropy(data);

            if (data.Length <= 1)
                return entropy;

            // Check if string is all digits
            if (IsAllDigits(data))
            {
                // Reduce entropy for all-digit strings to reduce false positives
                // This heuristic was determined through trial and error
                entropy -= 1.2 / Math.Log(data.Length, 2);
            }

            return entropy;
        }

        private static bool IsAllDigits(string data)
        {
            foreach (char c in data)
            {
                if (!char.IsDigit(c))
                    return false;
            }
            return true;
        }
    }
}
