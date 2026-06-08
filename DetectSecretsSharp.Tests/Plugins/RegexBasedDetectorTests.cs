using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class RegexBasedDetectorTests
    {
        /// <summary>
        /// A test detector that finds values looking like API keys: 32 hex chars.
        /// </summary>
        private class TestApiKeyDetector : RegexBasedDetector
        {
            public override string SecretType => "Test API Key";
            protected override IEnumerable<Regex> DenyList => new[]
            {
                new Regex(@"[A-F0-9]{32}", RegexOptions.Compiled),
                new Regex(@"(?i)api_key['""]?\s*[:=]\s*['""]([^'""]+)['""]", RegexOptions.Compiled)
            };
        }

        /// <summary>
        /// A test detector with capture groups.
        /// </summary>
        private class TestCaptureGroupDetector : RegexBasedDetector
        {
            public override string SecretType => "CaptureGroup";
            protected override IEnumerable<Regex> DenyList => new[]
            {
                new Regex(@"(?i)(password|secret)\s*[:=]\s*(\S+)", RegexOptions.Compiled)
            };
        }

        [Fact]
        public void AnalyzeString_FindsHexKey()
        {
            // 32 hex chars: A1B2C3D4E5F6 (12) + A1B2C3D4E5F6 (12) + A1B2C3D4 (8) = 32
            const string hex32 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4";
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeString("key=" + hex32).ToList();

            Assert.Single(results);
            Assert.Equal(hex32, results[0]);
        }

        [Fact]
        public void AnalyzeString_FindsApiKeyAssignment()
        {
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeString("API_KEY = 'sk-1234567890abcdef'").ToList();

            Assert.Single(results);
            Assert.Equal("sk-1234567890abcdef", results[0]);
        }

        [Fact]
        public void AnalyzeString_NoMatch_ReturnsEmpty()
        {
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeString("hello world");

            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_MultipleMatches()
        {
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeString(
                "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4 and D5E6F7A8B9C0D5E6F7A8B9C0D5E6F7A8B9C0")
                .ToList();

            Assert.Equal(2, results.Count);
        }

        [Fact]
        public void AnalyzeString_CaptureGroups_YieldNonEmpty()
        {
            var detector = new TestCaptureGroupDetector();
            var results = detector.AnalyzeString("password = hunter2").ToList();

            Assert.Contains("password", results);
            Assert.Contains("hunter2", results);
        }

        [Fact]
        public void AnalyzeString_CaptureGroups_WithEmptySecondGroup_IgnoresEmpty()
        {
            // Use a regex where second group can be empty
            var detector = new TestDetectorWithOptionalGroup();
            var results = detector.AnalyzeString("secret = ").ToList();

            // Should yield "secret" but not the empty value
            Assert.Contains("secret", results);
            Assert.DoesNotContain("", results);
        }

        /// <summary>
        /// Detector with optional second capture group.
        /// </summary>
        private class TestDetectorWithOptionalGroup : RegexBasedDetector
        {
            public override string SecretType => "OptionalGroup";
            protected override IEnumerable<Regex> DenyList => new[]
            {
                new Regex(@"(?i)(password|secret)\s*[:=]\s*(\S*)?", RegexOptions.Compiled)
            };
        }

        [Fact]
        public void BuildAssignmentRegex_MatchesStandardFormat()
        {
            var regex = RegexBasedDetector.BuildAssignmentRegex(
                prefixRegex: "MYAPP",
                secretKeywordRegex: "TOKEN",
                secretRegex: @"[A-Za-z0-9]+");

            Assert.Matches(regex, "MYAPP_TOKEN = abc123");
            Assert.Matches(regex, "MYAPP-TOKEN:xyz789");
            Assert.DoesNotMatch(regex, "NOT_MYAPP_TOKEN = abc");
        }

        [Fact]
        public void AnalyzeLine_Integration()
        {
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeLine("config.txt", "API_KEY = 'sk-abcdef1234567890'", 15);

            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Test API Key", secret.Type);
            Assert.Equal("config.txt", secret.Filename);
            Assert.Equal(15, secret.LineNumber);
        }

        [Fact]
        public void SecretType_IsSet()
        {
            var detector = new TestApiKeyDetector();
            Assert.Equal("Test API Key", detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_CaptureGroups_MultipleRegexes()
        {
            // Test that both regexes in the deny list work
            var detector = new TestApiKeyDetector();
            var results = detector.AnalyzeString(
                "API_KEY = 'secret123' AND A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4")
                .ToList();

            Assert.Equal(2, results.Count);
            Assert.Contains("secret123", results);
        }
    }
}
