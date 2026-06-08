using System.Linq;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class SlackDetectorTests
    {
        private readonly SlackDetector _detector = new SlackDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Slack Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsBotToken()
        {
            var results = _detector.AnalyzeString("xoxb-123456789012-123456789012-abc123def456ghi789jkl012mno345pqr").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsUserToken()
        {
            var results = _detector.AnalyzeString("xoxp-123456789012-123456789012-123456789012-abc123def456ghi789jkl012mno345pqr").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsWebhookUrl()
        {
            var results = _detector.AnalyzeString("https://hooks.slack.com/services/T12345678/B12345678/abc123def456ghi789jkl012").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_InvalidPrefix_NoMatch()
        {
            var results = _detector.AnalyzeString("xoxz-123456789012-123456789012-abc123def456ghi789jkl012mno345pqr").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoToken_NoMatch()
        {
            var results = _detector.AnalyzeString("just a normal string without tokens").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.yaml",
                "slack_token: xoxb-123456789012-123456789012-abc123def456ghi789jkl012mno345pqr", 15);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Slack Token", secret.Type);
            Assert.Equal("config.yaml", secret.Filename);
            Assert.Equal(15, secret.LineNumber);
        }

        [Fact]
        public void Verify_UnverifiedForInvalidToken()
        {
            // This won't actually call the API - the token is clearly invalid format
            var result = _detector.Verify("xoxb-1-2-abc");
            // Should return Unverified (the API call would fail but we catch exceptions)
            Assert.Equal(VerifiedResult.Unverified, result);
        }
    }
}
