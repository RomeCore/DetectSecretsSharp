using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class MailchimpDetectorTests
    {
        private readonly MailchimpDetector _detector = new MailchimpDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Mailchimp Access Key", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsApiKey()
        {
            var results = _detector.AnalyzeString("abcdefghijklmnopqrstuvwxyz123456-us10").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_InvalidSuffix()
        {
            var results = _detector.AnalyzeString("abcdefghijklmnopqrstuvwxyz123456-uss10").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TooShort()
        {
            var results = _detector.AnalyzeString("short-us1").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env", "MAILCHIMP_API_KEY=abcdefghijklmnopqrstuvwxyz123456-us5", 12);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Mailchimp Access Key", secret.Type);
        }
    }
}
