using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class SendGridDetectorTests
    {
        private readonly SendGridDetector _detector = new SendGridDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("SendGrid API Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsToken()
        {
            var token = "SG." + new string('a', 68);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongPrefix()
        {
            var results = _detector.AnalyzeString("XX." + new string('b', 68)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var token = "SG." + new string('c', 68);
            var results = _detector.AnalyzeLine("config.env", $"SENDGRID_API_KEY={token}", 2);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("SendGrid API Token", secret.Type);
        }
    }
}
