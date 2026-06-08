using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class TwilioKeyDetectorTests
    {
        private readonly TwilioKeyDetector _detector = new TwilioKeyDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Twilio API Key", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsApiKey()
        {
            var results = _detector.AnalyzeString("SK" + new string('a', 32)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TooShort()
        {
            var results = _detector.AnalyzeString("SK123").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongPrefix()
        {
            var results = _detector.AnalyzeString("XX" + new string('b', 32)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env", "TWILIO_API_KEY=SK" + new string('c', 32), 6);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Twilio API Key", secret.Type);
            Assert.Equal(".env", secret.Filename);
        }
    }
}
