using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class SoftlayerDetectorTests
    {
        private readonly SoftlayerDetector _detector = new SoftlayerDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("SoftLayer Credentials", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsApiKeyAssignment()
        {
            // 64 lowercase alphanumeric chars
            var key = new string('a', 64);
            var results = _detector.AnalyzeString($"softlayer_api_key={key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsUrlWithKey()
        {
            var key = new string('b', 64);
            var results = _detector.AnalyzeString($"https://api.softlayer.com/soap/v3/{key}").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_InvalidUrlVersion()
        {
            var key = new string('c', 64);
            var results = _detector.AnalyzeString($"https://api.softlayer.com/soap/v2/{key}").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var key = new string('d', 64);
            var results = _detector.AnalyzeLine(".env", $"SOFTLAYER_API_KEY={key}", 5);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("SoftLayer Credentials", secret.Type);
        }
    }
}
