using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class SquareOAuthDetectorTests
    {
        private readonly SquareOAuthDetector _detector = new SquareOAuthDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Square OAuth Secret", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsProductionSecret()
        {
            // sq0csp- is the production secret prefix
            var results = _detector.AnalyzeString("sq0csp-" + new string('a', 30)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsAccessToken()
        {
            // sq0asp- is the access token prefix
            var results = _detector.AnalyzeString("sq0asp-" + new string('b', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongPrefix()
        {
            var results = _detector.AnalyzeString("sq0xsp-" + new string('c', 30)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.json", "\"square_secret\": \"sq0csp-" + new string('d', 30) + "\"", 8);
            Assert.Single(results);
        }
    }
}
