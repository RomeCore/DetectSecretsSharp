using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class BasicAuthDetectorTests
    {
        private readonly BasicAuthDetector _detector = new BasicAuthDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Basic Auth Credentials", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsBasicAuthInUrl()
        {
            // The password is captured between : and @
            var results = _detector.AnalyzeString("http://user:password@example.com").ToList();
            Assert.Single(results);
            Assert.Equal("password", results[0]);
        }

        [Fact]
        public void AnalyzeString_NoPassword_NoMatch()
        {
            var results = _detector.AnalyzeString("http://example.com/path").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_InvalidUrl()
        {
            var results = _detector.AnalyzeString("just a string without url").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.txt", "https://admin:supersecret@host.com", 3);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Basic Auth Credentials", secret.Type);
            Assert.Equal(3, secret.LineNumber);
        }

        [Fact]
        public void AnalyzeString_FindsPasswordWithSpecialChars()
        {
            var results = _detector.AnalyzeString("ftp://user:my-pass_word123@server.com").ToList();
            Assert.Single(results);
        }
    }
}
