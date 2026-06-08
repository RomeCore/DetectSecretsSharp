using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class GitHubTokenDetectorTests
    {
        private readonly GitHubTokenDetector _detector = new GitHubTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("GitHub Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsGhpToken()
        {
            var results = _detector.AnalyzeString("ghp_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsGhoToken()
        {
            var results = _detector.AnalyzeString("gho_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsGhsToken()
        {
            var results = _detector.AnalyzeString("ghs_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsGhrToken()
        {
            var results = _detector.AnalyzeString("ghr_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsGhuToken()
        {
            var results = _detector.AnalyzeString("ghu_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_InvalidPrefix_NoMatch()
        {
            var results = _detector.AnalyzeString("ghz_abc123ABC456def789GHI012jkl345MNO678").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_TooShort_NoMatch()
        {
            var results = _detector.AnalyzeString("ghp_abc123ABC456def789GHI012jkl345").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.env", "GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678", 42);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("GitHub Token", secret.Type);
            Assert.Equal("config.env", secret.Filename);
            Assert.Equal(42, secret.LineNumber);
        }
    }
}
