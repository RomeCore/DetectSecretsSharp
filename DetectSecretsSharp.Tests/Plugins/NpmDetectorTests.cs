using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class NpmDetectorTests
    {
        private readonly NpmDetector _detector = new NpmDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("NPM tokens", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsNpmToken()
        {
            var results = _detector.AnalyzeString("//registry.npmjs.org/:_authToken=npm_abc123def456ghi789jkl012mno345pqr678stu901vwx234").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsUuidToken()
        {
            var results = _detector.AnalyzeString("//registry.npmjs.org/:_authToken=abcdef01-2345-6789-abcd-ef0123456789").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_MissingPrefix()
        {
            var results = _detector.AnalyzeString("_authToken=npm_abc123").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".npmrc", "//registry.npmjs.org/:_authToken=npm_secret1234567890abcdef", 3);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("NPM tokens", secret.Type);
            Assert.Equal(".npmrc", secret.Filename);
        }
    }
}
