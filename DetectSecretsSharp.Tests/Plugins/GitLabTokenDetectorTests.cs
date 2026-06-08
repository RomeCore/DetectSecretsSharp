using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class GitLabTokenDetectorTests
    {
        private readonly GitLabTokenDetector _detector = new GitLabTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("GitLab Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsPersonalAccessToken()
        {
            var results = _detector.AnalyzeString("glpat-" + new string('a', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsDeployToken()
        {
            var results = _detector.AnalyzeString("gldt-" + new string('b', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsTriggerToken()
        {
            var results = _detector.AnalyzeString("glptt-" + new string('c', 40)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsCicdToken()
        {
            var results = _detector.AnalyzeString("glcbt-ab_" + new string('d', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsAgentToken()
        {
            var results = _detector.AnalyzeString("glagent-" + new string('e', 55)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsOauthSecret()
        {
            var results = _detector.AnalyzeString("gloas-" + new string('f', 64)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsIncomingMailToken()
        {
            var results = _detector.AnalyzeString("glimt-" + new string('g', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsRunnerRegistrationToken()
        {
            var results = _detector.AnalyzeString("GR1348941" + new string('h', 25)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_InvalidPrefix()
        {
            var results = _detector.AnalyzeString("glxxx-" + new string('i', 25)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine("config.env", "GITLAB_TOKEN=glpat-" + new string('j', 25), 8);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("GitLab Token", secret.Type);
        }
    }
}
