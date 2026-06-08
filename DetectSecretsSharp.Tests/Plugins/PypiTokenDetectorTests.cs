using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class PypiTokenDetectorTests
    {
        private readonly PypiTokenDetector _detector = new PypiTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("PyPI Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsPypiOrgToken()
        {
            var token = "pypi-AgEIcHlwaS5vcmc" + new string('A', 70);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsTestPypiOrgToken()
        {
            var token = "pypi-AgENdGVzdC5weXBpLm9yZw" + new string('B', 70);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongPrefix()
        {
            var results = _detector.AnalyzeString("pypi-wrongprefix" + new string('C', 70)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var token = "pypi-AgEIcHlwaS5vcmc" + new string('D', 70);
            var results = _detector.AnalyzeLine(".pypirc", $"password = {token}", 4);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("PyPI Token", secret.Type);
            Assert.Equal(".pypirc", secret.Filename);
        }
    }
}
