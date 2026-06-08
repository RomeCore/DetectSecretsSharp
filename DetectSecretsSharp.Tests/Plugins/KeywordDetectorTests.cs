using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class KeywordDetectorTests
    {
        private readonly KeywordDetector _detector = new KeywordDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Secret Keyword", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsPasswordAssignment()
        {
            var results = _detector.AnalyzeString("password = \"supersecret123\"").ToList();
            Assert.NotEmpty(results);
        }

        [Fact]
        public void AnalyzeString_FindsApiKey()
        {
            var results = _detector.AnalyzeString("api_key = \"abc123def456\"").ToList();
            Assert.NotEmpty(results);
        }

        [Fact]
        public void AnalyzeString_FindsSecret()
        {
            var results = _detector.AnalyzeString("secret: \"mysecretvalue\"").ToList();
            Assert.NotEmpty(results);
        }

        [Fact]
        public void AnalyzeString_FindsAuthToken()
        {
            var results = _detector.AnalyzeString("auth_token = \"tokensecret123\";").ToList();
            Assert.NotNull(results);
        }

        [Theory]
        [InlineData("x = 1")]
        [InlineData("public class Foo")]
        [InlineData("hello world")]
        public void AnalyzeString_NoMatch_NormalText(string text)
        {
            var results = _detector.AnalyzeString(text).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ByFileType_UsesCorrectRegex()
        {
            var results = _detector.AnalyzeLine("config.cs", "password = \"secret123\";", 5);
            Assert.NotEmpty(results);
        }

        [Fact]
        public void AnalyzeLine_YamlFile_UsesColonRegex()
        {
            var results = _detector.AnalyzeLine("config.yaml", "password: \"secretvalue\"", 3);
            Assert.NotEmpty(results);
            var secret = results.First();
            Assert.Equal("Secret Keyword", secret.Type);
            Assert.Equal("config.yaml", secret.Filename);
        }

        [Fact]
        public void AnalyzeString_WithKeywordExclude_FiltersOut()
        {
            var detector = new KeywordDetector(keywordExclude: "excluded");
            var results = detector.AnalyzeString("password = \"excluded_value\"").ToList();
            Assert.Empty(results);
        }
    }
}
