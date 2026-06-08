using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class JwtTokenDetectorTests
    {
        private readonly JwtTokenDetector _detector = new JwtTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("JSON Web Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsValidJwt()
        {
            // A JWT with valid base64-encoded JSON in header and payload
            var header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
            var payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"; // {"sub":"1234567890","name":"John Doe","iat":1516239022}
            var signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            var jwt = $"{header}.{payload}.{signature}";
            var results = _detector.AnalyzeString(jwt).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_InvalidPayload_NoMatch()
        {
            // Invalid base64 in payload
            var results = _detector.AnalyzeString("eyJhbGciOiJIUzI1NiJ9.invalid!!!.signature").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_RandomString()
        {
            var results = _detector.AnalyzeString("just a normal string").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            var payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
            var signature = "dGhpcyBpcyBhIHRlc3Qgc2lnbmF0dXJl";

            var results = _detector.AnalyzeLine("config.yaml",
                $"TOKEN={header}.{payload}.{signature}", 10);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("JSON Web Token", secret.Type);
        }
    }
}
