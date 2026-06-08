using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class StripeDetectorTests
    {
        private readonly StripeDetector _detector = new StripeDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Stripe Access Key", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsSkLiveKey()
        {
            var results = _detector.AnalyzeString("sk_live_" + new string('a', 24)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsRkLiveKey()
        {
            var results = _detector.AnalyzeString("rk_live_" + new string('b', 24)).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TestKey()
        {
            var results = _detector.AnalyzeString("sk_test_" + new string('c', 24)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env", "STRIPE_SECRET_KEY=sk_live_" + new string('d', 24), 3);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Stripe Access Key", secret.Type);
        }
    }
}
