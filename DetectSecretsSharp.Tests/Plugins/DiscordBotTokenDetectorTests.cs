using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class DiscordBotTokenDetectorTests
    {
        private readonly DiscordBotTokenDetector _detector = new DiscordBotTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Discord Bot Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsNToken()
        {
            var token = "N" + new string('a', 24) + ".abc123." + new string('x', 27);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsMToken()
        {
            var token = "M" + new string('b', 23) + ".def456." + new string('y', 27);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_FindsOToken()
        {
            var token = "O" + new string('c', 25) + ".ghi789." + new string('z', 27);
            var results = _detector.AnalyzeString(token).ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_InvalidPrefix_NoMatch()
        {
            var results = _detector.AnalyzeString("P" + new string('a', 24) + ".abc123." + new string('x', 27)).ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var token = "M" + new string('a', 23) + ".abc123." + new string('x', 27);
            var results = _detector.AnalyzeLine(".env", $"DISCORD_TOKEN={token}", 7);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Discord Bot Token", secret.Type);
            Assert.Equal(".env", secret.Filename);
        }
    }
}
