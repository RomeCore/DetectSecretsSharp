using System.Linq;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class TelegramBotTokenDetectorTests
    {
        private readonly TelegramBotTokenDetector _detector = new TelegramBotTokenDetector();

        [Fact]
        public void SecretType_IsSet()
        {
            Assert.Equal("Telegram Bot Token", _detector.SecretType);
        }

        [Fact]
        public void AnalyzeString_FindsToken()
        {
            // Format: 1234567890:ABCdefGHIjklmNOpqrsTUVwxyz-_1234567890123456
            var results = _detector.AnalyzeString("1234567890:ABCdefGHIjklmNOpqrsTUVwxyz-_1234567890123456").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_TooShort()
        {
            var results = _detector.AnalyzeString("123:ABC").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeString_NoMatch_WrongFormat()
        {
            var results = _detector.AnalyzeString("not-a-telegram-token").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void AnalyzeLine_ReturnsPotentialSecret()
        {
            var results = _detector.AnalyzeLine(".env",
                "TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklmNOpqrsTUVwxyz-_1234567890123456", 4);
            Assert.Single(results);
            var secret = results.First();
            Assert.Equal("Telegram Bot Token", secret.Type);
        }
    }
}
