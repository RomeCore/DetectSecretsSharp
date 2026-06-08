using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DetectSecretsSharp.Plugins
{
    /// <summary>
    /// Scans for PyPI tokens (pypi.org and test.pypi.org).
    /// </summary>
    public class PypiTokenDetector : RegexBasedDetector
    {
        public override string SecretType => "PyPI Token";

        protected override IEnumerable<Regex> DenyList => new[]
        {
            // pypi.org token
            new Regex(
                @"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}",
                RegexOptions.Compiled),

            // test.pypi.org token
            new Regex(
                @"pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}",
                RegexOptions.Compiled),
        };
    }
}
