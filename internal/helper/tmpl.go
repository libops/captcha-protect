package helper

// need to hardcode a default template
// given yaegi's constraints on finding files on disk
// provided by this plugin
func GetDefaultTmpl() string {
	return `<html>
  <head>
    <title>Verifying connection</title>
    <script src="{{ .FrontendJS }}" async defer referrerpolicy="no-referrer"></script>
  </head>
  <body>
    <h1>Verifying connection</h1>
    <p>One moment while we verify your network connection.</p>
    <form action="{{ .ChallengeURL }}" method="post" id="captcha-form" accept-charset="UTF-8">
        <div
            data-callback="captchaCallback"
            class="{{ .FrontendKey }}"
            data-sitekey="{{ .SiteKey }}"
            data-theme="auto"
            data-size="normal"
            data-language="auto"
            data-retry="auto"
            interval="8000"
            data-appearance="always">
        </div>
        <input type="hidden" name="destination" value="{{ .Destination }}">
    </form>
    <script type="text/javascript">
        function captchaCallback(token) {
            setTimeout(function() {
                document.getElementById("captcha-form").submit();
            }, 1000);
        }
    </script>
  </body>
</html>`
}
