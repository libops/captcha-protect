package helper

// GetPojJS returns the proof-of-javascript JavaScript implementation
func GetPojJS() string {
	return `// Proof of Javascript CAPTCHA
(function() {
    function initPoJ() {
        var captchaDiv = document.querySelector('[data-callback]');
        if (!captchaDiv) {
            console.error('PoW: captcha div not found');
            return;
        }

        var callbackName = captchaDiv.getAttribute('data-callback');

        if (!callbackName || typeof window[callbackName] !== 'function') {
            console.error('PoW: missing callback or challenge');
            return;
        }
        var form = document.getElementById("captcha-form");
        var captchaDiv = document.querySelector('[data-callback]');
        var frontendKey = captchaDiv.className;

        // Create hidden input for the token if it doesn't exist
        var inputName = frontendKey + "-response";
        var existingInput = form.querySelector('input[name="' + inputName + '"]');
        if (!existingInput) {
            var input = document.createElement("input");
            input.type = "hidden";
            input.name = inputName;
            input.value = "foo";
            form.appendChild(input);
        }
        window[callbackName]("foo");
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPoJ);
    } else {
        initPoJ();
    }
})();`
}
