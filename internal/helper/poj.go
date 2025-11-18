package helper

// GetPojJS returns the proof-of-javascript JavaScript implementation
func GetPojJS() string {
	return `// Proof of Javascript CAPTCHA
(function() {
    function initPoW() {
        var captchaDiv = document.querySelector('[data-callback]');
        if (!captchaDiv) {
            console.error('PoW: captcha div not found');
            return;
        }

        var callbackName = captchaDiv.getAttribute('data-callback');

        if (!callbackName) {
            console.error('PoW: missing callback or challenge');
            return;
        }
        callbackName("foo")
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPoW);
    } else {
        initPoW();
    }
})();`
}
