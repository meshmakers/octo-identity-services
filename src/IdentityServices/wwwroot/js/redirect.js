window.addEventListener("load", function () {

    function explode() {
        const a = document.querySelector("a.redirect-url");
        if (a) {
            window.location = a.href;
        }
    }

    setTimeout(explode, 3000);
});