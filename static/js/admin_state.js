// Preserve admin page context (query + scroll) across POST redirects.
(function () {
    function ensureHidden(form, name) {
        var input = form.querySelector('input[name="' + name + '"]');
        if (!input) {
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            form.appendChild(input);
        }
        return input;
    }

    function stampReturnState(form) {
        ensureHidden(form, '_return_path').value = window.location.pathname || '/';
        var search = window.location.search || '';
        ensureHidden(form, '_return_query').value = search.startsWith('?') ? search.substring(1) : search;
        ensureHidden(form, '_return_scroll').value = String(Math.max(0, Math.round(window.scrollY || 0)));
    }

    function setupForms() {
        var forms = document.querySelectorAll('form');
        forms.forEach(function (form) {
            var method = (form.getAttribute('method') || 'get').toLowerCase();
            if (method !== 'post') return;
            form.addEventListener('submit', function () { stampReturnState(form); }, true);
        });
    }

    function restoreScroll() {
        try {
            var url = new URL(window.location.href);
            var scrollVal = url.searchParams.get('_scroll');
            if (!scrollVal) return;
            var y = parseInt(scrollVal, 10);
            if (!isNaN(y) && y >= 0) {
                window.requestAnimationFrame(function () { window.scrollTo(0, y); });
            }
            url.searchParams.delete('_scroll');
            window.history.replaceState({}, '', url.pathname + (url.search ? url.search : '') + url.hash);
        } catch (e) {
            // no-op
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        setupForms();
        restoreScroll();
    });
})();
