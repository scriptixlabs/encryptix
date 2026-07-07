/* strio docs — light interactions (no dependencies) */
(function () {
  'use strict';

  // ── Mobile nav toggle ─────────────────────────────────────────────
  var toggle = document.querySelector('.nav-toggle');
  var links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', function () {
      links.classList.toggle('open');
    });
  }

  // ── Copy buttons on code blocks ───────────────────────────────────
  function makeCopyButton(getText) {
    var btn = document.createElement('button');
    btn.className = 'code-copy';
    btn.type = 'button';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      var text = getText();
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1600);
      });
    });
    return btn;
  }

  document.querySelectorAll('.content pre, .terminal').forEach(function (pre) {
    if (pre.querySelector('.code-copy')) return;
    var codeEl = pre.querySelector('code, pre');
    pre.style.position = pre.style.position || 'relative';
    pre.appendChild(
      makeCopyButton(function () {
        return (codeEl || pre).innerText.trim();
      })
    );
  });

  // ── Inline install copy button ────────────────────────────────────
  document.querySelectorAll('.install .copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var cmd = btn.getAttribute('data-copy') || '';
      navigator.clipboard.writeText(cmd).then(function () {
        var original = btn.textContent;
        btn.textContent = '✓ copied';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove('copied');
        }, 1600);
      });
    });
  });

  // ── Reveal-on-scroll ──────────────────────────────────────────────
  var revealEls = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && revealEls.length) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add('in');
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12 }
    );
    revealEls.forEach(function (el) {
      io.observe(el);
    });
  } else {
    revealEls.forEach(function (el) {
      el.classList.add('in');
    });
  }

  // ── Highlight active sidebar link on scroll into a section ────────
  // (sidebar links already get .active server-side per page)
})();
