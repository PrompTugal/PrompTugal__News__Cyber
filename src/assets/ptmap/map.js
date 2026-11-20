// Draws the shared map (ptmap, vendored and pinned) in the home page's "Where" section. cyber.b@PrompTugal.dinis, 20 Nov 2026.
// No places yet: every figure on this site is worldwide, and the Portugal lens is not built. London links to what this site
// has for London; there is no EU inset while the EU source (ENISA's EUVD) is paused.
(function () {
  var el = document.getElementById('ptmap');
  if (!el || !window.PTMap) return;
  window.PTMap.render(el, {
    places: [],
    london: { href: 'https://cyber.promptugal.news/london/' },
    label: 'Portugal, with London small: this site has no figures for a single place yet'
  });
})();
