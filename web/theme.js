// Applies the saved theme before the page paints, so a light-mode user never sees a dark flash.
// Loaded synchronously from <head>; the CSP forbids inline scripts, hence its own file.
(function () {
  try {
    const saved = localStorage.getItem("monitor.theme.v1");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
    if (localStorage.getItem("monitor.sidebar.v1") === "collapsed") document.documentElement.classList.add("sidebar-collapsed");
  } catch (e) { /* storage blocked: follow the system preference */ }
})();
