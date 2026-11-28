// Applies the saved theme before the page paints, so a light-mode user never sees a dark flash.
// Loaded synchronously from <head>; the CSP forbids inline scripts, hence its own file.
(function () {
  try {
    const saved = localStorage.getItem("monitor.theme.v1");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
    // Classic or Modern: the account's choice, remembered here from the last visit so it shows at once.
    if (localStorage.getItem("monitor.ui.v1") === "modern") document.documentElement.dataset.ui = "modern";
    if (localStorage.getItem("monitor.sidebar.v1") === "collapsed") document.documentElement.classList.add("sidebar-collapsed");
  } catch (e) { /* storage blocked: follow the system preference */ }
})();
