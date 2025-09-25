// Inject favicon from local public assets to avoid 404 and align branding
(function() {
  try {
    var link = document.createElement('link');
    link.rel = 'icon';
    link.type = 'image/x-icon';
    link.href = '/public/favicon.ico';
    document.head.appendChild(link);
  } catch (e) {
    console.warn('Failed to inject favicon:', e);
  }
})();

// Debug marker to confirm custom JS is loaded
(function() {
  try {
    console.log('[CWE ChatBot] custom.js loaded');
  } catch (e) {}
})();

// Inject critical CSS overrides to force menu/dialog/header text visibility
(function() {
  try {
    var css = `
      header *, .MuiAppBar-root *, [class*="cl-header"] * {
        color: var(--primary-foreground) !important;
        -webkit-text-fill-color: var(--primary-foreground) !important;
      }
      [role='menu'], [role='menu'] *, li[role='menuitem'], li[role='menuitem'] * {
        color: var(--foreground) !important;
        -webkit-text-fill-color: var(--foreground) !important;
      }
      .MuiDialog-root *, .MuiDialog-paper *, .MuiDialogActions-root *, .MuiPopover-paper * {
        color: var(--foreground) !important;
        -webkit-text-fill-color: var(--foreground) !important;
      }
    `;
    var style = document.createElement('style');
    style.setAttribute('data-injected-by', 'cwe-chatbot');
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
  } catch (e) {
    console.warn('Failed to inject critical CSS overrides', e);
  }
})();
