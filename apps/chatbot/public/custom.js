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
