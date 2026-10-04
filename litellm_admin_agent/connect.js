/* The server creates and binds the OAuth request before the browser leaves. */
(() => {
  const destination = document.querySelector("a[data-oauth-redirect]");
  if (destination) window.location.replace(destination.href);
})();
