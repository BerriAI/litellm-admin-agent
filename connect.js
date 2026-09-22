/* Progressive enhancement: native forms still work when scripts/popups are off. */
(() => {
  const main = document.getElementById("connection");
  let busy = false;
  let timer;

  const schedule = () => {
    clearTimeout(timer);
    if (main.querySelector('form[data-sso-action="check"]')) {
      timer = setTimeout(() => submit(main.querySelector("form"), "check", true), 3000);
    }
  };

  async function submit(form, action, automatic = false) {
    if (busy || !form) return;
    busy = true;
    clearTimeout(timer);
    // Open synchronously in the click event so normal popup blockers allow it.
    // The gateway (not this app) selects Google, Okta, or its configured IdP.
    const popup = action === "start" ? window.open("about:blank", "_blank") : null;
    if (popup) popup.opener = null;
    try {
      const body = new URLSearchParams(new FormData(form));
      body.set("action", action);
      const response = await fetch(location.pathname, {
        method: "POST", body, credentials: "same-origin", redirect: "error",
      });
      const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
      const next = parsed.getElementById("connection");
      if (!next) throw new Error("Unexpected connection response");
      const signIn = next.querySelector("a[data-sso-link]");
      if (popup) {
        if (response.ok && signIn) popup.location.replace(signIn.href);
        else popup.close();
      }
      // Do not disrupt someone selecting/copying their code on each poll.
      if (!(automatic && response.ok && next.querySelector('form[data-sso-action="check"]'))) {
        main.replaceChildren(...next.childNodes);
        document.title = parsed.title;
      }
      if (response.ok) schedule();
    } catch {
      if (popup) popup.close();
      // A failed request may have consumed the one-use login. Leave an
      // explicit retry available; never silently keep retrying after a fault.
      let notice = main.querySelector("[data-connection-error]");
      if (!notice) {
        notice = document.createElement("p");
        notice.dataset.connectionError = "true";
        main.append(notice);
      }
      notice.textContent = "Couldn’t finish connecting. Try the button again, or send connect in Slack for a new sign-in link.";
    } finally {
      busy = false;
    }
  }

  main.addEventListener("submit", event => {
    const form = event.target;
    if (!form.matches("form[data-sso-action]")) return;
    event.preventDefault();
    submit(form, form.dataset.ssoAction === "start" ? "start" : "check");
  });
  schedule();
})();
