(() => {
  "use strict";

  const form = document.getElementById("secret-form");
  const fields = document.getElementById("fields");
  const profile = document.getElementById("profile-label");
  const intro = document.getElementById("intro");
  const status = document.getElementById("status");
  const submit = document.getElementById("submit");
  let capability = "";
  let initData = "";
  let terminal = false;
  let vault = false;
  let codeMode = false;

  function decode(value) {
    try { return decodeURIComponent(value.replace(/\+/g, " ")); }
    catch (_) { throw new Error("Invalid link."); }
  }

  function parsePairs(text) {
    const result = new Map();
    if (!text) return result;
    for (const part of text.split("&")) {
      if (!part || !part.includes("=")) throw new Error("Invalid link.");
      const split = part.indexOf("=");
      const key = decode(part.slice(0, split));
      const value = decode(part.slice(split + 1));
      if (!key || result.has(key)) throw new Error("Invalid link.");
      result.set(key, value);
    }
    return result;
  }

  function launchData() {
    const query = parsePairs(location.search.slice(1));
    const rawFragment = location.hash.slice(1);
    const parts = rawFragment ? rawFragment.split("&") : [];
    let token = "";
    let fragmentPairs;
    if (parts.length && !parts[0].includes("=")) {
      token = decode(parts.shift());
      fragmentPairs = parsePairs(parts.join("&"));
    } else {
      fragmentPairs = parsePairs(rawFragment);
      token = fragmentPairs.get("token") || fragmentPairs.get("capability") || "";
    }
    const fragmentInit = fragmentPairs.get("tgWebAppData") || "";
    const queryInit = query.get("tgWebAppData") || "";
    if (fragmentInit && queryInit && fragmentInit !== queryInit) {
      throw new Error("Launch data does not match.");
    }
    if (!token) throw new Error("The link is incomplete or damaged.");
    // Launch parameters are held only in this closure, never Web Storage/history.
    history.replaceState(null, "", location.pathname);
    return { token, initData: fragmentInit || queryInit };
  }

  function disableAndClear(message) {
    terminal = true;
    for (const input of form.querySelectorAll("input")) {
      input.value = "";
      input.disabled = true;
    }
    submit.disabled = true;
    status.textContent = message;
    status.focus();
  }

  async function post(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "request_failed");
    return data;
  }

  const VAULT_KEYS = ["Username", "Password", "Authenticator key (optional)"];
  const OPTIONAL_KEY_HINT = "Optional. Paste the 2FA setup key the site showed when you switched on the authenticator app (letters and digits, spaces allowed), or its otpauth:// link. Leave empty when the site uses no authenticator app. The key is stored in the encrypted Vault so future codes are generated there instead of being typed in chat.";

  function looksLikeAuthenticatorKey(value) {
    const trimmed = value.trim();
    if (!trimmed) return true;
    if (/^otpauth:\/\//i.test(trimmed)) return /^otpauth:\/\/totp\//i.test(trimmed);
    const seed = trimmed.replace(/[\s-]/g, "").toUpperCase().replace(/=+$/, "");
    return seed.length > 0 && !/[^A-Z2-7]/.test(seed);
  }

  function buildForm(data) {
    if (!data || typeof data.label !== "string" || !Array.isArray(data.keys) || !data.keys.length) {
      throw new Error("invalid_response");
    }
    profile.textContent = data.label;
    vault = data.kind === 'browser_vault';
    codeMode = data.kind === 'browser_code';
    if (codeMode && (data.keys.length !== 1 || data.keys[0] !== 'Verification code')) throw new Error('invalid_response');
    // Accept the legacy two-field answer as well: during a deploy the assets can be newer than the
    // loaded backend, and the form must keep working until the gateway restarts.
    const expectedKeys = vault && data.keys.length === 2 ? VAULT_KEYS.slice(0, 2) : VAULT_KEYS;
    if (vault && (data.keys.length !== expectedKeys.length
        || expectedKeys.some((key, index) => data.keys[index] !== key))) throw new Error('invalid_response');
    data.keys.forEach((key, index) => {
      if (typeof key !== "string" || !key) throw new Error("invalid_response");
      const optional = vault && index === VAULT_KEYS.length - 1;
      const wrapper = document.createElement("div");
      wrapper.className = "field";
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.id = `secret-${index}`;
      input.type = vault && index === 0 ? "text" : "password";
      input.name = `secret-${index}`;
      // This is a one-time transfer form, not account registration on this host.
      // new-password can open Chrome's password generator and intercept navigation.
      // Browsers may still override off; keep native masked inputs and Tab behavior.
      input.autocomplete = "off";
      input.autocapitalize = "none";
      input.spellcheck = false;
      input.required = !optional;
      if (codeMode) { input.minLength = 4; input.maxLength = 16; input.pattern = '[A-Za-z0-9]{4,16}'; }
      label.htmlFor = input.id;
      label.textContent = key;
      wrapper.append(label, input);
      if (optional) {
        const hint = document.createElement("p");
        hint.className = "hint";
        hint.id = `${input.id}-hint`;
        hint.textContent = OPTIONAL_KEY_HINT;
        input.setAttribute("aria-describedby", hint.id);
        input.addEventListener("input", () => {
          input.removeAttribute("aria-invalid");
          input.setAttribute("aria-describedby", hint.id);
          if (status.dataset.validation === "authenticator") {
            status.textContent = "";
            delete status.dataset.validation;
          }
        });
        wrapper.append(hint);
      }
      fields.append(wrapper);
    });
    intro.textContent = codeMode ? "Enter only the one-time code from email, SMS, or your authenticator app. The code fills the captured browser page; this does not submit the site's form. Never type it in chat. Anyone with this link can use it." : vault ? "Save a login for this exact site. Anyone with this link can submit it. Saving does not fill the browser or sign in. Enter credentials only here, never in chat." : "Enter your secrets. They are sent directly to the server, not through chat. This page does not store them in browser storage.";
    form.hidden = false;
    form.querySelector("input").focus();
  }

  async function initialize() {
    try {
      const launch = launchData();
      capability = launch.token;
      initData = launch.initData;
      const data = await post("/session", { token: capability, initData });
      buildForm(data);
    } catch (_) {
      capability = "";
      initData = "";
      disableAndClear("This link is invalid or has expired. Request a new link from the bot.");
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (terminal) return;
    const inputs = [...form.querySelectorAll("input")];
    const values = inputs.map((input) => input.value);
    if (vault && inputs.length === VAULT_KEYS.length && !looksLikeAuthenticatorKey(values[VAULT_KEYS.length - 1])) {
      // Keep the one-time link usable: a typo in the optional field must not burn the capability.
      values.fill("");
      const invalid = inputs[VAULT_KEYS.length - 1];
      invalid.setAttribute("aria-invalid", "true");
      invalid.setAttribute("aria-describedby", `${invalid.id}-hint status`);
      status.dataset.validation = "authenticator";
      status.textContent = "The authenticator key looks wrong. Use the setup key (letters and digits 2-7, spaces allowed) or the otpauth:// link, or leave the field empty.";
      invalid.focus();
      return;
    }
    submit.disabled = true;
    status.textContent = codeMode ? "Filling…" : "Saving…";
    try {
      const response = await post("/submit", { token: capability, initData, values });
      if (codeMode && response.filled !== true) throw new Error('fill_unconfirmed');
      disableAndClear(codeMode ? "Code filled in the browser. Check the site and submit its form if needed. You can close this page." : vault ? "Login saved to the encrypted Vault. The browser has not been filled or signed in. You can close this page." : "Secrets saved. You can close this page.");
    } catch (error) {
      const rejectedKey = vault && error && error.message === "invalid_authenticator_key";
      disableAndClear(codeMode ? "Code fill was not confirmed. Fields were cleared. Check the browser before requesting a new link." : rejectedKey ? "The authenticator key was rejected, so nothing was saved. Check the setup key, then request a new link." : vault ? "The save result is unconfirmed. Fields were cleared. Check Vault metadata without revealing the password; request a new link only if no item was saved." : "The save result is unconfirmed: the request was rejected or no response was received. The fields have been cleared. Check whether the keys were saved without displaying their values. Request a new link to try again.");
    } finally {
      values.fill("");
      capability = "";
      initData = "";
    }
  });

  void initialize();
})();
