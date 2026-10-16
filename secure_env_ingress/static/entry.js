(() => {
  "use strict";

  const form = document.getElementById("secret-form");
  const fields = document.getElementById("fields");
  const profile = document.getElementById("profile-label");
  const intro = document.getElementById("intro");
  const operationSummary = document.getElementById("operation-summary");
  const status = document.getElementById("status");
  const submit = document.getElementById("submit");
  let capability = "";
  let initData = "";
  let terminal = false;
  let vault = false;
  let codeMode = false;
  let paymentMode = false;
  let operationMode = false;
  let targetPolicy = null;
  let confirmation = null;
  const controls = [];

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
    for (const input of controls) {
      input.value = "";
      input.disabled = true;
    }
    submit.disabled = true;
    if (confirmation) confirmation.disabled = true;
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

  const PAYMENT_KEYS = ["Card number", "Cardholder name (optional)", "Expiry month", "Expiry year", "CVC", "Billing postal code (optional)"];
  const VAULT_KEYS = ["Username", "Password", "Authenticator key (optional)"];
  const OPTIONAL_KEY_HINT = "Optional. Paste the 2FA setup key the site showed when you switched on the authenticator app (letters and digits, spaces allowed), or its otpauth:// link. Leave empty when the site uses no authenticator app. The key is stored in the encrypted Vault so future codes are generated there instead of being typed in chat.";

  function looksLikeAuthenticatorKey(value) {
    const trimmed = value.trim();
    if (!trimmed) return true;
    if (/^otpauth:\/\//i.test(trimmed)) return /^otpauth:\/\/totp\//i.test(trimmed);
    const seed = trimmed.replace(/[\s-]/g, "").toUpperCase().replace(/=+$/, "");
    return seed.length > 0 && !/[^A-Z2-7]/.test(seed);
  }

  // The trusted session carries the packaged Unicode14 table, not the browser UCD.
  // Pin the canonical payload so omitted, changed or malformed ranges fail closed.
  async function unicodeContract(data) {
    if (!data || Object.keys(data).sort().join(',') !== 'forbidden_ranges,version' || data.version !== 'unicode-14.0.0-C-Zl-Zp-v1' || !Array.isArray(data.forbidden_ranges)) throw new Error('invalid_response');
    const canonical = JSON.stringify({forbidden_ranges: data.forbidden_ranges, version: data.version});
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    if (Array.from(new Uint8Array(hash), x => x.toString(16).padStart(2, '0')).join('') !== 'e83baed34ac406005cd17ef0433d0bee688fa67f6a3e6e807998555b7849acba') throw new Error('invalid_response');
    return data.forbidden_ranges;
  }

  function validTargetValue(value) {
    if ([...value].length !== targetPolicy.exact_length) return false;
    if (targetPolicy.charset === 'ascii_digits') return /^[0-9]+$/.test(value);
    if (targetPolicy.charset === 'ascii_printable_no_space') return /^[!-~]+$/.test(value);
    return [...value].every(c => {
      if (c === '\n') return targetPolicy.multiline;
      const cp = c.codePointAt(0);
      return c !== '\r' && !targetPolicy.forbiddenRanges.some(([lo, hi]) => lo <= cp && cp <= hi);
    });
  }

  async function buildForm(data) {
    if (!data || typeof data.label !== "string" || !Array.isArray(data.keys) || !data.keys.length) {
      throw new Error("invalid_response");
    }
    profile.textContent = data.label;
    vault = data.kind === 'browser_vault';
    codeMode = data.kind === 'browser_code';
    paymentMode = data.kind === 'browser_payment';
    if (paymentMode && (data.keys.length !== PAYMENT_KEYS.length || PAYMENT_KEYS.some((key, i) => data.keys[i] !== key))) throw new Error('invalid_response');
    operationMode = data.kind === 'secure_operation';
    if (operationMode) {
      if (data.keys.length !== 1 || data.keys[0] !== 'Secret' || typeof data.summary !== 'string' || !data.summary.trim()) throw new Error('invalid_response');
      operationSummary.textContent = data.summary;
      operationSummary.hidden = false;
      submit.textContent = 'Run operation';
    }
    if (codeMode && data.target) {
      const t = data.target, v = t.validation;
      if (t.version !== 1 || t.purpose !== 'transient_code' || t.confirmation_required !== true || !v || !Number.isInteger(v.exact_length) || v.exact_length < 1 || v.exact_length > 100 || typeof v.multiline !== 'boolean' || !['ascii_digits','ascii_printable_no_space','unicode_text'].includes(v.charset)) throw new Error('invalid_response');
      if (!['single', 'ordered_cells', 'indexed_cells'].includes(t.layout) || !Number.isInteger(t.count) || t.count < 1 || t.count > 100 || (t.layout === 'single' ? t.count !== 1 : v.exact_length !== t.count) || (v.multiline && (t.layout !== 'single' || v.charset !== 'unicode_text'))) throw new Error('invalid_response');
      const forbiddenRanges = v.charset === 'unicode_text' ? await unicodeContract(t.unicode_contract) : null;
      targetPolicy = {...v, forbiddenRanges};
    }
    if (codeMode && (data.keys.length !== 1 || data.keys[0] !== (targetPolicy ? 'Transient verification code' : 'Verification code'))) throw new Error('invalid_response');
    // Accept the legacy two-field answer as well: during a deploy the assets can be newer than the
    // loaded backend, and the form must keep working until the gateway restarts.
    const expectedKeys = vault && data.keys.length === 2 ? VAULT_KEYS.slice(0, 2) : VAULT_KEYS;
    if (vault && (data.keys.length !== expectedKeys.length
        || expectedKeys.some((key, index) => data.keys[index] !== key))) throw new Error('invalid_response');
    data.keys.forEach((key, index) => {
      if (typeof key !== "string" || !key) throw new Error("invalid_response");
      const optional = (vault && index === VAULT_KEYS.length - 1) || (paymentMode && (index === 1 || index === 5));
      const wrapper = document.createElement("div");
      wrapper.className = "field";
      const label = document.createElement("label");
      const input = document.createElement(targetPolicy?.multiline ? "textarea" : "input");
      input.id = `secret-${index}`;
      if (input.tagName === 'INPUT') input.type = (vault && index === 0) || (paymentMode && index !== 0 && index !== 4) ? "text" : "password";
      input.name = `secret-${index}`;
      // This is a one-time transfer form, not account registration on this host.
      // new-password can open Chrome's password generator and intercept navigation.
      // Browsers may still override off; keep native masked inputs and Tab behavior.
      input.autocomplete = "off";
      input.autocapitalize = "none";
      input.spellcheck = false;
      input.required = !optional;
      if (paymentMode) {
        input.maxLength = [19, 120, 2, 4, 4, 32][index];
        if ([0, 2, 3, 4].includes(index)) input.inputMode = 'numeric';
        if (index === 0) { input.minLength = 12; input.pattern = '[0-9]{12,19}'; }
        if (index === 2) input.pattern = '(0?[1-9]|1[0-2])';
        if (index === 3) input.pattern = '[0-9]{4}';
        if (index === 4) { input.minLength = 3; input.pattern = '[0-9]{3,4}'; }
      }
      if (codeMode) {
        input.minLength = targetPolicy ? targetPolicy.exact_length : 4;
        input.maxLength = targetPolicy ? targetPolicy.exact_length * (targetPolicy.charset === 'unicode_text' ? 2 : 1) : 16;
        if (!targetPolicy) input.pattern = '[!-~]{4,16}';
        else if (targetPolicy.charset === 'ascii_digits') input.pattern = '[0-9]{'+targetPolicy.exact_length+'}';
        else if (targetPolicy.charset === 'ascii_printable_no_space') input.pattern = '[!-~]{'+targetPolicy.exact_length+'}';
      }
      label.htmlFor = input.id;
      label.textContent = key;
      controls.push(input);
      wrapper.append(label, input);
      if (optional && vault) {
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
    intro.textContent = paymentMode ? "Save a payment card for this exact HTTPS origin. Card number and CVC are encrypted in the native Vault. Cardholder name and billing postal code are optional. Enter digits only for number, month, four-digit year and CVC. Saving does not fill a checkout or authorize any payment; later native filling requires your separate confirmation. Anyone with this link can submit it. Never send card details in chat." : operationMode ? "Review the operation and target below. Enter the secret only if you intend to authorize this exact action. Anyone with this link can execute it; this page cannot verify who opened the link. The secret is not saved by this form." : codeMode ? "Enter only the one-time code from email, SMS, or your authenticator app. The code fills the captured browser page; this does not submit the site's form. Never type it in chat. Anyone with this link can use it." : vault ? "Save a login for this exact site. Anyone with this link can submit it. Saving does not fill the browser or sign in. Enter credentials only here, never in chat." : "Enter your secrets. They are sent directly to the server, not through chat. This page does not store them in browser storage.";
    if (targetPolicy) {
      operationSummary.textContent = `Transient verification code; ${data.target.layout}; ${data.target.count} retained field(s); exactly ${targetPolicy.exact_length} Unicode scalars; ${targetPolicy.charset}. ${targetPolicy.multiline ? 'Multiline entry is visible, not password-masked. LF is preserved.' : 'Single-line entry.'} Filling can trigger site actions; no Submit is clicked.`;
      operationSummary.hidden = false;
      const wrapper = document.createElement('label');
      confirmation = document.createElement('input'); confirmation.type = 'checkbox'; confirmation.required = true;
      wrapper.append(confirmation, document.createTextNode(' I confirm this is the transient verification code for the exact site shown above, not a password, card, API key or recovery seed. Filling may trigger site input handlers; no Submit is clicked.'));
      fields.append(wrapper);
    }
    form.hidden = false;
    controls[0].focus();
  }

  async function initialize() {
    try {
      const launch = launchData();
      capability = launch.token;
      initData = launch.initData;
      const data = await post("/session", { token: capability, initData });
      await buildForm(data);
    } catch (_) {
      capability = "";
      initData = "";
      disableAndClear("This link is invalid or has expired. Request a new link from the bot.");
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (terminal) return;
    const inputs = controls;
    const values = inputs.map((input) => input.value);
    if (targetPolicy && (!confirmation?.checked || !validTargetValue(values[0]))) { values.fill(''); status.textContent = 'Confirm the transient-code purpose and enter the declared exact length and format.'; return; }
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
    status.textContent = operationMode ? "Running…" : codeMode ? "Filling…" : "Saving…";
    try {
      const response = await post("/submit", { token: capability, initData, values, ...(targetPolicy ? {confirmed: confirmation.checked} : {}) });
      if (codeMode && response.filled !== true) throw new Error('fill_unconfirmed');
      if (paymentMode && response.saved !== true) throw new Error('save_unconfirmed');
      if (operationMode && response.completed !== true) throw new Error('operation_unconfirmed');
      disableAndClear(paymentMode ? "Card saved to the encrypted Vault. No checkout was filled and no payment was authorized. You can close this page." : operationMode ? "Operation reported complete. You can close this page." : codeMode ? "Code filled in the browser. Check the site and submit its form if needed. You can close this page." : vault ? "Login saved to the encrypted Vault. The browser has not been filled or signed in. You can close this page." : "Secrets saved. You can close this page.");
    } catch (error) {
      const rejectedKey = vault && error && error.message === "invalid_authenticator_key";
      disableAndClear(paymentMode ? "Card storage was rejected or unconfirmed. Fields were cleared. Check native Vault metadata without exposing card details before requesting another link." : operationMode ? "The operation outcome is unknown or rejected. Fields were cleared. Verify the target independently before requesting another link; do not retry blindly." : codeMode ? "Code fill was not confirmed. Fields were cleared. Check the browser before requesting a new link." : rejectedKey ? "The authenticator key was rejected, so nothing was saved. Check the setup key, then request a new link." : vault ? "The save result is unconfirmed. Fields were cleared. Check Vault metadata without revealing the password; request a new link only if no item was saved." : "The save result is unconfirmed: the request was rejected or no response was received. The fields have been cleared. Check whether the keys were saved without displaying their values. Request a new link to try again.");
    } finally {
      values.fill("");
      capability = "";
      initData = "";
    }
  });

  void initialize();
})();
