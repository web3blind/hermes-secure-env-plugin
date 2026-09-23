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

  function buildForm(data) {
    if (!data || typeof data.label !== "string" || !Array.isArray(data.keys) || !data.keys.length) {
      throw new Error("invalid_response");
    }
    profile.textContent = data.label;
    data.keys.forEach((key, index) => {
      if (typeof key !== "string" || !key) throw new Error("invalid_response");
      const wrapper = document.createElement("div");
      wrapper.className = "field";
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.id = `secret-${index}`;
      input.type = "password";
      input.name = `secret-${index}`;
      input.autocomplete = "new-password";
      input.autocapitalize = "none";
      input.spellcheck = false;
      input.required = true;
      label.htmlFor = input.id;
      label.textContent = key;
      wrapper.append(label, input);
      fields.append(wrapper);
    });
    intro.textContent = "Enter your secrets. They are sent directly to the server, not through chat. This page does not store them in browser storage.";
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
    submit.disabled = true;
    status.textContent = "Saving…";
    const inputs = [...form.querySelectorAll("input")];
    const values = inputs.map((input) => input.value);
    try {
      await post("/submit", { token: capability, initData, values });
      disableAndClear("Secrets saved. You can close this page.");
    } catch (_) {
      disableAndClear("The save result is unconfirmed: the request was rejected or no response was received. The fields have been cleared. Check whether the keys were saved without displaying their values. Request a new link to try again.");
    } finally {
      values.fill("");
      capability = "";
      initData = "";
    }
  });

  void initialize();
})();
