(function () {
  const $ = (id) => document.getElementById(id);

  const els = {
    libraryStatus: $("libraryStatus"),
    generateKeys: $("generateKeys"),
    encryptMessage: $("encryptMessage"),
    decryptMessage: $("decryptMessage"),
    inspectKey: $("inspectKey"),
  };

  function setResult(id, message, type) {
    const node = $(id);
    node.textContent = message;
    node.className = `result ${type || ""}`.trim();
  }

  function requireValue(id, label) {
    const value = $(id).value.trim();
    if (!value) {
      throw new Error(`${label} is required.`);
    }
    return value;
  }

  function downloadText(text, filename) {
    if (!text.trim()) return;
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url); 
  }

  async function copyText(id) {
    const value = $(id).value;
    if (!value.trim()) return;
    await navigator.clipboard.writeText(value);
  }

  async function readFileIntoInput(fileInputId, targetId) {
    const input = $(fileInputId);
    const file = input.files && input.files[0];
    if (!file) return;
    $(targetId).value = await file.text();
    input.value = "";
  }

  function setBusy(button, busy, label) {
    button.disabled = busy;
    if (busy) {
      button.dataset.originalText = button.textContent;
      button.textContent = label;
    } else if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
      delete button.dataset.originalText;
    }
  }

  async function generateKeys() {
    setBusy(els.generateKeys, true, "Generating...");
    setResult("generateResult", "", "");
    try {
      const name = requireValue("genName", "Name");
      const email = requireValue("genEmail", "Email");
      const passphrase = requireValue("genPassphrase", "Private key passphrase");
      const confirm = requireValue("genPassphraseConfirm", "Passphrase confirmation");
      const keyExpirationTime = Number($("genExpiration").value);

      if (passphrase !== confirm) {
        throw new Error("Passphrases do not match.");
      }

      const algorithm = $("genAlgorithm").value;
      const options = {
        userIDs: [{ name, email }],
        passphrase,
        keyExpirationTime,
        format: "armored",
      };

      if (algorithm === "rsa") {
        options.type = "rsa";
        options.rsaBits = 4096;
      } else {
        options.type = "ecc";
        options.curve = "curve25519";
      }

      const { privateKey, publicKey } = await openpgp.generateKey(options);
      $("publicKeyOutput").value = publicKey;
      $("privateKeyOutput").value = privateKey;
      setResult("generateResult", "Key pair generated. Store the private key and passphrase securely.", "success");
    } catch (error) {
      setResult("generateResult", error.message, "error");
    } finally {
      setBusy(els.generateKeys, false);
    }
  }

  async function unlockPrivateKey(armoredKey, passphrase) {
    const privateKey = await openpgp.readPrivateKey({ armoredKey });
    return openpgp.decryptKey({ privateKey, passphrase });
  }

  async function encryptMessage() {
    setBusy(els.encryptMessage, true, "Encrypting...");
    setResult("encryptResult", "", "");
    try {
      const publicKeyArmored = requireValue("encryptPublicKey", "Recipient public key");
      const text = requireValue("plainMessage", "Plaintext message");
      const encryptionKeys = await openpgp.readKey({ armoredKey: publicKeyArmored });
      const signPrivateKey = $("signPrivateKey").value.trim();
      const signPassphrase = $("signPassphrase").value;

      const options = {
        message: await openpgp.createMessage({ text }),
        encryptionKeys,
        format: "armored",
      };

      if (signPrivateKey) {
        if (!signPassphrase) {
          throw new Error("Signing passphrase is required when a signing private key is provided.");
        }
        options.signingKeys = await unlockPrivateKey(signPrivateKey, signPassphrase);
      }

      $("encryptedOutput").value = await openpgp.encrypt(options);
      setResult("encryptResult", signPrivateKey ? "Message encrypted and signed." : "Message encrypted.", "success");
    } catch (error) {
      setResult("encryptResult", error.message, "error");
    } finally {
      setBusy(els.encryptMessage, false);
    }
  }

  async function decryptMessage() {
    setBusy(els.decryptMessage, true, "Decrypting...");
    setResult("decryptResult", "", "");
    try {
      const armoredMessage = requireValue("encryptedInput", "Encrypted message");
      const privateKeyArmored = requireValue("decryptPrivateKey", "Recipient private key");
      const passphrase = requireValue("decryptPassphrase", "Private key passphrase");
      const verificationKeyArmored = $("verifyPublicKey").value.trim();

      const privateKey = await unlockPrivateKey(privateKeyArmored, passphrase);
      const message = await openpgp.readMessage({ armoredMessage });
      const options = {
        message,
        decryptionKeys: privateKey,
        format: "utf8",
      };

      if (verificationKeyArmored) {
        options.verificationKeys = await openpgp.readKey({ armoredKey: verificationKeyArmored });
        options.expectSigned = true;
      }

      const result = await openpgp.decrypt(options);
      $("decryptedOutput").value = result.data;

      if (verificationKeyArmored) {
        await Promise.all(result.signatures.map((signature) => signature.verified));
        setResult("decryptResult", "Message decrypted and signature verified.", "success");
      } else {
        setResult("decryptResult", "Message decrypted.", "success");
      }
    } catch (error) {
      setResult("decryptResult", error.message, "error");
    } finally {
      setBusy(els.decryptMessage, false);
    }
  }

  function formatDate(date) {
    if (!date) return "No expiration";
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  function addMetadata(label, value) {
    const list = $("keyMetadata");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = value || "Unavailable";
    list.append(term, detail);
  }

  async function inspectKey() {
    setBusy(els.inspectKey, true, "Inspecting...");
    setResult("inspectResult", "", "");
    $("keyMetadata").replaceChildren();
    try {
      const armoredKey = requireValue("inspectKeyInput", "Key");
      let key;
      let type = "Public";

      if (armoredKey.includes("PRIVATE KEY BLOCK")) {
        key = await openpgp.readPrivateKey({ armoredKey });
        type = "Private";
      } else {
        key = await openpgp.readKey({ armoredKey });
      }

      const userIDs = key.getUserIDs ? key.getUserIDs() : [];
      const expiration = await key.getExpirationTime();
      addMetadata("Type", type);
      addMetadata("Key ID", key.getKeyID().toHex().toUpperCase());
      addMetadata("Fingerprint", key.getFingerprint().toUpperCase());
      addMetadata("Users", userIDs.join(", "));
      addMetadata("Created", formatDate(key.getCreationTime()));
      addMetadata("Expires", expiration === Infinity ? "Does not expire" : formatDate(expiration));
      setResult("inspectResult", "Key parsed successfully.", "success");
    } catch (error) {
      setResult("inspectResult", error.message, "error");
    } finally {
      setBusy(els.inspectKey, false);
    }
  }

  function wireUi() {
    document.querySelectorAll(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((node) => node.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((node) => node.classList.remove("active"));
        tab.classList.add("active");
        $(tab.dataset.tab).classList.add("active");
      });
    });

    document.querySelectorAll("[data-copy]").forEach((button) => {
      button.addEventListener("click", () => copyText(button.dataset.copy));
    });

    document.querySelectorAll("[data-download]").forEach((button) => {
      button.addEventListener("click", () => {
        downloadText($(button.dataset.download).value, button.dataset.filename);
      });
    });

    document.querySelectorAll("[data-clear]").forEach((button) => {
      button.addEventListener("click", () => {
        $(button.dataset.clear).value = "";
      });
    });

    $("publicKeyFile").addEventListener("change", () => readFileIntoInput("publicKeyFile", "encryptPublicKey"));
    $("messageFile").addEventListener("change", () => readFileIntoInput("messageFile", "encryptedInput"));
    $("inspectKeyFile").addEventListener("change", () => readFileIntoInput("inspectKeyFile", "inspectKeyInput"));

    els.generateKeys.addEventListener("click", generateKeys);
    els.encryptMessage.addEventListener("click", encryptMessage);
    els.decryptMessage.addEventListener("click", decryptMessage);
    els.inspectKey.addEventListener("click", inspectKey);
  }

  window.addEventListener("load", () => {
    wireUi();
    if (window.openpgp) {
      els.libraryStatus.textContent = `OpenPGP.js ${openpgp.version || "loaded"}`;
      els.libraryStatus.classList.add("ready");
    } else {
      els.libraryStatus.textContent = "OpenPGP.js failed to load";
      els.libraryStatus.classList.add("error");
      [els.generateKeys, els.encryptMessage, els.decryptMessage, els.inspectKey].forEach((button) => {
        button.disabled = true;
      });
    }
  });
})();
