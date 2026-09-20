/*
  PRIVATE BACKUP VAULT
  --------------------
  No password or plaintext backup is stored in this source code.

  Encryption:
  - AES-256-GCM
  - PBKDF2-SHA-256
  - 600,000 iterations
  - Random 256-bit salt
  - Random 96-bit IV

  The encrypted JSON can safely be exported and moved to another computer.
  NEVER put the plaintext backup codes into this repository.
*/

const STORAGE_KEY = "private_backup_vault_v1";

const $ = id => document.getElementById(id);

let masterPassword = null;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function showMessage(text, type = "") {
  const el = $("message");
  el.textContent = text;
  el.className = `message show ${type}`;
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function bytesFromB64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000,
      hash: "SHA-256"
    },
    material,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBackup(text, password) {
  const salt = randomBytes(32);
  const iv = randomBytes(12);

  const key = await deriveKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    encoder.encode(text)
  );

  return {
    format: "private-backup-vault",
    version: 1,
    algorithm: "AES-256-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: 600000,
    salt: b64(salt),
    iv: b64(iv),
    ciphertext: b64(ciphertext),
    createdAt: new Date().toISOString()
  };
}

async function decryptBackup(vault, password) {
  if (
    vault.format !== "private-backup-vault" ||
    vault.version !== 1 ||
    vault.algorithm !== "AES-256-GCM" ||
    vault.kdf !== "PBKDF2-SHA256" ||
    vault.iterations !== 600000
  ) {
    throw new Error("Format backup tidak dikenali.");
  }

  const salt = bytesFromB64(vault.salt);
  const iv = bytesFromB64(vault.iv);

  const key = await deriveKey(password, salt);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    bytesFromB64(vault.ciphertext)
  );

  return decoder.decode(plaintext);
}

function saveLocal(vault) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
}

function getLocal() {
  const value = localStorage.getItem(STORAGE_KEY);
  return value ? JSON.parse(value) : null;
}

function removeLocal() {
  localStorage.removeItem(STORAGE_KEY);
}

function showSetup() {
  $("setup").classList.remove("hidden");
  $("unlock").classList.add("hidden");
  $("vault").classList.add("hidden");
}

function showUnlock() {
  $("setup").classList.add("hidden");
  $("unlock").classList.remove("hidden");
  $("vault").classList.add("hidden");
}

function showVault() {
  $("setup").classList.add("hidden");
  $("unlock").classList.add("hidden");
  $("vault").classList.remove("hidden");
}

function clearPasswordFields() {
  $("newPassword").value = "";
  $("confirmPassword").value = "";
  $("password").value = "";
}

function lock() {
  masterPassword = null;
  $("backup").value = "";
  clearPasswordFields();
  showUnlock();
  showMessage("Vault dikunci.");
}

$("createBtn").addEventListener("click", async () => {
  const password = $("newPassword").value;
  const confirm = $("confirmPassword").value;

  if (password.length < 16) {
    return showMessage(
      "Gunakan master password minimal 16 karakter.",
      "error"
    );
  }

  if (password !== confirm) {
    return showMessage(
      "Konfirmasi password tidak cocok.",
      "error"
    );
  }

  masterPassword = password;
  showVault();
  showMessage(
    "Vault dibuat. Password ini tidak disimpan oleh aplikasi.",
    "ok"
  );
  clearPasswordFields();
});

$("unlockBtn").addEventListener("click", async () => {
  const password = $("password").value;
  const vault = getLocal();

  if (!vault) {
    return showSetup();
  }

  try {
    const plaintext = await decryptBackup(vault, password);

    masterPassword = password;
    $("backup").value = plaintext;

    showVault();
    showMessage("Vault berhasil dibuka.", "ok");
    $("password").value = "";
  } catch {
    $("password").value = "";
    showMessage("Password salah atau file backup rusak.", "error");
  }
});

$("saveBtn").addEventListener("click", async () => {
  if (!masterPassword) return;

  const text = $("backup").value;

  if (!text.trim()) {
    return showMessage("Backup tidak boleh kosong.", "error");
  }

  try {
    const encrypted = await encryptBackup(text, masterPassword);
    saveLocal(encrypted);

    showMessage(
      "Backup berhasil dienkripsi dan disimpan di browser.",
      "ok"
    );
  } catch {
    showMessage("Gagal mengenkripsi backup.", "error");
  }
});

$("exportBtn").addEventListener("click", () => {
  const vault = getLocal();

  if (!vault) {
    return showMessage("Belum ada encrypted backup.", "error");
  }

  const blob = new Blob(
    [JSON.stringify(vault, null, 2)],
    { type: "application/json" }
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = "encrypted-backup.json";
  a.click();

  URL.revokeObjectURL(url);

  showMessage(
    "Encrypted backup berhasil diexport. File ini boleh dipindahkan ke komputer lain.",
    "ok"
  );
});

$("importBtn").addEventListener("click", () => {
  $("fileInput").click();
});

$("fileInput").addEventListener("change", async event => {
  const file = event.target.files[0];

  if (!file) return;

  try {
    const text = await file.text();
    const vault = JSON.parse(text);

    if (
      vault.format !== "private-backup-vault" ||
      !vault.ciphertext ||
      !vault.salt ||
      !vault.iv
    ) {
      throw new Error("Invalid vault");
    }

    /*
      Import hanya menyimpan ciphertext.
      Tidak ada plaintext yang dikirim ke mana pun.
    */
    saveLocal(vault);

    masterPassword = null;
    $("backup").value = "";

    showUnlock();

    showMessage(
      "Encrypted backup berhasil diimport. Masukkan master password.",
      "ok"
    );
  } catch {
    showMessage("File encrypted backup tidak valid.", "error");
  }

  event.target.value = "";
});

$("deleteBtn").addEventListener("click", () => {
  if (!confirm(
    "Hapus encrypted backup dari browser ini? Pastikan Anda sudah memiliki salinan export."
  )) {
    return;
  }

  removeLocal();
  masterPassword = null;
  $("backup").value = "";

  showSetup();
  showMessage("Encrypted backup dihapus dari browser.", "ok");
});

$("lockBtn").addEventListener("click", lock);

/*
  First load:
  - If ciphertext exists -> unlock.
  - If no ciphertext -> setup.
*/
if (getLocal()) {
  showUnlock();
} else {
  showSetup();
}
