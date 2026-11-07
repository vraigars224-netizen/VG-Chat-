import React, { useState, useEffect, useCallback, useRef } from "react";
import { storage } from "./storage";
import { auth } from "./firebase";
import { createUserWithEmailAndPassword, signInWithEmailAndPassword, sendEmailVerification, signOut } from "firebase/auth";
import { Lock, ShieldCheck, LogOut, Plus, Send, Users, MessageCircle, KeyRound, X, Fingerprint, AlertTriangle, Loader2, DoorOpen, Copy, Check, Settings, UserRound, EyeOff, ChevronLeft, Camera, Trash2 } from "lucide-react";

/* ---------------------------------------------------------------------- */
/* Crypto helpers — everything here runs client-side, in the browser.     */
/* Plaintext never leaves this tab; only ciphertext touches storage.      */
/* ---------------------------------------------------------------------- */

const enc = new TextEncoder();
const dec = new TextDecoder();

function buf2b64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b642buf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
async function sha256Hex(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function pbkdf2Bits(secret, saltBytes, iterations = 150000, length = 256) {
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" }, base, length);
}
async function aesKeyFromRaw(rawBits) {
  return crypto.subtle.importKey("raw", rawBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return { iv: buf2b64(iv), ct: buf2b64(ct) };
}
async function decryptText(key, ivB64, ctB64) {
  const iv = new Uint8Array(b642buf(ivB64));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b642buf(ctB64));
  return dec.decode(pt);
}
async function generateEcdhKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
}
function pairKeyFor(a, b) {
  return [a, b].sort().join("__");
}
function generateRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{1,4}/g).join("-");
}
function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());
}
function isValidPassword(v) {
  return v.length >= 8;
}
function normalizePhone(v) {
  return v.replace(/[\s().-]/g, "");
}
function isValidPhone(v) {
  return /^\+?[0-9]{8,15}$/.test(v);
}

/* 5x5 mirrored identicon-style fingerprint, derived from key material — lets two
   people visually confirm they share the same secret (a real safety-number pattern) */
function fingerprintGrid(hex) {
  const bytes = [];
  for (let i = 0; i < 30; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  const rows = [];
  for (let r = 0; r < 5; r++) {
    const half = bytes.slice(r * 3, r * 3 + 3);
    rows.push([...half, ...half.slice(0, 2).reverse()]);
  }
  return rows;
}

/* Crops an image file to a small square JPEG data URL — kept tiny on purpose
   since it's stored inline in the Firestore user record (no Firebase Storage
   needed). Retries at lower quality if the result is still too heavy. */
function fileToAvatarDataUrl(file, size = 160) {
  return new Promise((resolve, reject) => {
    if (!file.type.startsWith("image/")) {
      reject(new Error("not-an-image"));
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("read-failed"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("decode-failed"));
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext("2d");
        const side = Math.min(img.width, img.height);
        const sx = (img.width - side) / 2;
        const sy = (img.height - side) / 2;
        ctx.drawImage(img, sx, sy, side, side, 0, 0, size, size);
        let dataUrl = canvas.toDataURL("image/jpeg", 0.75);
        if (dataUrl.length > 220000) dataUrl = canvas.toDataURL("image/jpeg", 0.45);
        resolve(dataUrl);
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

/* ---------------------------------------------------------------------- */
/* Palette / type tokens                                                  */
/* ---------------------------------------------------------------------- */
const C = {
  bg: "#10141A",
  panel: "#171C24",
  panel2: "#1D232C",
  border: "#2A313C",
  text: "#ECEFF3",
  sub: "#8892A0",
  brass: "#C9A24B",
  brassDim: "#8A712F",
  brassSoft: "#2B2416",
  danger: "#D9736B",
  success: "#6FAE8B",
};
const MONO = "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
const SANS = "'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, sans-serif";

function FontLoader() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
      * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
      html, body { overscroll-behavior: none; }
      textarea::placeholder, input::placeholder { color: ${C.sub}; }
      ::-webkit-scrollbar { width: 8px; height: 8px; }
      ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 4px; }
      ::-webkit-scrollbar-track { background: transparent; }
      button { touch-action: manipulation; }
      input, textarea, select { font-size: 16px; }
      .coffre-root { height: 100vh; height: 100dvh; }
      .coffre-input-bar { padding-bottom: calc(16px + env(safe-area-inset-bottom)); }
      .coffre-header { padding-top: calc(14px + env(safe-area-inset-top)); }
    `}</style>
  );
}

function FingerprintGrid({ hex, size = 10 }) {
  const rows = fingerprintGrid(hex);
  return (
    <div style={{ display: "inline-grid", gridTemplateColumns: `repeat(5, ${size}px)`, gap: 2 }}>
      {rows.flat().map((v, i) => (
        <div
          key={i}
          style={{
            width: size,
            height: size,
            borderRadius: 2,
            background: v % 2 === 0 ? C.brass : C.panel2,
            opacity: v % 2 === 0 ? 0.35 + (v % 100) / 160 : 1,
            border: `1px solid ${C.border}`,
          }}
        />
      ))}
    </div>
  );
}

function Avatar({ src, label, size = 36 }) {
  if (src) {
    return (
      <img
        src={src}
        alt=""
        style={{ width: size, height: size, borderRadius: "50%", objectFit: "cover", border: `1px solid ${C.border}`, flexShrink: 0 }}
      />
    );
  }
  const initial = (label || "?").trim().charAt(0).toUpperCase();
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        background: C.brassSoft,
        border: `1px solid ${C.brassDim}`,
        color: C.brass,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: MONO,
        fontWeight: 600,
        fontSize: Math.round(size * 0.42),
        flexShrink: 0,
      }}
    >
      {initial}
    </div>
  );
}

/* ---------------------------------------------------------------------- */

export default function Coffre() {
  const [screen, setScreen] = useState("auth"); // auth | app
  const [authMode, setAuthMode] = useState("login"); // login | register
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [avatarDataUrl, setAvatarDataUrl] = useState(null);
  const [avatarError, setAvatarError] = useState("");
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [cryptoOk, setCryptoOk] = useState(true);

  const [pendingReveal, setPendingReveal] = useState(null); // {code, user} shown once after registration
  const [revealCopied, setRevealCopied] = useState(false);
  const [revealChecked, setRevealChecked] = useState(false);

  const [pendingAuth, setPendingAuth] = useState(null); // {user, recoveryCode} — waiting on email verification
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyError, setVerifyError] = useState("");
  const [verifyInfo, setVerifyInfo] = useState("");

  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotStep, setForgotStep] = useState("verify"); // verify | reset | done
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotCode, setForgotCode] = useState("");
  const [forgotNewPass, setForgotNewPass] = useState("");
  const [forgotNewPass2, setForgotNewPass2] = useState("");
  const [forgotError, setForgotError] = useState("");
  const [forgotLoading, setForgotLoading] = useState(false);
  const [forgotPrivJwk, setForgotPrivJwk] = useState(null);
  const [forgotRecord, setForgotRecord] = useState(null);

  const [currentUser, setCurrentUser] = useState(null); // {email, privateKey, pubJwk, fingerprintHex}

  // Local PIN session: keeps the app signed in on this device, unlocked by a short PIN.
  const [unlockSession, setUnlockSession] = useState(null);
  const [unlockPin, setUnlockPin] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [unlockAttempts, setUnlockAttempts] = useState(0);
  const [pinSessionEmail, setPinSessionEmail] = useState(null);
  const [pinModalOpen, setPinModalOpen] = useState(false);
  const [pinModalMode, setPinModalMode] = useState("prompt");
  const [pin1, setPin1] = useState("");
  const [pin2, setPin2] = useState("");
  const [pinSetupError, setPinSetupError] = useState("");
  const [pinSetupLoading, setPinSetupLoading] = useState(false);
  const [tab, setTab] = useState("rooms"); // rooms | dms
  const [publicRooms, setPublicRooms] = useState([]);
  const [joinedRooms, setJoinedRooms] = useState({}); // name -> {key, fingerprintHex}
  const [dmContacts, setDmContacts] = useState([]);
  const [avatarCache, setAvatarCache] = useState({}); // email -> dataUrl | null
  const [dmKeys, setDmKeys] = useState({}); // partner -> {key, fingerprintHex}
  const [activeConv, setActiveConv] = useState(null); // {type:'room', name} | {type:'dm', partner}
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState("");

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsAvatarLoading, setSettingsAvatarLoading] = useState(false);
  const [settingsAvatarError, setSettingsAvatarError] = useState("");
  const [accountCreatedAt, setAccountCreatedAt] = useState(null);

  const [modal, setModal] = useState(null); // 'createRoom' | 'joinRoom' | 'newDm' | 'fingerprint'
  const [modalName, setModalName] = useState("");
  const [modalPass, setModalPass] = useState("");
  const [modalPass2, setModalPass2] = useState("");
  const [modalError, setModalError] = useState("");
  const [modalLoading, setModalLoading] = useState(false);

  const scrollRef = useRef(null);

  const [isMobile, setIsMobile] = useState(typeof window !== "undefined" ? window.innerWidth < 768 : false);
  useEffect(() => {
    function onResize() {
      setIsMobile(window.innerWidth < 768);
    }
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    if (!window.crypto || !window.crypto.subtle) setCryptoOk(false);
  }, []);

  // On launch, a saved PIN session sends the user to the PIN screen instead of full login.
  useEffect(() => {
    try {
      const raw = localStorage.getItem("coffre_session");
      if (raw) {
        const session = JSON.parse(raw);
        setUnlockSession(session);
        setPinSessionEmail(session.email);
        setScreen((s) => (s === "auth" ? "unlock" : s));
      }
    } catch (e) {}
  }, []);

  // After login, offer to set up a PIN on this device if none is active for this account.
  useEffect(() => {
    if (screen !== "app" || !currentUser) return;
    try {
      const dismissed = localStorage.getItem("coffre_pin_dismissed:" + currentUser.email);
      if (pinSessionEmail !== currentUser.email && !dismissed) {
        setPinModalMode("prompt");
        setPin1("");
        setPin2("");
        setPinSetupError("");
        setPinModalOpen(true);
      }
    } catch (e) {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen, currentUser]);

  function isValidPin(v) {
    return /^[0-9]{4,6}$/.test(v);
  }

  async function saveLocalPin(pin) {
    const privJwk = await crypto.subtle.exportKey("jwk", currentUser.privateKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const bits = await pbkdf2Bits(pin, salt);
    const key = await aesKeyFromRaw(bits);
    const wrapped = await encryptText(key, JSON.stringify(privJwk));
    const session = {
      email: currentUser.email,
      pubJwk: currentUser.pubJwk,
      pinSalt: buf2b64(salt),
      pinWrapIv: wrapped.iv,
      pinWrapped: wrapped.ct,
    };
    localStorage.setItem("coffre_session", JSON.stringify(session));
    try {
      localStorage.removeItem("coffre_pin_dismissed:" + currentUser.email);
    } catch (e) {}
    setUnlockSession(session);
    setPinSessionEmail(currentUser.email);
  }

  async function submitPinSetup() {
    setPinSetupError("");
    if (!isValidPin(pin1)) {
      setPinSetupError("Le code doit contenir 4 à 6 chiffres.");
      return;
    }
    if (pin1 !== pin2) {
      setPinSetupError("Les deux codes ne correspondent pas.");
      return;
    }
    setPinSetupLoading(true);
    try {
      await saveLocalPin(pin1);
      setPinModalOpen(false);
      setPin1("");
      setPin2("");
    } catch (e) {
      console.error(e);
      setPinSetupError("Erreur lors de l'activation du code PIN.");
    } finally {
      setPinSetupLoading(false);
    }
  }

  function skipPinSetup() {
    try {
      if (currentUser) localStorage.setItem("coffre_pin_dismissed:" + currentUser.email, "1");
    } catch (e) {}
    setPinModalOpen(false);
  }

  function disableLocalPin() {
    try {
      localStorage.removeItem("coffre_session");
    } catch (e) {}
    setUnlockSession(null);
    setPinSessionEmail(null);
  }

  async function attemptUnlock() {
    if (!unlockSession || !unlockPin) return;
    setUnlockError("");
    setUnlockLoading(true);
    try {
      const salt = new Uint8Array(b642buf(unlockSession.pinSalt));
      const bits = await pbkdf2Bits(unlockPin, salt);
      const key = await aesKeyFromRaw(bits);
      let privJwkStr;
      try {
        privJwkStr = await decryptText(key, unlockSession.pinWrapIv, unlockSession.pinWrapped);
      } catch (e) {
        const attempts = unlockAttempts + 1;
        setUnlockAttempts(attempts);
        setUnlockError(attempts >= 5 ? "Code incorrect plusieurs fois. Utilise ton mot de passe ci-dessous." : "Code PIN incorrect.");
        setUnlockLoading(false);
        return;
      }
      const privateKey = await crypto.subtle.importKey("jwk", JSON.parse(privJwkStr), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
      const pubKeyImp = await crypto.subtle.importKey("jwk", unlockSession.pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
      const fpHex = await sha256Hex(await crypto.subtle.exportKey("raw", pubKeyImp));
      setCurrentUser({ email: unlockSession.email, phone: null, avatar: null, privateKey, pubJwk: unlockSession.pubJwk, fingerprintHex: fpHex });
      setScreen("app");
      setUnlockPin("");
      setUnlockAttempts(0);
      try {
        const rec = await storage.get("user:" + unlockSession.email, true);
        const record = JSON.parse(rec.value);
        setCurrentUser((prev) => (prev ? { ...prev, phone: record.phone || null, avatar: record.avatar || null } : prev));
      } catch (e) {}
    } catch (e) {
      console.error(e);
      setUnlockError("Erreur lors du déverrouillage.");
    } finally {
      setUnlockLoading(false);
    }
  }

  function useFullLoginInstead() {
    setUnlockPin("");
    setUnlockError("");
    setEmail(unlockSession?.email || "");
    setScreen("auth");
  }

  /* ---------------- auth ---------------- */

  async function handleAuthSubmit() {
    setAuthError("");
    if (!isValidEmail(email) || !password) {
      setAuthError("Adresse e-mail valide et mot de passe requis.");
      return;
    }
    const emailKey = email.trim().toLowerCase();
    setAuthLoading(true);
    try {
      if (authMode === "register") {
        if (!isValidPassword(password)) {
          setAuthError("Le mot de passe doit contenir au moins 8 caractères.");
          setAuthLoading(false);
          return;
        }
        const normalizedPhone = phone.trim() ? normalizePhone(phone.trim()) : null;
        if (normalizedPhone && !isValidPhone(normalizedPhone)) {
          setAuthError("Numéro de téléphone invalide (8 à 15 chiffres, ex. +33612345678).");
          setAuthLoading(false);
          return;
        }
        let existing = null;
        try {
          existing = await storage.get("user:" + emailKey, true);
        } catch (e) {}
        if (existing) {
          setAuthError("Un compte existe déjà avec cet e-mail.");
          setAuthLoading(false);
          return;
        }
        if (normalizedPhone) {
          let existingPhone = null;
          try {
            existingPhone = await storage.get("phone:" + normalizedPhone, true);
          } catch (e) {}
          if (existingPhone) {
            setAuthError("Ce numéro de téléphone est déjà associé à un compte.");
            setAuthLoading(false);
            return;
          }
        }

        // Create the Firebase Auth account solely to send a real verification e-mail —
        // the encryption keys below are entirely separate and never touch Firebase Auth.
        let cred;
        try {
          cred = await createUserWithEmailAndPassword(auth, emailKey, password);
        } catch (e) {
          if (e.code === "auth/email-already-in-use") setAuthError("Un compte existe déjà avec cet e-mail.");
          else if (e.code === "auth/weak-password") setAuthError("Mot de passe trop faible (8 caractères minimum).");
          else setAuthError("Erreur lors de la création du compte.");
          setAuthLoading(false);
          return;
        }
        try {
          await sendEmailVerification(cred.user);
        } catch (e) {}

        const keyPair = await generateEcdhKeyPair();
        const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
        const privJwkStr = JSON.stringify(privJwk);

        // wrap #1: with the password (normal login)
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const passBits = await pbkdf2Bits(password, salt);
        const passKey = await aesKeyFromRaw(passBits);
        const wrapped = await encryptText(passKey, privJwkStr);

        // wrap #2: with a one-time recovery code (used to reset the password later,
        // since the encryption key must never depend on Firebase Auth's own password store)
        const recoveryCode = generateRecoveryCode();
        const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
        const recoveryBits = await pbkdf2Bits(recoveryCode, recoverySalt);
        const recoveryKey = await aesKeyFromRaw(recoveryBits);
        const recoveryWrapped = await encryptText(recoveryKey, privJwkStr);

        const record = {
          email: emailKey,
          phone: normalizedPhone,
          avatar: avatarDataUrl || null,
          pubJwk,
          salt: buf2b64(salt),
          wrapIv: wrapped.iv,
          wrapped: wrapped.ct,
          recoverySalt: buf2b64(recoverySalt),
          recoveryWrapIv: recoveryWrapped.iv,
          recoveryWrapped: recoveryWrapped.ct,
          emailVerified: false,
          createdAt: Date.now(),
        };
        const res = await storage.set("user:" + emailKey, JSON.stringify(record), true);
        if (!res) throw new Error("save-failed");
        if (normalizedPhone) {
          await storage.set("phone:" + normalizedPhone, JSON.stringify({ email: emailKey }), true);
        }
        const rawPub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
        const fpHex = await sha256Hex(rawPub);
        const user = { email: emailKey, phone: normalizedPhone, avatar: avatarDataUrl || null, privateKey: keyPair.privateKey, pubJwk, fingerprintHex: fpHex };
        setVerifyError("");
        setVerifyInfo("");
        setPendingAuth({ user, recoveryCode });
        setScreen("verify");
      } else {
        let rec;
        try {
          rec = await storage.get("user:" + emailKey, true);
        } catch (e) {
          rec = null;
        }
        if (!rec) {
          setAuthError("Aucun compte pour cet e-mail.");
          setAuthLoading(false);
          return;
        }
        const record = JSON.parse(rec.value);
        const salt = new Uint8Array(b642buf(record.salt));
        const passBits = await pbkdf2Bits(password, salt);
        const passKey = await aesKeyFromRaw(passBits);
        let privJwkStr;
        try {
          privJwkStr = await decryptText(passKey, record.wrapIv, record.wrapped);
        } catch (e) {
          setAuthError("Mot de passe incorrect.");
          setAuthLoading(false);
          return;
        }
        const privJwk = JSON.parse(privJwkStr);
        const privateKey = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
        const pubKeyImp = await crypto.subtle.importKey("jwk", record.pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
        const rawPub = await crypto.subtle.exportKey("raw", pubKeyImp);
        const fpHex = await sha256Hex(rawPub);
        const user = { email: emailKey, phone: record.phone || null, avatar: record.avatar || null, privateKey, pubJwk: record.pubJwk, fingerprintHex: fpHex };

        if (!record.emailVerified) {
          // Get (or lazily create, for accounts predating this feature) a Firebase Auth
          // session so the "renvoyer l'e-mail" button on the verify screen can work.
          try {
            await signInWithEmailAndPassword(auth, emailKey, password);
          } catch (e) {
            if (e.code === "auth/user-not-found") {
              try {
                const cred = await createUserWithEmailAndPassword(auth, emailKey, password);
                await sendEmailVerification(cred.user);
              } catch (e2) {}
            }
          }
          setVerifyError("");
          setVerifyInfo("");
          setPendingAuth({ user, recoveryCode: null });
          setScreen("verify");
          setAuthLoading(false);
          return;
        }

        setCurrentUser(user);
        setScreen("app");
      }
    } catch (e) {
      console.error(e);
      setAuthError("Une erreur est survenue. Réessaie.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function checkEmailVerified() {
    if (!pendingAuth) return;
    setVerifyError("");
    setVerifyInfo("");
    setVerifyLoading(true);
    try {
      if (auth.currentUser) await auth.currentUser.reload();
      const verified = !!auth.currentUser?.emailVerified;
      if (!verified) {
        setVerifyError("Pas encore vérifié. Ouvre le lien reçu par e-mail (pense aux spams), puis réessaie.");
        setVerifyLoading(false);
        return;
      }
      const rec = await storage.get("user:" + pendingAuth.user.email, true);
      const record = JSON.parse(rec.value);
      await storage.set("user:" + pendingAuth.user.email, JSON.stringify({ ...record, emailVerified: true }), true);

      if (pendingAuth.recoveryCode) {
        // registration path: show the one-time recovery code before entering the app
        setRevealChecked(false);
        setRevealCopied(false);
        setPendingReveal({ code: pendingAuth.recoveryCode, user: pendingAuth.user });
      } else {
        setCurrentUser(pendingAuth.user);
        setScreen("app");
      }
      setPendingAuth((prev) => (prev ? { ...prev, verified: true } : prev));
    } catch (e) {
      console.error(e);
      setVerifyError("Erreur lors de la vérification.");
    } finally {
      setVerifyLoading(false);
    }
  }

  async function resendVerificationEmail() {
    setVerifyError("");
    setVerifyInfo("");
    setVerifyLoading(true);
    try {
      if (!auth.currentUser) throw new Error("no-session");
      await sendEmailVerification(auth.currentUser);
      setVerifyInfo("E-mail renvoyé.");
    } catch (e) {
      if (e.code === "auth/too-many-requests") setVerifyError("Trop de tentatives — réessaie dans quelques minutes.");
      else setVerifyError("Impossible de renvoyer l'e-mail pour l'instant.");
    } finally {
      setVerifyLoading(false);
    }
  }

  async function cancelVerification() {
    try {
      await signOut(auth);
    } catch (e) {}
    setPendingAuth(null);
    setVerifyError("");
    setVerifyInfo("");
    setPassword("");
    setScreen("auth");
  }

  function confirmReveal() {
    if (!pendingReveal || !revealChecked) return;
    setCurrentUser(pendingReveal.user);
    setPendingReveal(null);
    setPendingAuth(null);
    setScreen("app");
  }

  function handleLogout() {
    disableLocalPin();
    setSettingsOpen(false);
    setCurrentUser(null);
    setScreen("auth");
    setPassword("");
    setPhone("");
    setAvatarDataUrl(null);
    setAvatarError("");
    setActiveConv(null);
    setMessages([]);
    setJoinedRooms({});
    setDmKeys({});
    setAvatarCache({});
  }

  async function openSettings() {
    setSettingsOpen(true);
    setSettingsAvatarError("");
    try {
      const rec = await storage.get("user:" + currentUser.email, true);
      const record = rec ? JSON.parse(rec.value) : null;
      setAccountCreatedAt(record?.createdAt || null);
    } catch (e) {
      setAccountCreatedAt(null);
    }
  }

  async function updateOwnAvatar(dataUrlOrNull) {
    setSettingsAvatarError("");
    setSettingsAvatarLoading(true);
    try {
      const rec = await storage.get("user:" + currentUser.email, true);
      const record = JSON.parse(rec.value);
      await storage.set("user:" + currentUser.email, JSON.stringify({ ...record, avatar: dataUrlOrNull }), true);
      setCurrentUser((prev) => (prev ? { ...prev, avatar: dataUrlOrNull } : prev));
    } catch (e) {
      console.error(e);
      setSettingsAvatarError("Erreur lors de la mise à jour de la photo.");
    } finally {
      setSettingsAvatarLoading(false);
    }
  }

  async function handleSettingsAvatarFile(file) {
    setSettingsAvatarError("");
    try {
      const dataUrl = await fileToAvatarDataUrl(file);
      await updateOwnAvatar(dataUrl);
    } catch (e) {
      setSettingsAvatarError("Impossible d'utiliser cette image.");
    }
  }

  /* ---------------- forgot password ---------------- */

  function openForgot() {
    setForgotOpen(true);
    setForgotStep("verify");
    setForgotEmail(email);
    setForgotCode("");
    setForgotNewPass("");
    setForgotNewPass2("");
    setForgotError("");
    setForgotPrivJwk(null);
    setForgotRecord(null);
  }
  function closeForgot() {
    setForgotOpen(false);
  }

  async function submitForgotVerify() {
    setForgotError("");
    const emailKey = forgotEmail.trim().toLowerCase();
    if (!isValidEmail(emailKey) || !forgotCode.trim()) {
      setForgotError("E-mail et code de récupération requis.");
      return;
    }
    setForgotLoading(true);
    try {
      const rec = await storage.get("user:" + emailKey, true).catch(() => null);
      if (!rec) {
        setForgotError("Aucun compte pour cet e-mail.");
        setForgotLoading(false);
        return;
      }
      const record = JSON.parse(rec.value);
      const recoverySalt = new Uint8Array(b642buf(record.recoverySalt));
      const recoveryBits = await pbkdf2Bits(forgotCode.trim(), recoverySalt);
      const recoveryKey = await aesKeyFromRaw(recoveryBits);
      let privJwkStr;
      try {
        privJwkStr = await decryptText(recoveryKey, record.recoveryWrapIv, record.recoveryWrapped);
      } catch (e) {
        setForgotError("E-mail ou code de récupération incorrect.");
        setForgotLoading(false);
        return;
      }
      setForgotPrivJwk(privJwkStr);
      setForgotRecord({ ...record, email: emailKey });
      setForgotStep("reset");
    } catch (e) {
      console.error(e);
      setForgotError("Erreur lors de la vérification.");
    } finally {
      setForgotLoading(false);
    }
  }

  async function submitForgotReset() {
    setForgotError("");
    if (!isValidPassword(forgotNewPass)) {
      setForgotError("Le mot de passe doit contenir au moins 8 caractères.");
      return;
    }
    if (forgotNewPass !== forgotNewPass2) {
      setForgotError("Les mots de passe ne correspondent pas.");
      return;
    }
    setForgotLoading(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passBits = await pbkdf2Bits(forgotNewPass, salt);
      const passKey = await aesKeyFromRaw(passBits);
      const wrapped = await encryptText(passKey, forgotPrivJwk);
      const updated = {
        ...forgotRecord,
        salt: buf2b64(salt),
        wrapIv: wrapped.iv,
        wrapped: wrapped.ct,
      };
      await storage.set("user:" + forgotRecord.email, JSON.stringify(updated), true);
      setForgotStep("done");
    } catch (e) {
      console.error(e);
      setForgotError("Erreur lors de la réinitialisation.");
    } finally {
      setForgotLoading(false);
    }
  }

  function finishForgot() {
    setForgotOpen(false);
    setAuthMode("login");
    setEmail(forgotRecord?.email || "");
    setPassword("");
  }

  /* ---------------- rooms / dms discovery ---------------- */

  const loadRoomList = useCallback(async () => {
    try {
      const r = await storage.get("roomlist", true);
      const list = r ? JSON.parse(r.value) : [];
      setPublicRooms(list);
    } catch (e) {
      setPublicRooms([]);
    }
  }, []);

  const loadDmContacts = useCallback(async () => {
    if (!currentUser) return;
    try {
      const r = await storage.get("dmindex:" + currentUser.email, true);
      setDmContacts(r ? JSON.parse(r.value) : []);
    } catch (e) {
      setDmContacts([]);
    }
  }, [currentUser]);

  useEffect(() => {
    if (screen !== "app") return;
    loadRoomList();
    loadDmContacts();
    const id = setInterval(() => {
      loadRoomList();
      loadDmContacts();
    }, 4000);
    return () => clearInterval(id);
  }, [screen, loadRoomList, loadDmContacts]);

  const ensureAvatar = useCallback(
    async (otherEmail) => {
      if (!otherEmail || Object.prototype.hasOwnProperty.call(avatarCache, otherEmail)) return;
      try {
        const rec = await storage.get("user:" + otherEmail, true);
        const record = JSON.parse(rec.value);
        setAvatarCache((prev) => ({ ...prev, [otherEmail]: record.avatar || null }));
      } catch (e) {
        setAvatarCache((prev) => ({ ...prev, [otherEmail]: null }));
      }
    },
    [avatarCache]
  );

  useEffect(() => {
    dmContacts.forEach((p) => ensureAvatar(p));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dmContacts]);

  /* ---------------- messages ---------------- */

  function convStorageKey(conv) {
    if (!conv) return null;
    return conv.type === "room" ? "room:" + conv.name + ":msgs" : "dm:" + pairKeyFor(currentUser.email, conv.partner) + ":msgs";
  }
  function convKey(conv) {
    if (!conv) return null;
    return conv.type === "room" ? joinedRooms[conv.name]?.key : dmKeys[conv.partner]?.key;
  }

  const refreshMessages = useCallback(
    async (conv) => {
      const storageKey = convStorageKey(conv);
      const key = convKey(conv);
      if (!storageKey || !key) return;
      let arr = [];
      try {
        const r = await storage.get(storageKey, true);
        arr = r ? JSON.parse(r.value) : [];
      } catch (e) {
        arr = [];
      }
      const out = [];
      for (const m of arr) {
        try {
          const text = await decryptText(key, m.iv, m.ct);
          out.push({ ...m, text, failed: false });
        } catch (e) {
          out.push({ ...m, text: null, failed: true });
        }
      }
      setMessages(out);
    },
    [joinedRooms, dmKeys, currentUser]
  );

  useEffect(() => {
    if (!activeConv) return;
    refreshMessages(activeConv);
    const id = setInterval(() => refreshMessages(activeConv), 2500);
    return () => clearInterval(id);
  }, [activeConv, refreshMessages]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);

  useEffect(() => {
    if (activeConv?.type === "room") {
      const senders = new Set(messages.map((m) => m.from));
      senders.forEach((s) => ensureAvatar(s));
    } else if (activeConv?.type === "dm") {
      ensureAvatar(activeConv.partner);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages, activeConv]);

  async function handleSend() {
    const text = messageInput.trim();
    if (!text || !activeConv) return;
    const key = convKey(activeConv);
    if (!key) return;
    setMessageInput("");
    const storageKey = convStorageKey(activeConv);
    const wrapped = await encryptText(key, text);
    let arr = [];
    try {
      const r = await storage.get(storageKey, true);
      arr = r ? JSON.parse(r.value) : [];
    } catch (e) {
      arr = [];
    }
    arr.push({ from: currentUser.email, iv: wrapped.iv, ct: wrapped.ct, ts: Date.now() });
    if (arr.length > 300) arr = arr.slice(arr.length - 300);
    await storage.set(storageKey, JSON.stringify(arr), true);
    refreshMessages(activeConv);
  }

  /* ---------------- room / dm modal actions ---------------- */

  function openModal(kind, prefillName = "") {
    setModal(kind);
    setModalName(prefillName);
    setModalPass("");
    setModalPass2("");
    setModalError("");
  }
  function closeModal() {
    setModal(null);
    setModalError("");
  }

  async function submitCreateRoom() {
    const name = modalName.trim();
    if (!name || !modalPass) {
      setModalError("Nom et phrase secrète requis.");
      return;
    }
    if (modalPass !== modalPass2) {
      setModalError("Les phrases secrètes ne correspondent pas.");
      return;
    }
    setModalLoading(true);
    try {
      const r = await storage.get("roomlist", true).catch(() => null);
      const list = r ? JSON.parse(r.value) : [];
      if (list.some((x) => x.name.toLowerCase() === name.toLowerCase())) {
        setModalError('Ce salon existe déjà — utilise "Rejoindre".');
        setModalLoading(false);
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const bits = await pbkdf2Bits(modalPass, salt);
      const key = await aesKeyFromRaw(bits);
      const fpHex = await sha256Hex(bits);
      const newList = [...list, { name, salt: buf2b64(salt), createdBy: currentUser.email, createdAt: Date.now() }];
      await storage.set("roomlist", JSON.stringify(newList), true);
      await storage.set("room:" + name + ":msgs", JSON.stringify([]), true);
      setJoinedRooms((prev) => ({ ...prev, [name]: { key, fingerprintHex: fpHex } }));
      setPublicRooms(newList);
      setActiveConv({ type: "room", name });
      setTab("rooms");
      closeModal();
    } catch (e) {
      console.error(e);
      setModalError("Erreur lors de la création.");
    } finally {
      setModalLoading(false);
    }
  }

  async function submitJoinRoom() {
    const name = modalName.trim();
    if (!name || !modalPass) {
      setModalError("Nom et phrase secrète requis.");
      return;
    }
    setModalLoading(true);
    try {
      const r = await storage.get("roomlist", true).catch(() => null);
      const list = r ? JSON.parse(r.value) : [];
      const meta = list.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!meta) {
        setModalError("Salon introuvable.");
        setModalLoading(false);
        return;
      }
      const salt = new Uint8Array(b642buf(meta.salt));
      const bits = await pbkdf2Bits(modalPass, salt);
      const key = await aesKeyFromRaw(bits);
      const fpHex = await sha256Hex(bits);
      setJoinedRooms((prev) => ({ ...prev, [meta.name]: { key, fingerprintHex: fpHex } }));
      setActiveConv({ type: "room", name: meta.name });
      setTab("rooms");
      closeModal();
    } catch (e) {
      console.error(e);
      setModalError("Erreur lors de la connexion au salon.");
    } finally {
      setModalLoading(false);
    }
  }

  async function submitNewDm() {
    const raw = modalName.trim();
    if (!raw) {
      setModalError("Entre une adresse e-mail ou un numéro de téléphone.");
      return;
    }
    setModalLoading(true);
    let partner;
    if (raw.includes("@")) {
      partner = raw.toLowerCase();
    } else {
      const normalized = normalizePhone(raw);
      if (!isValidPhone(normalized)) {
        setModalError("Entre une adresse e-mail ou un numéro de téléphone valide.");
        setModalLoading(false);
        return;
      }
      let phoneRec;
      try {
        phoneRec = await storage.get("phone:" + normalized, true);
      } catch (e) {
        phoneRec = null;
      }
      if (!phoneRec) {
        setModalError("Aucun compte avec ce numéro de téléphone.");
        setModalLoading(false);
        return;
      }
      partner = JSON.parse(phoneRec.value).email;
    }
    if (partner === currentUser.email) {
      setModalError("Tu ne peux pas te parler à toi-même ici.");
      setModalLoading(false);
      return;
    }
    try {
      let rec;
      try {
        rec = await storage.get("user:" + partner, true);
      } catch (e) {
        rec = null;
      }
      if (!rec) {
        setModalError("Aucun compte pour cet e-mail.");
        setModalLoading(false);
        return;
      }
      const record = JSON.parse(rec.value);
      const theirPub = await crypto.subtle.importKey("jwk", record.pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
      const dmKey = await crypto.subtle.deriveKey({ name: "ECDH", public: theirPub }, currentUser.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      const secretBits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirPub }, currentUser.privateKey, 256);
      const fpHex = await sha256Hex(secretBits);

      const meIdxR = await storage.get("dmindex:" + currentUser.email, true).catch(() => null);
      const meIdx = meIdxR ? JSON.parse(meIdxR.value) : [];
      if (!meIdx.includes(partner)) await storage.set("dmindex:" + currentUser.email, JSON.stringify([...meIdx, partner]), true);

      const themIdxR = await storage.get("dmindex:" + partner, true).catch(() => null);
      const themIdx = themIdxR ? JSON.parse(themIdxR.value) : [];
      if (!themIdx.includes(currentUser.email)) await storage.set("dmindex:" + partner, JSON.stringify([...themIdx, currentUser.email]), true);

      setDmKeys((prev) => ({ ...prev, [partner]: { key: dmKey, fingerprintHex: fpHex } }));
      setDmContacts((prev) => (prev.includes(partner) ? prev : [...prev, partner]));
      setActiveConv({ type: "dm", partner });
      setTab("dms");
      closeModal();
    } catch (e) {
      console.error(e);
      setModalError("Erreur lors de l'ouverture de la conversation.");
    } finally {
      setModalLoading(false);
    }
  }

  async function openDmContact(partner) {
    if (dmKeys[partner]) {
      setActiveConv({ type: "dm", partner });
      return;
    }
    setModalLoading(true);
    try {
      const rec = await storage.get("user:" + partner, true);
      const record = JSON.parse(rec.value);
      const theirPub = await crypto.subtle.importKey("jwk", record.pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
      const dmKey = await crypto.subtle.deriveKey({ name: "ECDH", public: theirPub }, currentUser.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      const secretBits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirPub }, currentUser.privateKey, 256);
      const fpHex = await sha256Hex(secretBits);
      setDmKeys((prev) => ({ ...prev, [partner]: { key: dmKey, fingerprintHex: fpHex } }));
      setActiveConv({ type: "dm", partner });
    } catch (e) {
      console.error(e);
    } finally {
      setModalLoading(false);
    }
  }

  async function openRoom(name) {
    if (joinedRooms[name]) {
      setActiveConv({ type: "room", name });
    } else {
      openModal("joinRoom", name);
    }
  }

  /* ---------------- render ---------------- */

  if (!cryptoOk) {
    return (
      <div style={{ background: C.bg, color: C.text, fontFamily: SANS, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ textAlign: "center", maxWidth: 360 }}>
          <AlertTriangle color={C.danger} size={32} />
          <p style={{ marginTop: 12 }}>Ce navigateur ne supporte pas les API de chiffrement nécessaires (Web Crypto). Essaie avec un navigateur récent.</p>
        </div>
      </div>
    );
  }

  if (screen === "auth") {
    return (
      <div style={{ background: C.bg, color: C.text, fontFamily: SANS, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
        <FontLoader />
        <div style={{ width: "100%", maxWidth: 380 }}>
          <div style={{ textAlign: "center", marginBottom: 28 }}>
            <div
              style={{
                width: 56,
                height: 56,
                margin: "0 auto 14px",
                borderRadius: 14,
                background: C.panel,
                border: `1px solid ${C.border}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Lock color={C.brass} size={26} />
            </div>
            <div style={{ fontFamily: MONO, letterSpacing: 4, fontSize: 22, fontWeight: 600 }}>COFFRE</div>
            <div style={{ color: C.sub, fontSize: 13, marginTop: 6 }}>Messagerie chiffrée de bout en bout, dans ton navigateur.</div>
          </div>

          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 22 }}>
            <div style={{ display: "flex", gap: 4, marginBottom: 18, background: C.panel2, borderRadius: 8, padding: 4 }}>
              <button
                onClick={() => {
                  setAuthMode("login");
                  setAuthError("");
                }}
                style={{
                  flex: 1,
                  padding: "8px 0",
                  borderRadius: 6,
                  border: "none",
                  cursor: "pointer",
                  fontFamily: SANS,
                  fontSize: 13,
                  fontWeight: 600,
                  background: authMode === "login" ? C.brassSoft : "transparent",
                  color: authMode === "login" ? C.brass : C.sub,
                }}
              >
                Se connecter
              </button>
              <button
                onClick={() => {
                  setAuthMode("register");
                  setAuthError("");
                }}
                style={{
                  flex: 1,
                  padding: "8px 0",
                  borderRadius: 6,
                  border: "none",
                  cursor: "pointer",
                  fontFamily: SANS,
                  fontSize: 13,
                  fontWeight: 600,
                  background: authMode === "register" ? C.brassSoft : "transparent",
                  color: authMode === "register" ? C.brass : C.sub,
                }}
              >
                Créer un compte
              </button>
            </div>

            {authMode === "register" && (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 16 }}>
                <label htmlFor="avatar-input" style={{ position: "relative", cursor: "pointer" }}>
                  <Avatar src={avatarDataUrl} label={email || "?"} size={72} />
                  <div
                    style={{
                      position: "absolute",
                      bottom: -2,
                      right: -2,
                      width: 24,
                      height: 24,
                      borderRadius: "50%",
                      background: C.brass,
                      border: `2px solid ${C.panel}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Camera size={12} color="#181307" />
                  </div>
                </label>
                <input
                  id="avatar-input"
                  type="file"
                  accept="image/*"
                  style={{ display: "none" }}
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (!file) return;
                    setAvatarError("");
                    try {
                      const dataUrl = await fileToAvatarDataUrl(file);
                      setAvatarDataUrl(dataUrl);
                    } catch (err) {
                      setAvatarError("Impossible d'utiliser cette image.");
                    }
                  }}
                />
                <div style={{ fontSize: 11, color: C.sub, marginTop: 6 }}>Photo de profil (optionnel)</div>
                {avatarError && <div style={{ fontSize: 11, color: C.danger, marginTop: 2 }}>{avatarError}</div>}
              </div>
            )}

            <label style={{ fontSize: 12, color: C.sub, fontFamily: MONO }}>ADRESSE E-MAIL</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="toi@exemple.com" style={inputStyle} />
            {authMode === "register" && (
              <>
                <label style={{ fontSize: 12, color: C.sub, fontFamily: MONO, marginTop: 12, display: "block" }}>TÉLÉPHONE (OPTIONNEL)</label>
                <input type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+33 6 12 34 56 78" style={inputStyle} />
              </>
            )}
            <label style={{ fontSize: 12, color: C.sub, fontFamily: MONO, marginTop: 12, display: "block" }}>MOT DE PASSE</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAuthSubmit()}
              placeholder="••••••••"
              style={inputStyle}
            />

            {authMode === "login" && (
              <button onClick={openForgot} style={{ background: "none", border: "none", color: C.sub, fontSize: 12, cursor: "pointer", marginTop: 8, padding: 0, textDecoration: "underline" }}>
                Mot de passe oublié ?
              </button>
            )}

            {authMode === "register" && (
              <div style={{ fontSize: 12, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
                8 caractères minimum. Ton mot de passe dérive ta clé de chiffrement — il faudra aussi confirmer ton adresse e-mail (un vrai lien te sera envoyé) avant de pouvoir te connecter.
              </div>
            )}

            {authError && (
              <div style={{ marginTop: 12, color: C.danger, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                <AlertTriangle size={14} /> {authError}
              </div>
            )}

            <button onClick={handleAuthSubmit} disabled={authLoading} style={primaryBtnStyle}>
              {authLoading ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />}
              {authMode === "login" ? "Entrer" : "Créer mon compte"}
            </button>
          </div>
        </div>

        {forgotOpen && (
          <Modal title="Récupérer l'accès" onClose={closeForgot}>
            {forgotStep === "verify" && (
              <>
                <FieldLabel>Adresse e-mail</FieldLabel>
                <input type="email" value={forgotEmail} onChange={(e) => setForgotEmail(e.target.value)} style={inputStyle} placeholder="toi@exemple.com" />
                <FieldLabel>Code de récupération</FieldLabel>
                <input value={forgotCode} onChange={(e) => setForgotCode(e.target.value)} style={inputStyle} placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" />
                <div style={{ fontSize: 12, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
                  Le code reçu à ton inscription. Sans lui, tes messages passés restent chiffrés et irrécupérables — c'est le prix d'un vrai chiffrement de bout en bout.
                </div>
                {forgotError && <ModalError text={forgotError} />}
                <button onClick={submitForgotVerify} disabled={forgotLoading} style={primaryBtnStyle}>
                  {forgotLoading ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />} Vérifier
                </button>
              </>
            )}
            {forgotStep === "reset" && (
              <>
                <FieldLabel>Nouveau mot de passe</FieldLabel>
                <input type="password" value={forgotNewPass} onChange={(e) => setForgotNewPass(e.target.value)} style={inputStyle} />
                <FieldLabel>Confirme le nouveau mot de passe</FieldLabel>
                <input type="password" value={forgotNewPass2} onChange={(e) => setForgotNewPass2(e.target.value)} style={inputStyle} />
                {forgotError && <ModalError text={forgotError} />}
                <button onClick={submitForgotReset} disabled={forgotLoading} style={primaryBtnStyle}>
                  {forgotLoading ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />} Réinitialiser
                </button>
              </>
            )}
            {forgotStep === "done" && (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: 8, color: C.success, fontSize: 14, marginTop: 4 }}>
                  <Check size={16} /> Mot de passe réinitialisé.
                </div>
                <button onClick={finishForgot} style={primaryBtnStyle}>
                  Retour à la connexion
                </button>
              </>
            )}
          </Modal>
        )}
      </div>
    );
  }

  if (screen === "unlock") {
    return (
      <div style={{ background: C.bg, color: C.text, fontFamily: SANS, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
        <FontLoader />
        <div style={{ width: "100%", maxWidth: 340, textAlign: "center" }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 14 }}>
            <Avatar src={null} label={unlockSession?.email} size={64} />
          </div>
          <div style={{ fontFamily: MONO, fontSize: 13, wordBreak: "break-all" }}>{unlockSession?.email}</div>
          <div style={{ color: C.sub, fontSize: 13, margin: "6px 0 18px" }}>Entre ton code PIN pour te reconnecter.</div>
          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
            <input
              type="password"
              inputMode="numeric"
              autoFocus
              maxLength={6}
              value={unlockPin}
              onChange={(e) => setUnlockPin(e.target.value.replace(/[^0-9]/g, ""))}
              onKeyDown={(e) => e.key === "Enter" && attemptUnlock()}
              placeholder="••••"
              style={{ ...inputStyle, textAlign: "center", letterSpacing: 8, fontFamily: MONO, fontSize: 22 }}
            />
            {unlockError && (
              <div style={{ marginTop: 12, color: C.danger, fontSize: 13, display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                <AlertTriangle size={14} /> {unlockError}
              </div>
            )}
            <button onClick={attemptUnlock} disabled={unlockLoading || unlockPin.length < 4} style={{ ...primaryBtnStyle, opacity: unlockPin.length < 4 ? 0.5 : 1 }}>
              {unlockLoading ? <Loader2 className="animate-spin" size={16} /> : <Lock size={16} />} Déverrouiller
            </button>
          </div>
          <button onClick={useFullLoginInstead} style={{ background: "none", border: "none", color: C.sub, fontSize: 12, cursor: "pointer", marginTop: 16, textDecoration: "underline" }}>
            Utiliser mon mot de passe à la place
          </button>
        </div>
      </div>
    );
  }

  if (screen === "verify") {
    return (
      <div style={{ background: C.bg, color: C.text, fontFamily: SANS, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
        <FontLoader />
        <div style={{ width: "100%", maxWidth: 380 }}>
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <div
              style={{
                width: 56,
                height: 56,
                margin: "0 auto 14px",
                borderRadius: 14,
                background: C.panel,
                border: `1px solid ${C.border}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ShieldCheck color={C.brass} size={26} />
            </div>
            <div style={{ fontFamily: MONO, letterSpacing: 2, fontSize: 17, fontWeight: 600 }}>VÉRIFIE TON E-MAIL</div>
          </div>

          <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 22 }}>
            <div style={{ fontSize: 13, color: C.sub, lineHeight: 1.6 }}>
              Un lien de confirmation a été envoyé à <b style={{ color: C.text }}>{pendingAuth?.user?.email}</b>. Ouvre-le, puis reviens ici et appuie sur "Continuer".
            </div>

            {verifyError && (
              <div style={{ marginTop: 14, color: C.danger, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                <AlertTriangle size={14} /> {verifyError}
              </div>
            )}
            {verifyInfo && (
              <div style={{ marginTop: 14, color: C.success, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                <Check size={14} /> {verifyInfo}
              </div>
            )}

            <button onClick={checkEmailVerified} disabled={verifyLoading} style={primaryBtnStyle}>
              {verifyLoading ? <Loader2 className="animate-spin" size={16} /> : <Check size={16} />} J'ai vérifié, continuer
            </button>
            <button onClick={resendVerificationEmail} disabled={verifyLoading} style={{ ...newBtnStyle, marginTop: 10 }}>
              Renvoyer l'e-mail
            </button>
            <button onClick={cancelVerification} style={{ background: "none", border: "none", color: C.sub, fontSize: 12, cursor: "pointer", marginTop: 14, padding: 0, textDecoration: "underline", display: "block" }}>
              Annuler et revenir en arrière
            </button>
          </div>
        </div>

        {pendingReveal && (
          <Modal title="Ton code de récupération" onClose={() => {}}>
            <div style={{ fontSize: 13, color: C.sub, lineHeight: 1.6 }}>
              Ce code est le <b>seul</b> moyen de réinitialiser ton mot de passe si tu l'oublies. Note-le quelque part de sûr (gestionnaire de mots de passe, papier). Il ne sera plus jamais affiché.
            </div>
            <div
              style={{
                marginTop: 14,
                background: C.panel2,
                border: `1px solid ${C.border}`,
                borderRadius: 8,
                padding: "14px 12px",
                fontFamily: MONO,
                fontSize: 17,
                letterSpacing: 1,
                textAlign: "center",
                color: C.brass,
              }}
            >
              {pendingReveal.code}
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(pendingReveal.code).then(() => {
                  setRevealCopied(true);
                  setTimeout(() => setRevealCopied(false), 1500);
                });
              }}
              style={{ ...newBtnStyle, marginTop: 10 }}
            >
              {revealCopied ? <Check size={14} /> : <Copy size={14} />} {revealCopied ? "Copié" : "Copier le code"}
            </button>
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 16, fontSize: 13, cursor: "pointer" }}>
              <input type="checkbox" checked={revealChecked} onChange={(e) => setRevealChecked(e.target.checked)} />
              J'ai sauvegardé mon code de récupération.
            </label>
            <button onClick={confirmReveal} disabled={!revealChecked} style={{ ...primaryBtnStyle, opacity: revealChecked ? 1 : 0.5 }}>
              Continuer
            </button>
          </Modal>
        )}
      </div>
    );
  }

  /* ---- main app ---- */
  const joinedRoomNames = Object.keys(joinedRooms);
  const discoverRooms = publicRooms.filter((r) => !joinedRooms[r.name]);
  const activeIsRoom = activeConv?.type === "room";
  const activeFp = activeConv ? (activeIsRoom ? joinedRooms[activeConv.name]?.fingerprintHex : dmKeys[activeConv.partner]?.fingerprintHex) : null;

  return (
    <div className="coffre-root" style={{ background: C.bg, color: C.text, fontFamily: SANS, display: "flex", overflow: "hidden" }}>
      <FontLoader />

      {/* Sidebar */}
      <div
        style={{
          width: isMobile ? "100%" : 280,
          minWidth: isMobile ? "auto" : 280,
          display: isMobile && activeConv ? "none" : "flex",
          flexDirection: "column",
          borderRight: isMobile ? "none" : `1px solid ${C.border}`,
          background: C.panel,
        }}
      >
        <div className="coffre-header" style={{ padding: "16px 16px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
          <Avatar src={currentUser.avatar} label={currentUser.email} size={36} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: MONO, fontSize: 12, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{currentUser.email}</div>
            <div style={{ fontSize: 11, color: C.sub }}>connecté</div>
          </div>
          <button onClick={openSettings} title="Paramètres" style={iconBtnStyle}>
            <Settings size={16} color={C.sub} />
          </button>
        </div>

        <div style={{ display: "flex", padding: 12, gap: 4, background: C.panel2, margin: 12, borderRadius: 8 }}>
          <button onClick={() => setTab("rooms")} style={tabBtnStyle(tab === "rooms")}>
            <Users size={13} /> Salons
          </button>
          <button onClick={() => setTab("dms")} style={tabBtnStyle(tab === "dms")}>
            <MessageCircle size={13} /> Messages
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "0 12px" }}>
          {tab === "rooms" ? (
            <>
              <SectionLabel text="Mes salons" />
              {joinedRoomNames.length === 0 && <EmptyHint text="Aucun salon rejoint." />}
              {joinedRoomNames.map((name) => (
                <ConvRow
                  key={name}
                  active={activeConv?.type === "room" && activeConv.name === name}
                  icon={<Lock size={13} color={C.brass} />}
                  label={name}
                  onClick={() => setActiveConv({ type: "room", name })}
                />
              ))}
              {discoverRooms.length > 0 && (
                <>
                  <SectionLabel text="Découvrir" />
                  {discoverRooms.map((r) => (
                    <ConvRow key={r.name} active={false} icon={<DoorOpen size={13} color={C.sub} />} label={r.name} onClick={() => openRoom(r.name)} />
                  ))}
                </>
              )}
              <button onClick={() => openModal("createRoom")} style={newBtnStyle}>
                <Plus size={14} /> Créer un salon
              </button>
              <button onClick={() => openModal("joinRoom")} style={{ ...newBtnStyle, marginTop: 6, background: "transparent", border: `1px solid ${C.border}`, color: C.sub }}>
                Rejoindre par nom
              </button>
            </>
          ) : (
            <>
              <SectionLabel text="Conversations" />
              {dmContacts.length === 0 && <EmptyHint text="Aucune conversation privée." />}
              {dmContacts.map((p) => (
                <ConvRow
                  key={p}
                  active={activeConv?.type === "dm" && activeConv.partner === p}
                  icon={<Avatar src={avatarCache[p]} label={p} size={22} />}
                  label={p}
                  onClick={() => openDmContact(p)}
                />
              ))}
              <button onClick={() => openModal("newDm")} style={newBtnStyle}>
                <Plus size={14} /> Nouvelle conversation
              </button>
            </>
          )}
        </div>
      </div>

      {/* Main panel */}
      <div style={{ flex: 1, display: isMobile && !activeConv ? "none" : "flex", flexDirection: "column", minWidth: 0 }}>
        {!activeConv ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: C.sub, flexDirection: "column", gap: 10 }}>
            <ShieldCheck size={30} color={C.brassDim} />
            <div>Choisis un salon ou une conversation privée.</div>
          </div>
        ) : (
          <>
            <div className="coffre-header" style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8, background: C.panel }}>
              {isMobile && (
                <button onClick={() => setActiveConv(null)} style={{ ...iconBtnStyle, marginRight: 2 }}>
                  <ChevronLeft size={20} color={C.sub} />
                </button>
              )}
              {activeIsRoom ? <Users size={16} color={C.brass} /> : <Avatar src={avatarCache[activeConv.partner]} label={activeConv.partner} size={24} />}
              <div style={{ fontWeight: 600, fontFamily: MONO, fontSize: 14, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{activeIsRoom ? activeConv.name : activeConv.partner}</div>
              <div style={{ marginLeft: "auto" }}>
                <button onClick={() => setModal("fingerprint")} style={{ ...iconBtnStyle, display: "flex", alignItems: "center", gap: 6, width: "auto", padding: "6px 10px" }}>
                  <Fingerprint size={14} color={C.sub} />
                  <span style={{ fontSize: 12, color: C.sub }}>Vérifier</span>
                </button>
              </div>
            </div>

            <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: 20, display: "flex", flexDirection: "column", gap: 10 }}>
              {messages.length === 0 && <div style={{ color: C.sub, fontSize: 13, textAlign: "center", marginTop: 40 }}>Aucun message. Écris le premier, il sera chiffré avant d'être envoyé.</div>}
              {messages.map((m, i) => {
                const own = m.from === currentUser.email;
                return (
                  <div key={i} style={{ display: "flex", justifyContent: own ? "flex-end" : "flex-start", gap: 8, alignItems: "flex-end" }}>
                    {activeIsRoom && !own && <Avatar src={avatarCache[m.from]} label={m.from} size={24} />}
                    <div
                      style={{
                        maxWidth: "70%",
                        background: own ? C.brassSoft : C.panel2,
                        border: `1px solid ${own ? C.brassDim : C.border}`,
                        borderRadius: 10,
                        padding: "8px 12px",
                      }}
                    >
                      {activeIsRoom && !own && <div style={{ fontFamily: MONO, fontSize: 11, color: C.brass, marginBottom: 3 }}>{m.from}</div>}
                      {m.failed ? (
                        <div style={{ fontSize: 13, color: C.sub, fontStyle: "italic", display: "flex", alignItems: "center", gap: 6 }}>
                          <Lock size={12} /> message illisible (mauvaise clé)
                        </div>
                      ) : (
                        <div style={{ fontSize: 14, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{m.text}</div>
                      )}
                      <div style={{ fontFamily: MONO, fontSize: 10, color: C.sub, marginTop: 4, textAlign: "right" }}>
                        {new Date(m.ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="coffre-input-bar" style={{ padding: "16px", borderTop: `1px solid ${C.border}`, display: "flex", gap: 10, background: C.panel }}>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
                placeholder="Écris un message chiffré…"
                rows={1}
                style={{
                  flex: 1,
                  resize: "none",
                  background: C.panel2,
                  border: `1px solid ${C.border}`,
                  borderRadius: 8,
                  padding: "10px 12px",
                  color: C.text,
                  fontFamily: SANS,
                  fontSize: 14,
                  outline: "none",
                }}
              />
              <button onClick={handleSend} style={{ ...primaryBtnStyle, marginTop: 0, width: 44, padding: 0, height: 42, flexShrink: 0 }}>
                <Send size={16} />
              </button>
            </div>
          </>
        )}
      </div>

      {/* Modals */}
      {modal === "createRoom" && (
        <Modal title="Créer un salon" onClose={closeModal}>
          <FieldLabel>Nom du salon</FieldLabel>
          <input value={modalName} onChange={(e) => setModalName(e.target.value)} style={inputStyle} placeholder="ex. equipe-projet" />
          <FieldLabel>Phrase secrète</FieldLabel>
          <input type="password" value={modalPass} onChange={(e) => setModalPass(e.target.value)} style={inputStyle} placeholder="Choisis une phrase forte" />
          <FieldLabel>Confirme la phrase secrète</FieldLabel>
          <input type="password" value={modalPass2} onChange={(e) => setModalPass2(e.target.value)} style={inputStyle} />
          <div style={{ fontSize: 12, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
            Cette phrase n'est jamais stockée. Elle sert uniquement, sur chaque appareil, à dériver la clé qui chiffre les messages du salon — partage-la seulement avec les personnes de confiance.
          </div>
          {modalError && <ModalError text={modalError} />}
          <button onClick={submitCreateRoom} disabled={modalLoading} style={primaryBtnStyle}>
            {modalLoading ? <Loader2 className="animate-spin" size={16} /> : <Plus size={16} />} Créer le salon
          </button>
        </Modal>
      )}

      {modal === "joinRoom" && (
        <Modal title="Rejoindre un salon" onClose={closeModal}>
          <FieldLabel>Nom du salon</FieldLabel>
          <input value={modalName} onChange={(e) => setModalName(e.target.value)} style={inputStyle} placeholder="ex. equipe-projet" />
          <FieldLabel>Phrase secrète</FieldLabel>
          <input type="password" value={modalPass} onChange={(e) => setModalPass(e.target.value)} style={inputStyle} placeholder="Demande-la à un membre" />
          {modalError && <ModalError text={modalError} />}
          <button onClick={submitJoinRoom} disabled={modalLoading} style={primaryBtnStyle}>
            {modalLoading ? <Loader2 className="animate-spin" size={16} /> : <DoorOpen size={16} />} Rejoindre
          </button>
        </Modal>
      )}

      {modal === "newDm" && (
        <Modal title="Nouvelle conversation privée" onClose={closeModal}>
          <FieldLabel>E-mail ou numéro de téléphone</FieldLabel>
          <input value={modalName} onChange={(e) => setModalName(e.target.value)} style={inputStyle} placeholder="email@exemple.com ou +33612345678" />
          <div style={{ fontSize: 12, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
            La personne doit avoir renseigné ce numéro à son inscription pour être trouvée ainsi. La clé de cette conversation est calculée à partir de vos deux clés personnelles (échange ECDH) — aucune phrase secrète à partager.
          </div>
          {modalError && <ModalError text={modalError} />}
          <button onClick={submitNewDm} disabled={modalLoading} style={primaryBtnStyle}>
            {modalLoading ? <Loader2 className="animate-spin" size={16} /> : <MessageCircle size={16} />} Démarrer
          </button>
        </Modal>
      )}

      {modal === "fingerprint" && activeConv && (
        <Modal title="Vérifier la sécurité" onClose={closeModal}>
          <div style={{ textAlign: "center", padding: "10px 0" }}>
            <FingerprintGrid hex={activeFp || "0".repeat(30)} size={22} />
            <div style={{ fontFamily: MONO, fontSize: 12, color: C.sub, marginTop: 14, wordBreak: "break-all", letterSpacing: 0.5 }}>{(activeFp || "").match(/.{1,4}/g)?.join(" ")}</div>
          </div>
          <div style={{ fontSize: 12, color: C.sub, lineHeight: 1.6, marginTop: 6 }}>
            {activeIsRoom
              ? "Ce motif est dérivé de la phrase secrète du salon. Compare-le avec celui des autres membres pour confirmer que vous utilisez tous la même clé."
              : "Ce motif est dérivé de la clé partagée entre vous deux (échange ECDH). Compare-le en personne ou par un autre canal pour écarter toute interception."}
            <br />
            <br />
            Note : les adresses e-mail, noms de salons et horaires ne sont pas chiffrés — seul le contenu des messages l'est.
          </div>
        </Modal>
      )}

      {pinModalOpen && (
        <Modal title="Rester connecté avec un code PIN" onClose={pinModalMode === "prompt" ? skipPinSetup : () => setPinModalOpen(false)}>
          <div style={{ fontSize: 13, color: C.sub, lineHeight: 1.6 }}>
            Choisis un code de 4 à 6 chiffres. Tu resteras connecté sur cet appareil : à la réouverture de l'app, il suffira du code PIN, plus du mot de passe.
          </div>
          <FieldLabel>Code PIN</FieldLabel>
          <input type="password" inputMode="numeric" maxLength={6} value={pin1} onChange={(e) => setPin1(e.target.value.replace(/[^0-9]/g, ""))} style={{ ...inputStyle, letterSpacing: 6, fontFamily: MONO }} placeholder="••••" />
          <FieldLabel>Confirme le code</FieldLabel>
          <input type="password" inputMode="numeric" maxLength={6} value={pin2} onChange={(e) => setPin2(e.target.value.replace(/[^0-9]/g, ""))} onKeyDown={(e) => e.key === "Enter" && submitPinSetup()} style={{ ...inputStyle, letterSpacing: 6, fontFamily: MONO }} placeholder="••••" />
          <div style={{ fontSize: 11, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
            Un PIN est court : il protège contre un regard indiscret, pas contre quelqu'un qui aurait accès aux données de ton appareil. Garde aussi un verrouillage d'écran sur ton téléphone.
          </div>
          {pinSetupError && <ModalError text={pinSetupError} />}
          <button onClick={submitPinSetup} disabled={pinSetupLoading} style={primaryBtnStyle}>
            {pinSetupLoading ? <Loader2 className="animate-spin" size={16} /> : <Lock size={16} />} Activer le code PIN
          </button>
          <button
            onClick={pinModalMode === "prompt" ? skipPinSetup : () => setPinModalOpen(false)}
            style={{ ...newBtnStyle, marginTop: 10, background: "transparent", border: `1px solid ${C.border}`, color: C.sub }}
          >
            {pinModalMode === "prompt" ? "Plus tard" : "Annuler"}
          </button>
        </Modal>
      )}

      {settingsOpen && (
        <Modal title="Paramètres" onClose={() => setSettingsOpen(false)}>
          <SettingsSectionLabel icon={<UserRound size={13} color={C.brass} />} text="Informations personnelles" />
          <div style={{ display: "flex", alignItems: "center", gap: 12, background: C.panel2, border: `1px solid ${C.border}`, borderRadius: 8, padding: 12, marginTop: 8 }}>
            <label htmlFor="settings-avatar-input" style={{ position: "relative", cursor: settingsAvatarLoading ? "default" : "pointer", flexShrink: 0 }}>
              <Avatar src={currentUser.avatar} label={currentUser.email} size={52} />
              <div
                style={{
                  position: "absolute",
                  bottom: -2,
                  right: -2,
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  background: C.brass,
                  border: `2px solid ${C.panel2}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                {settingsAvatarLoading ? <Loader2 className="animate-spin" size={10} color="#181307" /> : <Camera size={10} color="#181307" />}
              </div>
            </label>
            <input
              id="settings-avatar-input"
              type="file"
              accept="image/*"
              style={{ display: "none" }}
              disabled={settingsAvatarLoading}
              onChange={(e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (file) handleSettingsAvatarFile(file);
              }}
            />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontFamily: MONO, fontSize: 13, fontWeight: 600, wordBreak: "break-all" }}>{currentUser.email}</div>
              {currentUser.phone && <div style={{ fontFamily: MONO, fontSize: 12, color: C.sub, marginTop: 2 }}>{currentUser.phone}</div>}
              <div style={{ fontSize: 11, color: C.sub, marginTop: 2 }}>
                Membre depuis {accountCreatedAt ? new Date(accountCreatedAt).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" }) : "…"}
              </div>
            </div>
          </div>
          {settingsAvatarError && <ModalError text={settingsAvatarError} />}
          {currentUser.avatar && (
            <button
              onClick={() => updateOwnAvatar(null)}
              disabled={settingsAvatarLoading}
              style={{ ...newBtnStyle, marginTop: 8, background: "transparent", border: `1px solid ${C.border}`, color: C.sub }}
            >
              <Trash2 size={13} /> Supprimer la photo
            </button>
          )}

          <SettingsSectionLabel icon={<Fingerprint size={13} color={C.brass} />} text="Empreinte de sécurité" />
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
            <FingerprintGrid hex={currentUser.fingerprintHex} size={8} />
            <div style={{ fontSize: 12, color: C.sub, lineHeight: 1.5 }}>
              Identifie ta clé publique. Partage-la pour que d'autres vérifient qu'ils te parlent bien à toi.
            </div>
          </div>

          <SettingsSectionLabel icon={<Lock size={13} color={C.brass} />} text="Code PIN" />
          <div style={{ fontSize: 12, color: C.sub, marginTop: 8, lineHeight: 1.5 }}>
            {pinSessionEmail === currentUser.email
              ? "Actif sur cet appareil : tu restes connecté et un code PIN suffit à la réouverture."
              : "Non activé : tu devras te reconnecter avec ton mot de passe à chaque ouverture."}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button
              onClick={() => {
                setPin1("");
                setPin2("");
                setPinSetupError("");
                setPinModalMode("settings");
                setSettingsOpen(false);
                setPinModalOpen(true);
              }}
              style={{ ...newBtnStyle, marginTop: 0, flex: 1 }}
            >
              {pinSessionEmail === currentUser.email ? "Changer le code" : "Activer un code PIN"}
            </button>
            {pinSessionEmail === currentUser.email && (
              <button onClick={disableLocalPin} style={{ ...newBtnStyle, marginTop: 0, flex: 1, background: "transparent", border: `1px solid ${C.border}`, color: C.sub }}>
                Désactiver
              </button>
            )}
          </div>

          <SettingsSectionLabel icon={<EyeOff size={13} color={C.brass} />} text="Confidentialité" />
          <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: C.sub, lineHeight: 1.7 }}>
            <li>Le contenu des messages est chiffré dans ton navigateur avant d'être stocké : ni salons ni messages privés ne sont lisibles sans la bonne clé.</li>
            <li>Ton mot de passe dérive ta clé personnelle et n'est jamais stocké en clair, nulle part.</li>
            <li>Les adresses e-mail, noms de salons, horodatages et photos de profil restent visibles (métadonnées) — ce ne sont pas des secrets, contrairement au texte des messages.</li>
            <li>Le code de récupération reçu à l'inscription est la seule façon de réinitialiser ton mot de passe.</li>
          </ul>

          <button
            onClick={handleLogout}
            style={{
              width: "100%",
              marginTop: 20,
              background: "transparent",
              color: C.danger,
              border: `1px solid ${C.danger}`,
              borderRadius: 8,
              padding: "10px 0",
              fontFamily: SANS,
              fontSize: 14,
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
            }}
          >
            <LogOut size={15} /> Se déconnecter
          </button>
        </Modal>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* small building blocks                                                  */
/* ---------------------------------------------------------------------- */

function SectionLabel({ text }) {
  return <div style={{ fontFamily: MONO, fontSize: 10, letterSpacing: 1, color: C.sub, margin: "14px 4px 6px" }}>{text.toUpperCase()}</div>;
}
function SettingsSectionLabel({ icon, text }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 18 }}>
      {icon}
      <div style={{ fontFamily: MONO, fontSize: 11, letterSpacing: 0.5, color: C.brass, fontWeight: 600 }}>{text}</div>
    </div>
  );
}
function EmptyHint({ text }) {
  return <div style={{ fontSize: 12, color: C.sub, padding: "4px 4px 10px" }}>{text}</div>;
}
function ConvRow({ active, icon, label, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "11px 10px",
        borderRadius: 8,
        border: "none",
        background: active ? C.brassSoft : "transparent",
        color: active ? C.brass : C.text,
        cursor: "pointer",
        fontFamily: SANS,
        fontSize: 13,
        textAlign: "left",
        marginBottom: 2,
      }}
    >
      {icon}
      <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
    </button>
  );
}
function FieldLabel({ children }) {
  return <label style={{ fontSize: 12, color: C.sub, fontFamily: MONO, marginTop: 12, display: "block" }}>{children}</label>;
}
function ModalError({ text }) {
  return (
    <div style={{ marginTop: 12, color: C.danger, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
      <AlertTriangle size={14} /> {text}
    </div>
  );
}
function Modal({ title, onClose, children }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50, padding: 20 }} onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()} style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 22, width: "100%", maxWidth: 380, maxHeight: "90vh", overflowY: "auto" }}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
          <div style={{ fontWeight: 600, fontSize: 15, fontFamily: SANS }}>{title}</div>
          <button onClick={onClose} style={{ marginLeft: "auto", background: "none", border: "none", cursor: "pointer" }}>
            <X size={18} color={C.sub} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

const inputStyle = {
  width: "100%",
  marginTop: 6,
  background: C.panel2,
  border: `1px solid ${C.border}`,
  borderRadius: 8,
  padding: "10px 12px",
  color: C.text,
  fontFamily: SANS,
  fontSize: 14,
  outline: "none",
};
const primaryBtnStyle = {
  width: "100%",
  marginTop: 18,
  background: C.brass,
  color: "#181307",
  border: "none",
  borderRadius: 8,
  padding: "11px 0",
  fontFamily: SANS,
  fontSize: 14,
  fontWeight: 700,
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 8,
};
const newBtnStyle = {
  width: "100%",
  marginTop: 14,
  background: C.brassSoft,
  color: C.brass,
  border: `1px solid ${C.brassDim}`,
  borderRadius: 8,
  padding: "11px 0",
  fontFamily: SANS,
  fontSize: 13,
  fontWeight: 600,
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 6,
};
const iconBtnStyle = {
  background: "none",
  border: "none",
  cursor: "pointer",
  width: 40,
  height: 40,
  minWidth: 40,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  borderRadius: 8,
  flexShrink: 0,
};
function tabBtnStyle(active) {
  return {
    flex: 1,
    padding: "9px 0",
    borderRadius: 6,
    border: "none",
    cursor: "pointer",
    fontFamily: SANS,
    fontSize: 12,
    fontWeight: 600,
    background: active ? C.brassSoft : "transparent",
    color: active ? C.brass : C.sub,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 5,
  };
}
