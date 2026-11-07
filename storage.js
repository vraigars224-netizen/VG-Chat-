import { db } from "./firebase";
import { doc, getDoc, setDoc, deleteDoc, collection, getDocs } from "firebase/firestore";

const COLLECTION = "coffre_kv";

function safeId(key) {
  // Firestore document IDs can't contain "/"; our keys never do, but this is a safety net.
  return String(key).replace(/\//g, "__slash__").slice(0, 1500);
}

// Same shape as the Claude-artifact window.storage API (get/set/delete/list),
// so the app code that calls storage.get(key, true) etc. needs no other changes.
// The `shared` argument is accepted for compatibility but ignored — every key
// lives in one Firestore collection, since the app already only ever used shared data.
export const storage = {
  async get(key) {
    const snap = await getDoc(doc(db, COLLECTION, safeId(key)));
    if (!snap.exists()) {
      throw new Error("not-found: " + key);
    }
    return { key, value: snap.data().value, shared: true };
  },
  async set(key, value) {
    await setDoc(doc(db, COLLECTION, safeId(key)), { value, updatedAt: Date.now() });
    return { key, value, shared: true };
  },
  async delete(key) {
    await deleteDoc(doc(db, COLLECTION, safeId(key)));
    return { key, deleted: true, shared: true };
  },
  async list(prefix = "") {
    const snap = await getDocs(collection(db, COLLECTION));
    const keys = [];
    snap.forEach((d) => {
      if (d.id.startsWith(safeId(prefix))) keys.push(d.id);
    });
    return { keys, prefix, shared: true };
  },
};
