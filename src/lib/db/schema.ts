// src/lib/db/schema.ts
import {
  collection,
  addDoc,
  query,
  where,
  orderBy,
  onSnapshot,
  doc,
  setDoc,
} from "firebase/firestore";
import { db } from "../firebase";
import { EncryptionService } from "@/lib/utils/encryption";
import { EncryptedMessage } from "@/types/chat";

export const createUser = async (
  uid: string,
  displayName: string
): Promise<void> => {
  const encryptionService = new EncryptionService();
  const { publicKey } = await encryptionService.generateKeyPair();

  await setDoc(doc(db, "users", uid), {
    uid,
    displayName,
    publicKey,
    createdAt: Date.now(),
  });
};

export const sendMessage = async (
  senderId: string,
  receiverId: string,
  content: string,
  recipientPublicKey: string
): Promise<void> => {
  const encryptionService = new EncryptionService();
  const { encryptedContent, encryptedKey, iv } =
    await encryptionService.encryptMessage(content, recipientPublicKey);

  await addDoc(collection(db, "messages"), {
    senderId,
    receiverId,
    encryptedContent,
    encryptedKey,
    iv,
    timestamp: Date.now(),
    version: 2,
  });
};

export const subscribeToMessages = (
  userId: string,
  callback: (messages: EncryptedMessage[]) => void
): (() => void) => {
  const q = query(
    collection(db, "messages"),
    where("receiverId", "==", userId),
    orderBy("timestamp", "desc")
  );

  return onSnapshot(q, (snapshot) => {
    const messages = snapshot.docs.map(
      (doc) =>
        ({
          id: doc.id,
          ...doc.data(),
        } as EncryptedMessage)
    );
    callback(messages);
  });
};
