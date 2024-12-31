import {
  collection,
  query,
  getDocs,
  where,
  getDoc,
  doc,
} from "firebase/firestore";
import { db } from "../firebase";
import type { User } from "@/types/chat";

export const getUsers = async (currentUserId: string): Promise<User[]> => {
  const usersRef = collection(db, "users");
  const q = query(usersRef, where("uid", "!=", currentUserId));
  const querySnapshot = await getDocs(q);

  return querySnapshot.docs.map((doc) => doc.data() as User);
};

export const getUserById = async (userId: string): Promise<User | null> => {
  const userDoc = await getDoc(doc(db, "users", userId));
  return userDoc.exists() ? (userDoc.data() as User) : null;
};

export const getUserPublicKey = async (
  userId: string
): Promise<string | null> => {
  const user = await getUserById(userId);
  return user?.publicKey || null;
};
