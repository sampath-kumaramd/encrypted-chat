// src/hooks/useAuth.ts
import { useState, useEffect, useMemo } from "react";
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  User,
} from "firebase/auth";
import { doc, getDoc } from "firebase/firestore";
import { auth, db } from "@/lib/firebase";
import { createUser } from "@/lib/db/schema";
import { EncryptionService } from "@/lib/utils/encryption";

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const encryptionService = useMemo(() => new EncryptionService(), []);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      try {
        setLoading(true);

        if (firebaseUser) {
          setUser(firebaseUser);

          const maxRetries = 3;
          let attempts = 0;

          while (attempts < maxRetries) {
            try {
              const userDocRef = doc(db, "users", firebaseUser.uid);
              const userDoc = await getDoc(userDocRef);

              if (userDoc.exists()) {
                setUser((prevUser) => {
                  if (!prevUser) return null;
                  return { ...prevUser, ...userDoc.data() } as User;
                });
              }
              break;
            } catch (firestoreError) {
              attempts++;
              console.error(
                `Firestore attempt ${attempts} failed:`,
                firestoreError
              );
              if (attempts === maxRetries) {
                throw firestoreError;
              }
              await new Promise((resolve) =>
                setTimeout(resolve, Math.pow(2, attempts) * 1000)
              );
            }
          }
        } else {
          setUser(null);
        }
      } catch (error) {
        console.error("Error in auth state change:", error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    });

    return () => unsubscribe();
  }, []);

  const signup = async (
    email: string,
    password: string,
    displayName: string
  ) => {
    try {
      setLoading(true);
      setError(null);

      const { user: firebaseUser } = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );

      await createUser(firebaseUser.uid, displayName);

      setUser(firebaseUser);
    } catch (error) {
      console.error("Signup failed:", error);
      setError(error instanceof Error ? error.message : "Signup failed");
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signin = async (email: string, password: string) => {
    try {
      setLoading(true);
      setError(null);

      const { user: firebaseUser } = await signInWithEmailAndPassword(
        auth,
        email,
        password
      );

      await encryptionService.initializeFromStoredKeys(password);

      setUser(firebaseUser);
    } catch (error) {
      console.error("Signin failed:", error);
      setError(error instanceof Error ? error.message : "Signin failed");
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signout = () => {
    return signOut(auth);
  };

  return {
    user,
    loading,
    error,
    signup,
    signin,
    signout,
  };
}
