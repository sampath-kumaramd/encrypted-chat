export interface EncryptedMessage {
  id: string;
  senderId: string;
  receiverId: string;
  encryptedContent: string;
  encryptedKey: string;
  iv: string;
  timestamp: number;
  version: number;
  retryCount?: number;
}

export interface User {
  uid: string;
  displayName: string;
  email: string;
  photoURL: string;
  createdAt: number;
  publicKey: string;
}
