// src/utils/encryption.ts
export class EncryptionService {
  private privateKey: CryptoKey | null = null;
  private keyCache: Map<string, CryptoKey> = new Map();

  async initializeKeyPair(): Promise<{
    publicKey: string;
    privateKey: CryptoKey;
  }> {
    try {
      // Generate a new key pair
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      // Export public key as JWK
      const exportedPublicKey = await window.crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey
      );

      this.privateKey = keyPair.privateKey;

      // Store private key securely
      await this.storePrivateKey(keyPair.privateKey);

      return {
        publicKey: JSON.stringify(exportedPublicKey),
        privateKey: keyPair.privateKey,
      };
    } catch (error) {
      console.error("Key pair generation failed:", error);
      throw new Error("Failed to initialize encryption");
    }
  }

  private async storePrivateKey(privateKey: CryptoKey): Promise<void> {
    try {
      const exportedPrivateKey = await window.crypto.subtle.exportKey(
        "jwk",
        privateKey
      );
      const encryptedPrivateKey = await this.encryptWithPassword(
        JSON.stringify(exportedPrivateKey),
        "your-secure-password" // This should come from user input
      );
      localStorage.setItem("encryptedPrivateKey", encryptedPrivateKey);
    } catch (error) {
      console.error("Failed to store private key:", error);
      throw error;
    }
  }

  // Add more robust error handling and validation
  async decryptMessage({
    encryptedContent,
    encryptedKey,
    iv,
    privateKey = this.privateKey,
  }: {
    encryptedContent: string;
    encryptedKey: string;
    iv: string;
    privateKey?: CryptoKey | null;
  }): Promise<string> {
    try {
      if (!encryptedContent || !encryptedKey || !iv || !privateKey) {
        throw new Error("Missing required decryption parameters");
      }

      // Decrypt the symmetric key first
      const rawKey = await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        privateKey,
        this.base64ToArrayBuffer(encryptedKey)
      );

      // Import the symmetric key
      const symmetricKey = await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Use the symmetric key to decrypt the content
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: this.base64ToArrayBuffer(iv),
        },
        symmetricKey,
        this.base64ToArrayBuffer(encryptedContent)
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error(
        `Decryption failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  // Helper methods
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async initializeFromStoredKeys(password: string): Promise<void> {
    try {
      const storedKey = localStorage.getItem("encryptedPrivateKey");
      if (!storedKey) {
        // If no stored key found, generate a new key pair
        await this.initializeKeyPair();
        return;
      }

      try {
        const decryptedKey = await this.decryptWithPassword(
          storedKey,
          password
        );
        const privateKeyData = JSON.parse(decryptedKey);

        this.privateKey = await window.crypto.subtle.importKey(
          "jwk",
          privateKeyData,
          {
            name: "RSA-OAEP",
            hash: "SHA-256",
          },
          true,
          ["decrypt"]
        );
      } catch (decryptError) {
        console.error("Failed to decrypt stored key:", decryptError);
        // If decryption fails, reinitialize with new keys
        await this.initializeKeyPair();
      }
    } catch (error) {
      console.error("Failed to initialize from stored keys:", error);
      throw error;
    }
  }

  private async decryptWithPassword(
    encryptedData: string,
    password: string
  ): Promise<string> {
    const key = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );

    const salt = new Uint8Array(16);
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      key,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const encryptedBytes = this.base64ToArrayBuffer(encryptedData);
    const iv = encryptedBytes.slice(0, 12);
    const data = encryptedBytes.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      data
    );

    return new TextDecoder().decode(decrypted);
  }

  private async encryptWithPassword(
    data: string,
    password: string
  ): Promise<string> {
    const key = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );

    const salt = new Uint8Array(16);
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      key,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      new TextEncoder().encode(data)
    );

    const result = new Uint8Array(
      iv.length + new Uint8Array(encryptedData).length
    );
    result.set(iv);
    result.set(new Uint8Array(encryptedData), iv.length);

    return btoa(String.fromCharCode(...result));
  }

  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    return {
      publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
      privateKey: keyPair.privateKey,
    };
  }

  async encryptMessage(content: string, recipientPublicKey: string) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const contentKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );

    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      contentKey,
      new TextEncoder().encode(content)
    );

    const importedPublicKey = await window.crypto.subtle.importKey(
      "spki",
      Uint8Array.from(atob(recipientPublicKey), (c) => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

    const encryptedKey = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      importedPublicKey,
      await window.crypto.subtle.exportKey("raw", contentKey)
    );

    return {
      encryptedContent: btoa(
        String.fromCharCode(...new Uint8Array(encryptedContent))
      ),
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
      iv: btoa(String.fromCharCode(...iv)),
    };
  }

  async getStoredPrivateKey() {
    const privateKeyString = localStorage.getItem("privateKey");
    if (!privateKeyString) return null;

    return window.crypto.subtle.importKey(
      "pkcs8",
      Uint8Array.from(atob(privateKeyString), (c) => c.charCodeAt(0)),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  }

  async verifyKeyPair() {
    const privateKey = await this.getStoredPrivateKey();
    const publicKeyString = localStorage.getItem("publicKey");

    if (!privateKey || !publicKeyString) return false;

    try {
      const testMessage = "test";
      const { encryptedContent, encryptedKey, iv } = await this.encryptMessage(
        testMessage,
        publicKeyString
      );
      const decrypted = await this.decryptMessage({
        encryptedContent,
        encryptedKey,
        iv,
      });
      return decrypted === testMessage;
    } catch (error) {
      console.error("Key pair verification failed:", error);
      return false;
    }
  }
}
