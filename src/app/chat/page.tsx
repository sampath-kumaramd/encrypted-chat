"use client";

import { useState, useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { subscribeToMessages, sendMessage } from '@/lib/db/schema';
import { getUserPublicKey } from '@/lib/db/users';
import ContactList from '@/components/ContactList';
import type { EncryptedMessage, User } from '@/types/chat';
import Message from '@/components/Message';
import { EncryptionService } from '@/lib/utils/encryption';

export default function ChatPage() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<EncryptedMessage[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [selectedContact, setSelectedContact] = useState<User | null>(null);
  const [isEncryptionReady, setIsEncryptionReady] = useState(false);
  
  useEffect(() => {
    if (!user) return;
    
    const unsubscribe = subscribeToMessages(user.uid, (messages) => {
      setMessages(messages);
    });
    
    return () => unsubscribe();
  }, [user]);

  useEffect(() => {
    const initializeEncryption = async () => {
      try {
          const encryptionService = new EncryptionService();
          
        
        // Initialize with a temporary password (in production, this should come from user input)
        await encryptionService.initializeFromStoredKeys("your-secure-password");
        
        const isValid = await encryptionService.verifyKeyPair();
        if (!isValid) {
          // If verification fails, generate new keys
            const { publicKey } = await encryptionService.initializeKeyPair();
            
            console.log("New encryption keys generated" , publicKey);
          // Here you would typically save the public key to your user's profile in the database
          console.log('New encryption keys generated');
        }
        
        setIsEncryptionReady(true);
      } catch (error) {
        console.error('Failed to initialize encryption:', error);
        // Handle the error appropriately (show user message, etc.)
      }
    };

    if (user) {
      initializeEncryption();
    }
  }, [user]);

  const handleSendMessage = async (e: React.FormEvent) => {
      e.preventDefault();
      
      console.log(newMessage);
    if (!user || !selectedContact || !newMessage.trim()) return;
    
    try {
      const recipientPublicKey = await getUserPublicKey(selectedContact.uid);
      if (!recipientPublicKey) {
        throw new Error("Recipient's public key not found");
      }
      
      await sendMessage(
        user.uid,
        selectedContact.uid,
        newMessage,
        recipientPublicKey
      );
      setNewMessage('');
    } catch (error) {
        console.error('Error sending message:', error);
        console.log("isEncryptionReady" , isEncryptionReady);
      alert('Failed to send message');
    }
  };

  if (!user) {
    return <div>Please sign in to access chat.</div>;
  }

  return (
    <div className="flex h-screen">
      <ContactList
        currentUserId={user.uid}
        onSelectContact={setSelectedContact}
      />
      
      <div className="flex-1 flex flex-col">
        {selectedContact ? (
          <>
            <div className="p-4 border-b">
              <h2 className="font-semibold">{selectedContact.displayName}</h2>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4">
              {messages
                .filter(
                  (msg) =>
                    (msg.senderId === user.uid &&
                      msg.receiverId === selectedContact.uid) ||
                    (msg.senderId === selectedContact.uid &&
                      msg.receiverId === user.uid)
                )
                .sort((a, b) => a.timestamp - b.timestamp)
                .map((message) => (
                  <Message
                    key={message.id}
                    message={message}
                    isOwnMessage={message.senderId === user.uid}
                  />
                ))}
            </div>
            
            <form onSubmit={handleSendMessage} className="p-4 border-t">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                className="w-full px-4 py-2 border rounded-lg text-black"
                placeholder="Type a message..."
                          />
                          

                          <button type="submit" className="bg-blue-500 text-white px-4 py-2 rounded-lg">
                            Send
                          </button>
            </form>
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500">
            Select a contact to start chatting
          </div>
        )}
      </div>
    </div>
  );
} 