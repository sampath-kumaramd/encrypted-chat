import { useState, useEffect, useCallback } from 'react';
import { EncryptionService } from '@/lib/utils/encryption';
import type { EncryptedMessage } from '@/types/chat';
import LoadingSpinner from '@/components/LoadingSpinner';

interface MessageProps {
  message: EncryptedMessage;
  isOwnMessage: boolean;
}

export default function Message({ message, isOwnMessage }: MessageProps) {
  const [decryptedContent, setDecryptedContent] = useState<string>('');
  const [decryptionStatus, setDecryptionStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const decryptMessage = useCallback(async () => {
    if (!message || decryptionStatus === 'loading') return;

    try {
      setDecryptionStatus('loading');
      const encryptionService = new EncryptionService();
      const privateKey = await encryptionService.getStoredPrivateKey();
      
      if (!privateKey) {
        throw new Error('Please log in again to restore your encryption keys');
      }

      const content = await encryptionService.decryptMessage({
        encryptedContent: message.encryptedContent,
        encryptedKey: message.encryptedKey,
        iv: message.iv,
        privateKey,
      });
      
      setDecryptedContent(content);
      setDecryptionStatus('success');
    } catch (error) {
      console.error('Decryption error:', error);
      setDecryptionStatus('error');
    }
  }, [message, decryptionStatus]);

  useEffect(() => {
    decryptMessage();
  }, [decryptMessage]);

  if (decryptionStatus === 'loading') {
    return <LoadingSpinner />;
  }

  if (decryptionStatus === 'error') {
    return (
      <div className="text-red-500">
        Failed to decrypt message
      </div>
    );
  }

  return (
    <div className={`message ${isOwnMessage ? 'sent' : 'received'}`}>
      {decryptedContent}
    </div>
  );
} 