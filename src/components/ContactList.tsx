import { useState, useEffect } from 'react';
import { getUsers } from '@/lib/db/users';
import type { User } from '@/types/chat';

interface ContactListProps {
  currentUserId: string;
  onSelectContact: (contact: User) => void;
}

export default function ContactList({ currentUserId, onSelectContact }: ContactListProps) {
  const [contacts, setContacts] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadContacts = async () => {
      try {
        const users = await getUsers(currentUserId);
        setContacts(users);
      } catch (error) {
        console.error('Error loading contacts:', error);
      } finally {
        setLoading(false);
      }
    };

    loadContacts();
  }, [currentUserId]);

  if (loading) {
    return <div className="p-4">Loading contacts...</div>;
  }

  return (
    <div className="border-r border-gray-200 w-64">
      <div className="p-4 border-b">
        <h2 className="text-lg font-semibold">Contacts</h2>
      </div>
      <div className="overflow-y-auto">
        {contacts.map((contact) => (
          <button
            key={contact.uid}
            onClick={() => onSelectContact(contact)}
            className="w-full p-4 text-left hover:bg-gray-50 focus:bg-gray-50 transition-colors"
          >
            <div className="font-medium">{contact.displayName}</div>
          </button>
        ))}
      </div>
    </div>
  );
} 