export interface Message {
    id: string;
    content: string;
    sender: string;
    timestamp: Date;
    expiresAt: Date;
    isRead: boolean;
}