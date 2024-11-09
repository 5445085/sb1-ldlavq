import { encode, decode } from '@nativescript/core/text';

export class CryptoService {
    private readonly algorithm = 'AES-GCM';
    private readonly keyLength = 256;

    async encrypt(text: string, key: CryptoKey): Promise<string> {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedText = encode(text);
        
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv
            },
            key,
            encodedText
        );

        const encryptedArray = new Uint8Array(encryptedData);
        const combined = new Uint8Array(iv.length + encryptedArray.length);
        combined.set(iv);
        combined.set(encryptedArray, iv.length);

        return Buffer.from(combined).toString('base64');
    }

    async decrypt(encryptedData: string, key: CryptoKey): Promise<string> {
        const data = Buffer.from(encryptedData, 'base64');
        const iv = data.slice(0, 12);
        const ciphertext = data.slice(12);

        const decryptedData = await crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv
            },
            key,
            ciphertext
        );

        return decode(new Uint8Array(decryptedData));
    }

    async generateKey(): Promise<CryptoKey> {
        return await crypto.subtle.generateKey(
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
}