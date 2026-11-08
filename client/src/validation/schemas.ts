import { z } from 'zod';

export const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const HEX_64_REGEX = /^[0-9a-fA-F]{64}$/;

export const RegisterSchema = z
  .object({
    email: z.string().email('Invalid email address').max(254, 'Email must be at most 254 characters'),
    salt: z.string().regex(HEX_64_REGEX, 'Salt must be exactly 64 hexadecimal characters'),
    authVerifier: z
      .string()
      .min(1, 'authVerifier must be at least 1 character')
      .max(512, 'authVerifier must be at most 512 characters'),
    clientPublicKey: z
      .string()
      .min(32, 'clientPublicKey must be at least 32 characters')
      .max(128, 'clientPublicKey must be at most 128 characters'),
  })
  .strict();

export const VaultItemSchema = z
  .object({
    id: z.string().uuid('Invalid UUID for id'),
    type: z.enum(['login', 'secure_note', 'card']),
    title: z.string().min(1, 'Title must be at least 1 character').max(128, 'Title must be at most 128 characters'),
    encryptedBlob: z
      .string()
      .min(1, 'encryptedBlob must not be empty')
      .max(65536, 'encryptedBlob must be at most 65536 characters')
      .regex(BASE64_REGEX, 'encryptedBlob must be valid Base64'),
    iv: z
      .string()
      .regex(BASE64_REGEX, 'iv must be valid Base64')
      .refine((val) => val.length === 16 || val.length === 24, {
        message: 'iv must be exactly 16 or 24 characters',
      }),
  })
  .strict();

export const ShareItemSchema = z
  .object({
    itemId: z.string().uuid('Invalid UUID for itemId'),
    recipientEmail: z
      .string()
      .email('Invalid email address')
      .max(254, 'recipientEmail must be at most 254 characters'),
    encryptedKey: z
      .string()
      .min(1, 'encryptedKey must not be empty')
      .regex(BASE64_REGEX, 'encryptedKey must be valid Base64'),
    permissions: z.enum(['read', 'write']),
    expiresAt: z.string().datetime('expiresAt must be a valid ISO datetime').optional(),
  })
  .strict();

export type RegisterInput = z.infer<typeof RegisterSchema>;
export type VaultItemInput = z.infer<typeof VaultItemSchema>;
export type ShareItemInput = z.infer<typeof ShareItemSchema>;
