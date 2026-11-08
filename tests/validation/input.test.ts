
import { describe, it, expect } from 'vitest';
import { RegisterSchema, VaultItemSchema, ShareItemSchema } from '../../client/src/validation/schemas.js';

describe('Week 2 Input Handling Kit - 20 Negative Security Tests', () => {
  // Baseline valid objects
  const validRegister = {
    email: 'alice@example.com',
    salt: 'a1b2c3d4e5f60718293a4b5c6d7e8f00112233445566778899aabbccddeeff00',
    authVerifier: 'verifier-sample-hash-1234567890',
    clientPublicKey: 'pk_sample_public_key_value_minimum_32_chars_long',
  };

  const validVaultItem = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    type: 'login' as const,
    title: 'My Banking Credentials',
    encryptedBlob: 'dGVzdC1lbmNyeXB0ZWQtYmxvYi1jb250ZW50cw==',
    iv: 'YWJjZGVmZ2hpamtsbW5vcA==', // 24-char Base64 string
  };

  const validShareItem = {
    itemId: '123e4567-e89b-12d3-a456-426614174000',
    recipientEmail: 'bob@example.com',
    encryptedKey: 'c2hhcmVkLWtleS1kYXRhLXZhbHVl',
    permissions: 'read' as const,
    expiresAt: '2026-12-31T23:59:59.000Z',
  };

  // Group 1: 5 SQL Injection (SQLi) Tests
  describe('Group 1: 5 SQL Injection (SQLi) Tests', () => {
    it("1. should reject SQLi payload: '' OR 1=1 --' in email field", () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        email: "' OR 1=1 --",
      });
      expect(result.success).toBe(false);
    });

    it("2. should reject SQLi payload: ''; DROP TABLE users; --' in id field", () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        id: "'; DROP TABLE users; --",
      });
      expect(result.success).toBe(false);
    });

    it("3. should reject SQLi payload: '' UNION SELECT null --' in encryptedBlob field", () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        encryptedBlob: "' UNION SELECT null --",
      });
      expect(result.success).toBe(false);
    });

    it("4. should reject SQLi payload: '; SELECT pg_sleep(5); --' in recipientEmail field", () => {
      const result = ShareItemSchema.safeParse({
        ...validShareItem,
        recipientEmail: '; SELECT pg_sleep(5); --',
      });
      expect(result.success).toBe(false);
    });

    it("5. should reject SQLi payload: '' OR '1'='1' in salt field", () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        salt: "' OR '1'='1",
      });
      expect(result.success).toBe(false);
    });
  });

  // Group 2: 5 Cross-Site Scripting (XSS) Tests
  describe('Group 2: 5 Cross-Site Scripting (XSS) Tests', () => {
    it('6. should reject XSS payload: <script>alert(1)</script> in email field', () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        email: '<script>alert(1)</script>',
      });
      expect(result.success).toBe(false);
    });

    it('7. should reject XSS payload: <img src=x onerror=alert(1)> in id field', () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        id: '<img src=x onerror=alert(1)>',
      });
      expect(result.success).toBe(false);
    });

    it('8. should reject XSS payload: javascript:alert(1) in recipientEmail field', () => {
      const result = ShareItemSchema.safeParse({
        ...validShareItem,
        recipientEmail: 'javascript:alert(1)',
      });
      expect(result.success).toBe(false);
    });

    it('9. should reject XSS payload: <svg onload=alert(1)> in encryptedBlob field', () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        encryptedBlob: '<svg onload=alert(1)>',
      });
      expect(result.success).toBe(false);
    });

    it('10. should reject XSS payload: <iframe src=javascript:alert(1)> in salt field', () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        salt: '<iframe src=javascript:alert(1)>',
      });
      expect(result.success).toBe(false);
    });
  });

  // Group 3: 5 Unicode & Boundary Tests
  describe('Group 3: 5 Unicode & Boundary Tests', () => {
    it('11. should reject null byte (\\x00) in email field', () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        email: 'alice\x00@example.com',
      });
      expect(result.success).toBe(false);
    });

    it('12. should reject 10,000-char string in title field (max 128 boundary)', () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        title: 'A'.repeat(10000),
      });
      expect(result.success).toBe(false);
    });

    it("13. should reject invalid hex ('z'.repeat(64)) in salt field", () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        salt: 'z'.repeat(64),
      });
      expect(result.success).toBe(false);
    });

    it("14. should reject off-by-one length ('a'.repeat(63)) in salt field", () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        salt: 'a'.repeat(63),
      });
      expect(result.success).toBe(false);
    });

    it('15. should reject oversized Base64 (>65536 chars) in encryptedBlob field', () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        encryptedBlob: 'A'.repeat(65540),
      });
      expect(result.success).toBe(false);
    });
  });

  // Group 4: 5 Type Mismatch Tests
  describe('Group 4: 5 Type Mismatch Tests', () => {
    it('16. should reject object instead of string for email field', () => {
      const result = RegisterSchema.safeParse({
        ...validRegister,
        email: { address: 'alice@example.com' },
      });
      expect(result.success).toBe(false);
    });

    it('17. should reject array instead of string for title field', () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        title: ['My', 'Banking', 'Credentials'],
      });
      expect(result.success).toBe(false);
    });

    it('18. should reject missing required field (iv)', () => {
      const { iv: _omittedIv, ...itemMissingIv } = validVaultItem;
      const result = VaultItemSchema.safeParse(itemMissingIv);
      expect(result.success).toBe(false);
    });

    it('19. should reject __proto__ injection via strict schema', () => {
      // Computed property ['__proto__'] creates an own property (prototype pollution attempt)
      const maliciousPayload = {
        ...validRegister,
        ['__proto__']: { isAdmin: true },
      };
      const result = RegisterSchema.safeParse(maliciousPayload);
      expect(result.success).toBe(false);
    });

    it("20. should reject invalid enum value (type: 'admin')", () => {
      const result = VaultItemSchema.safeParse({
        ...validVaultItem,
        type: 'admin',
      });
      expect(result.success).toBe(false);
    });
  });
});
