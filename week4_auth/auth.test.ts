import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import {
  hashPassword,
  verifyPassword,
  shouldRehash,
  generateTOTPSecret,
  generateTOTPToken,
  verifyTOTP,
  getSession,
  clearAllSessions,
} from './auth.js';
import {
  app,
  seedUser,
  clearMockUsers,
  clearRateLimits,
} from './server.js';

describe('Week 4 Authentication Module Tests', () => {
  const TEST_USER = {
    id: 'user-uuid-12345',
    email: 'alice@zkpm.example',
    password: 'SuperSecretPassword123!',
    totpSecret: '',
  };

  beforeEach(async () => {
    clearMockUsers();
    clearRateLimits();
    clearAllSessions();

    // Generate fresh Argon2id hash and TOTP secret for the test user
    const passwordHash = await hashPassword(TEST_USER.password);
    const totpSecret = generateTOTPSecret();
    TEST_USER.totpSecret = totpSecret;

    seedUser({
      id: TEST_USER.id,
      email: TEST_USER.email,
      passwordHash,
      totpSecret,
    });
  });

  // -------------------------------------------------------------
  // Requirement 1: Argon2id Hashing and Verification
  // -------------------------------------------------------------
  describe('1. Argon2id Password Hashing & Verification', () => {
    it('should generate different hashes for the same password due to unique salt', async () => {
      const password = 'MySecureMasterPassword!2026';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
      expect(hash1).toContain('$argon2id$');
      expect(hash2).toContain('$argon2id$');
    });

    it('should correctly verify valid and invalid passwords', async () => {
      const password = 'CorrectPassword987#';
      const hash = await hashPassword(password);

      const isValid = await verifyPassword(hash, password);
      const isInvalid = await verifyPassword(hash, 'WrongPassword!');

      expect(isValid).toBe(true);
      expect(isInvalid).toBe(false);
    });

    it('should correctly detect if a password hash requires rehashing (shouldRehash)', async () => {
      // Modern Argon2id hash with m=65536
      const modernHash = await hashPassword('SamplePassword');
      expect(shouldRehash(modernHash)).toBe(false);

      // Outdated hash with low memory cost (e.g. m=1024)
      const outdatedMemoryHash = '$argon2id$v=19$m=1024,t=2,p=1$c29tZXNhbHQ$abcdef';
      expect(shouldRehash(outdatedMemoryHash)).toBe(true);

      // Outdated legacy algorithm (e.g. argon2i instead of argon2id)
      const outdatedAlgorithmHash = '$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$abcdef';
      expect(shouldRehash(outdatedAlgorithmHash)).toBe(true);
    });
  });

  // -------------------------------------------------------------
  // Requirement 2: Time-based One-Time Password (TOTP)
  // -------------------------------------------------------------
  describe('2. TOTP Two-Factor Authentication', () => {
    it('should generate valid Base32 secret and verify genuine token', () => {
      const secret = generateTOTPSecret();
      expect(secret).toBeDefined();
      expect(secret.length).toBeGreaterThanOrEqual(16);

      const validToken = generateTOTPToken(secret);
      expect(validToken).toMatch(/^\d{6}$/);

      const isValid = verifyTOTP(secret, validToken);
      expect(isValid).toBe(true);
    });

    it('should reject invalid or forged TOTP tokens', () => {
      const secret = generateTOTPSecret();
      const invalidToken = '000000';

      const isValid = verifyTOTP(secret, invalidToken);
      expect(isValid).toBe(false);
    });

    it('should verify TOTP code via POST /verify-totp', async () => {
      const validToken = generateTOTPToken(TEST_USER.totpSecret);

      const resSuccess = await request(app)
        .post('/verify-totp')
        .send({ email: TEST_USER.email, token: validToken });

      expect(resSuccess.status).toBe(200);
      expect(resSuccess.body.message).toBe('TOTP verified successfully');

      const resFail = await request(app)
        .post('/verify-totp')
        .send({ email: TEST_USER.email, token: '999999' });

      expect(resFail.status).toBe(401);
      expect(resFail.body.error).toBe('Invalid TOTP token');
    });
  });

  // -------------------------------------------------------------
  // Requirement 3: Secure Session Cookie Flags
  // -------------------------------------------------------------
  describe('3. Secure Cookie Flags (HttpOnly, Secure, SameSite=Strict)', () => {
    it('should return Set-Cookie with Secure, HttpOnly, and SameSite=Strict on login', async () => {
      const res = await request(app)
        .post('/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(res.status).toBe(200);
      expect(res.headers['set-cookie']).toBeDefined();

      const rawCookies = res.headers['set-cookie'];
      const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies].filter(Boolean) as string[];
      const sessionCookie = cookies.find((c: string) => c.startsWith('sessionId='));

      expect(sessionCookie).toBeDefined();
      expect(sessionCookie).toMatch(/HttpOnly/i);
      expect(sessionCookie).toMatch(/Secure/i);
      expect(sessionCookie).toMatch(/SameSite=Strict/i);
    });
  });

  // -------------------------------------------------------------
  // Requirement 4: Rate Limiting
  // -------------------------------------------------------------
  describe('4. Rate Limiting (Brute-Force Protection)', () => {
    it('should allow 5 failed attempts and trigger 429 Too Many Requests on the 6th attempt', async () => {
      const attackerPayload = {
        email: TEST_USER.email,
        password: 'WrongPasswordGuess',
      };

      // Attempts 1 through 5: should return 401 Unauthorized
      for (let i = 1; i <= 5; i++) {
        const res = await request(app).post('/login').send(attackerPayload);
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Invalid email or password');
      }

      // 6th attempt: should be blocked by rate limiter with 429 Too Many Requests
      const blockedRes = await request(app).post('/login').send(attackerPayload);
      expect(blockedRes.status).toBe(429);
      expect(blockedRes.body.error).toBe('Too Many Requests');
      expect(blockedRes.body.message).toMatch(/Too many failed login attempts/i);
    });
  });

  // -------------------------------------------------------------
  // Requirement 5: Session Rotation
  // -------------------------------------------------------------
  describe('5. Session Rotation on Successful Authentication', () => {
    it('should invalidate the old session ID and issue a new one upon subsequent login', async () => {
      // First login
      const firstLoginRes = await request(app)
        .post('/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(firstLoginRes.status).toBe(200);
      const firstSessionId = firstLoginRes.body.sessionId;
      expect(firstSessionId).toBeDefined();

      // Verify first session is active in session store
      expect(getSession(firstSessionId)).toBeDefined();
      expect(getSession(firstSessionId)?.userId).toBe(TEST_USER.id);

      // Extract first session cookie
      const firstCookies = firstLoginRes.headers['set-cookie'];

      // Second login sending previous session cookie
      const secondLoginRes = await request(app)
        .post('/login')
        .set('Cookie', firstCookies)
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(secondLoginRes.status).toBe(200);
      const secondSessionId = secondLoginRes.body.sessionId;
      expect(secondSessionId).toBeDefined();

      // Prove that a completely new session ID was generated (rotation)
      expect(secondSessionId).not.toBe(firstSessionId);

      // Prove that the old session ID is now invalidated and purged
      expect(getSession(firstSessionId)).toBeUndefined();

      // Prove that the new session ID is active
      expect(getSession(secondSessionId)).toBeDefined();
      expect(getSession(secondSessionId)?.userId).toBe(TEST_USER.id);
    });
  });
});
