import express, { type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import {
  verifyPassword,
  verifyTOTP,
  createSession,
  invalidateSession,
  setSessionCookie,
  sessionStore,
} from './auth.js';

export interface MockUser {
  id: string;
  email: string;
  passwordHash: string;
  totpSecret: string;
}

// In-memory mock database of users
export const mockUsers = new Map<string, MockUser>();

// Rate limiting state tracking: key -> { count, firstAttemptAt }
export interface RateLimitRecord {
  count: number;
  firstAttemptAt: number;
}
export const rateLimitStore = new Map<string, RateLimitRecord>();
export const MAX_LOGIN_ATTEMPTS = 5;

/**
 * Checks if the IP/email combination has exceeded the maximum failed attempts threshold.
 * Throws an Error if rate-limited.
 */
export function checkRateLimit(ip: string, email: string): void {
  const key = `${ip}:${email.toLowerCase()}`;
  const record = rateLimitStore.get(key);

  if (record && record.count >= MAX_LOGIN_ATTEMPTS) {
    const error: any = new Error('Too many failed login attempts. Please try again later.');
    error.status = 429;
    throw error;
  }
}

/**
 * Records a failed login attempt for the IP/email.
 */
export function recordFailedAttempt(ip: string, email: string): void {
  const key = `${ip}:${email.toLowerCase()}`;
  const record = rateLimitStore.get(key);

  if (!record) {
    rateLimitStore.set(key, { count: 1, firstAttemptAt: Date.now() });
  } else {
    record.count += 1;
  }
}

/**
 * Resets rate limit attempts for an IP/email on successful login.
 */
export function resetRateLimit(ip: string, email: string): void {
  const key = `${ip}:${email.toLowerCase()}`;
  rateLimitStore.delete(key);
}

/**
 * Clears rate limiter storage (used during test teardown).
 */
export function clearRateLimits(): void {
  rateLimitStore.clear();
}

/**
 * Clears mock users (used during test teardown).
 */
export function clearMockUsers(): void {
  mockUsers.clear();
}

/**
 * Seeds a user into the mock database.
 */
export function seedUser(user: MockUser): void {
  mockUsers.set(user.email.toLowerCase(), user);
}

// Initialize Express application
export const app = express();
app.use(express.json());
app.use(cookieParser());

/**
 * POST /login
 * Authenticates user credentials, applies rate limiting, rotates sessions,
 * and sets secure HttpOnly/Secure/SameSite=Strict cookie.
 */
app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';

  // 1. Check Rate Limiter
  try {
    checkRateLimit(clientIp, email);
  } catch (err: any) {
    return res.status(429).json({
      error: 'Too Many Requests',
      message: err.message,
    });
  }

  // 2. Query Mock Database
  const user = mockUsers.get(email.toLowerCase());
  if (!user) {
    recordFailedAttempt(clientIp, email);
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // 3. Verify Argon2id Password Hash
  const isPasswordValid = await verifyPassword(user.passwordHash, password);
  if (!isPasswordValid) {
    recordFailedAttempt(clientIp, email);
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Reset rate limiting upon valid login
  resetRateLimit(clientIp, email);

  // 4. Session Rotation
  // Invalidate any existing session from cookies to prevent session fixation attacks
  const existingSessionId = req.cookies?.sessionId;
  if (existingSessionId) {
    invalidateSession(existingSessionId);
  }

  // Also invalidate any existing active session belonging to this user
  for (const [id, session] of sessionStore.entries()) {
    if (session.userId === user.id) {
      sessionStore.delete(id);
    }
  }

  // Generate new, rotated session
  const newSessionId = createSession(user.id);

  // 5. Set Cookie with Secure, HttpOnly, and SameSite=Strict flags
  setSessionCookie(res, newSessionId);

  return res.status(200).json({
    message: 'Login successful',
    userId: user.id,
    sessionId: newSessionId,
  });
});

/**
 * POST /verify-totp
 * Verifies a 6-digit TOTP code for a user.
 */
app.post('/verify-totp', (req: Request, res: Response) => {
  const { email, token } = req.body;

  if (!email || !token) {
    return res.status(400).json({ error: 'Email and token are required' });
  }

  const user = mockUsers.get(email.toLowerCase());
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const isValid = verifyTOTP(user.totpSecret, token);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid TOTP token' });
  }

  return res.status(200).json({ message: 'TOTP verified successfully' });
});

