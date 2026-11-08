import argon2 from 'argon2';
import { authenticator } from 'otplib';
import crypto from 'node:crypto';
import type { Response } from 'express';

export interface SessionData {
  userId: string;
  createdAt: number;
}

// In-memory session store (mapping sessionId -> SessionData)
export const sessionStore = new Map<string, SessionData>();

// Argon2id Recommended Baseline Parameters (OWASP specifications)
export const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3,      // 3 iterations
  parallelism: 4,   // 4 parallel threads
};

/**
 * Hashes a plain-text password using the Argon2id algorithm.
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_CONFIG);
}

/**
 * Verifies a plain-text password against an Argon2 hash.
 */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Checks whether an existing password hash needs to be rehashed
 * due to outdated parameters (e.g. low memory cost or non-Argon2id type).
 */
export function shouldRehash(hash: string, targetMemoryCost = ARGON2_CONFIG.memoryCost): boolean {
  // Argon2 hash pattern: $argon2id$v=19$m=65536,t=3,p=4$...
  if (!hash.startsWith('$argon2id$')) {
    return true; // Not modern Argon2id
  }

  const match = hash.match(/\$m=(\d+)/);
  if (!match) {
    return true;
  }

  const memoryCost = parseInt(match[1], 10);
  return memoryCost < targetMemoryCost;
}

/**
 * Generates a random Base32 TOTP secret key using otplib.
 */
export function generateTOTPSecret(): string {
  return authenticator.generateSecret();
}

/**
 * Generates the current 6-digit TOTP token for a given secret.
 */
export function generateTOTPToken(secret: string): string {
  return authenticator.generate(secret);
}

/**
 * Verifies a 6-digit TOTP code against the provided secret.
 */
export function verifyTOTP(secret: string, token: string): boolean {
  try {
    return authenticator.verify({ token, secret });
  } catch {
    return false;
  }
}

/**
 * Generates a cryptographically secure random session ID and records it in the session store.
 */
export function createSession(userId: string): string {
  const sessionId = crypto.randomBytes(32).toString('hex');
  sessionStore.set(sessionId, {
    userId,
    createdAt: Date.now(),
  });
  return sessionId;
}

/**
 * Retrieves session data for a given session ID.
 */
export function getSession(sessionId: string): SessionData | undefined {
  return sessionStore.get(sessionId);
}

/**
 * Invalidates an active session ID (used in logout and session rotation).
 */
export function invalidateSession(sessionId: string): boolean {
  return sessionStore.delete(sessionId);
}

/**
 * Clears all active sessions (used during test teardown).
 */
export function clearAllSessions(): void {
  sessionStore.clear();
}

/**
 * Sets a session cookie with required security flags:
 * - HttpOnly (prevents client-side XSS access)
 * - Secure (only transmitted over HTTPS)
 * - SameSite=Strict (mitigates CSRF)
 */
export function setSessionCookie(res: Response, sessionId: string): void {
  res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 3600 * 1000, // 1 hour expiration
  });
}
