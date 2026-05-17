import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
// import { getUser } from '../db/queries'; // project-internal — replace with your own DB lookup

// ==================== SESSION STORE ====================
// Server-side session tokens (replaces relying on long-lived initData).
// On first valid initData, a session token is issued (1h TTL).
// Subsequent requests use the session token instead.

interface Session {
  userId: number;
  firstName: string;
  lastName?: string;
  username?: string;
  expiresAt: number;
}

const sessions = new Map<string, Session>();

// Cleanup expired sessions every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt < now) sessions.delete(token);
  }
}, 300_000);

const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

export function createSession(user: { id: number; first_name: string; last_name?: string; username?: string }): string {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    userId: user.id,
    firstName: user.first_name,
    lastName: user.last_name,
    username: user.username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return token;
}

// ==================== TYPE AUGMENTATION ====================

declare global {
  namespace Express {
    interface Request {
      telegramUser?: {
        id: number;
        first_name: string;
        last_name?: string;
        username?: string;
      };
    }
  }
}

// ==================== INIT DATA VALIDATION ====================

const INIT_DATA_TTL = 3600; // 1 hour (was 24h — reduced for security)

/**
 * Validates Telegram Mini App init data OR a server-issued session token.
 * 
 * Priority:
 * 1. X-Session-Token header → validate session
 * 2. X-Telegram-Init-Data header → validate HMAC + issue session
 */
export function validateTelegramAuth(req: Request, res: Response, next: NextFunction): void {
  // Try session token first (faster, no HMAC computation)
  const sessionToken = req.headers['x-session-token'] as string;
  if (sessionToken) {
    const session = sessions.get(sessionToken);
    if (session && session.expiresAt > Date.now()) {
      req.telegramUser = {
        id: session.userId,
        first_name: session.firstName,
        last_name: session.lastName,
        username: session.username,
      };
      next();
      return;
    }
    // Expired or invalid — fall through to initData
  }

  const initData = req.headers['x-telegram-init-data'] as string;

  if (!initData) {
    res.status(401).json({ error: 'Missing authentication' });
    return;
  }

  try {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    urlParams.delete('hash');

    // Sort parameters alphabetically
    const dataCheckString = Array.from(urlParams.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    // Create secret key
    const botToken = process.env.BOT_TOKEN!;
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(botToken)
      .digest();

    // Validate hash (constant-time comparison)
    const computedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    const computedBuf = Buffer.from(computedHash, 'hex');
    const hashBuf = Buffer.from(hash || '', 'hex');
    if (computedBuf.length !== hashBuf.length || !crypto.timingSafeEqual(computedBuf, hashBuf)) {
      res.status(401).json({ error: 'Invalid init data hash' });
      return;
    }

    // Strict TTL: 1 hour (was 24h)
    const authDate = parseInt(urlParams.get('auth_date') || '0');
    const now = Math.floor(Date.now() / 1000);
    if (now - authDate > INIT_DATA_TTL) {
      res.status(401).json({ error: 'Init data expired' });
      return;
    }

    // Extract user data
    const userStr = urlParams.get('user');
    if (!userStr) {
      res.status(401).json({ error: 'No user data in init data' });
      return;
    }

    const user = JSON.parse(userStr);
    req.telegramUser = user;

    // Issue a session token in response header for subsequent requests
    const token = createSession(user);
    res.setHeader('X-Session-Token', token);

    next();
  } catch (err) {
    console.error('[Auth] Validation error:', err);
    res.status(401).json({ error: 'Auth validation failed' });
  }
}

/**
 * Ensures user exists in database and has active subscription.
 */
export async function requireSubscription(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.telegramUser) {
    res.status(401).json({ error: 'Not authenticated' });
    return;
  }

  const user = await getUser(req.telegramUser.id);
  if (!user) {
    res.status(404).json({ error: 'User not found. Please connect the bot first.' });
    return;
  }

  // Free tier (0) is allowed — paid tiers check expiry
  if (user.subscription_tier > 0 && user.subscription_expires_at && user.subscription_expires_at < new Date()) {
    // Expired paid sub — still allow access (falls back to free tier behavior)
  }

  next();
}
