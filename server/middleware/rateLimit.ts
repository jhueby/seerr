import type { Options } from 'express-rate-limit';
import rateLimit, { MemoryStore } from 'express-rate-limit';

const stores: MemoryStore[] = [];

/**
 * Rate limiters for the unauthenticated endpoints.
 *
 * Requests are keyed on the client IP. The forwarded headers are only trusted
 * when network.trustProxy is enabled (see server/index.ts), which express-rate-limit
 * cannot know about, so its own X-Forwarded-For heuristic is turned off to keep it
 * from warning about a setup we already handle.
 */
const createRateLimiter = (options: Partial<Options>) => {
  const store = new MemoryStore();
  stores.push(store);

  return rateLimit({
    store,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    handler: (_req, res) =>
      res.status(429).json({
        status: 429,
        error: 'Too many requests. Please try again later.',
      }),
    ...options,
  });
};

/** Clears every counter. Intended for tests, which reuse a single app instance. */
export const resetRateLimiters = async (): Promise<void> => {
  await Promise.all(stores.map((store) => store.resetAll()));
};

/**
 * Sign-in endpoints. Only failed attempts are counted, so a shared address
 * (households behind a single NAT, or a reverse proxy) does not lock itself out
 * through normal use.
 */
export const loginRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  skipSuccessfulRequests: true,
});

/**
 * Password reset. Both the request for a recovery link (which sends mail to a
 * third party) and the redemption of one are limited.
 */
export const passwordResetRateLimit = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 10,
});

/**
 * Starting a Quick Connect flow creates state on the media server, so it is
 * limited more tightly than the status polling that follows it.
 */
export const quickConnectInitiateRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 30,
});

/**
 * The client polls the Quick Connect status every two seconds while the modal is
 * open, so this only needs to be generous enough to not interfere with that.
 */
export const quickConnectCheckRateLimit = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  limit: 300,
});

export default createRateLimiter;
