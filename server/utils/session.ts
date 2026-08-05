import { getRepository } from '@server/datasource';
import { Session } from '@server/entity/Session';
import logger from '@server/logger';
import type { Request } from 'express';
import { In } from 'typeorm';

/**
 * Signs a user in on the current request.
 *
 * The session is regenerated first so that a session ID an attacker managed to
 * plant in the browser before sign-in (session fixation) cannot be used to ride
 * along on the authenticated session. The new session is saved before we resolve,
 * so the caller can safely respond once this settles.
 */
export const setSessionUser = (req: Request, userId: number): Promise<void> =>
  new Promise((resolve, reject) => {
    if (!req.session) {
      resolve();
      return;
    }

    req.session.regenerate((regenerateError) => {
      if (regenerateError) {
        reject(regenerateError);
        return;
      }

      req.session.userId = userId;

      req.session.save((saveError) => {
        if (saveError) {
          reject(saveError);
          return;
        }
        resolve();
      });
    });
  });

/**
 * Destroys every stored session belonging to a user, optionally sparing one (the
 * session that performed the action). Used to make a password change take effect
 * everywhere instead of leaving other browsers signed in with the old credentials.
 *
 * The session payload is stored as opaque JSON by connect-typeorm, so it is
 * filtered in memory rather than with a database-specific JSON query.
 */
export const destroyUserSessions = async (
  userId: number,
  exceptSessionId?: string
): Promise<void> => {
  try {
    const sessionRepository = getRepository(Session);
    const sessions = await sessionRepository.find();

    const staleSessionIds = sessions
      .filter((session) => {
        if (session.id === exceptSessionId) {
          return false;
        }

        try {
          return (JSON.parse(session.json)?.userId ?? null) === userId;
        } catch {
          return false;
        }
      })
      .map((session) => session.id);

    if (staleSessionIds.length) {
      await sessionRepository.delete({ id: In(staleSessionIds) });
    }
  } catch (e) {
    // A failure here must not block the password change that triggered it.
    logger.error('Failed to destroy existing sessions for user', {
      label: 'Auth',
      errorMessage: e.message,
      userId,
    });
  }
};
