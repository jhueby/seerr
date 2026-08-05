/**
 * Response headers applied to every request.
 *
 * Deliberately limited to headers that cannot change how a correct client renders
 * the app, so that existing deployments keep working. Framing is not restricted
 * here because embedding Seerr in a dashboard (Organizr, Homarr, ...) is a common
 * setup; operators who do not need that should send X-Frame-Options or a
 * frame-ancestors policy from their reverse proxy.
 */
const securityHeaders: Middleware = (_req, res, next) => {
  // Stop the browser from second-guessing our Content-Type, which is what turns a
  // proxied image or an uploaded file into a script.
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Keep the full URL (which can carry password reset GUIDs and media IDs) out of
  // the Referer header sent to third parties.
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // The legacy XSS auditor introduced vulnerabilities of its own; explicitly off
  // is the current guidance.
  res.setHeader('X-XSS-Protection', '0');

  next();
};

export default securityHeaders;
