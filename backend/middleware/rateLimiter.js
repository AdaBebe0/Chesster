/**
 * Simple in-memory fixed-window rate limiter.
 *
 * Tracks request counts per key (IP by default) and rejects requests over
 * `max` within `windowMs` with a 429. Not distributed — fine for a single
 * backend instance, not for a multi-node deployment without a shared store.
 */
function createRateLimiter({
	windowMs = 60_000,
	max = 100,
	message = "Too many requests, please try again later.",
	keyGenerator = (req) => req.ip || req.connection?.remoteAddress || "unknown",
} = {}) {
	const hits = new Map(); // key -> { count, resetAt }

	function rateLimiter(req, res, next) {
		const key = keyGenerator(req);
		const now = Date.now();
		let entry = hits.get(key);

		if (!entry || now >= entry.resetAt) {
			entry = { count: 0, resetAt: now + windowMs };
			hits.set(key, entry);
		}

		entry.count += 1;

		res.set("X-RateLimit-Limit", String(max));
		res.set("X-RateLimit-Remaining", String(Math.max(0, max - entry.count)));

		if (entry.count > max) {
			const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
			res.set("Retry-After", String(retryAfterSec));
			return res.status(429).json({ success: false, error: message });
		}

		return next();
	}

	// Exposed for tests that need to assert on internal state or force a reset
	// between cases without waiting out the real window.
	rateLimiter.reset = () => hits.clear();

	return rateLimiter;
}

/**
 * Tracks hit counts for a single key space within a fixed window, without
 * attaching HTTP semantics. Shared by `createAuthChallengeRateLimiter` so the
 * IP and wallet-address windows can be checked independently before either
 * one writes a response.
 */
function createWindowCounter({ windowMs, max }) {
	const hits = new Map(); // key -> { count, resetAt }

	return {
		hit(key) {
			const now = Date.now();
			let entry = hits.get(key);

			if (!entry || now >= entry.resetAt) {
				entry = { count: 0, resetAt: now + windowMs };
				hits.set(key, entry);
			}

			entry.count += 1;

			return {
				exceeded: entry.count > max,
				retryAfterSec: Math.ceil((entry.resetAt - now) / 1000),
			};
		},
		reset() {
			hits.clear();
		},
	};
}

/**
 * Sliding-window-style limiter for the wallet auth challenge endpoint
 * (`POST /api/auth/challenge`), enforcing two independent caps:
 *   - `ipMax` requests per `windowMs` from a single IP address.
 *   - `addressMax` pending challenge requests per `windowMs` for the same
 *     wallet address, regardless of source IP (skipped when no address is
 *     present on the request; the IP cap still applies).
 *
 * Responds with the structured 429 shape required by the auth challenge
 * contract: `{ error: 'Too Many Requests', retryAfter: <seconds> }`.
 */
function createAuthChallengeRateLimiter({
	windowMs = 60_000,
	ipMax = 10,
	addressMax = 3,
	addressGenerator = (req) => req.body?.address || req.query?.address,
} = {}) {
	const ipCounter = createWindowCounter({ windowMs, max: ipMax });
	const addressCounter = createWindowCounter({ windowMs, max: addressMax });

	function reject(res, retryAfterSec) {
		res.set("Retry-After", String(retryAfterSec));
		return res.status(429).json({ error: "Too Many Requests", retryAfter: retryAfterSec });
	}

	function authChallengeRateLimiter(req, res, next) {
		const ipKey = req.ip || req.connection?.remoteAddress || "unknown";
		const ipResult = ipCounter.hit(ipKey);
		if (ipResult.exceeded) return reject(res, ipResult.retryAfterSec);

		const address = addressGenerator(req);
		if (address) {
			const addressResult = addressCounter.hit(`addr:${address}`);
			if (addressResult.exceeded) return reject(res, addressResult.retryAfterSec);
		}

		return next();
	}

	authChallengeRateLimiter.reset = () => {
		ipCounter.reset();
		addressCounter.reset();
	};

	return authChallengeRateLimiter;
}

module.exports = { createRateLimiter, createAuthChallengeRateLimiter };
