// [RMR] Notation constants from the shared context. Do not invent alternatives.

/** Values fixed by the shared context block. Changing one is a design change. */
export const NOTATION = Object.freeze({
  /** S_id: the WebAuthn RP ID. UDK-6 re-exports this as the single source for signer and RP config. */
  S_ID: 'auth.deltaforce.lk',
  NONCE_BYTES: 32,
  SESSION_ID_BYTES: 32,
  X25519_PUBLIC_KEY_BYTES: 32,
  /** HPKE (RFC 9180) suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
  HPKE: Object.freeze({ KEM_ID: 0x0020, KDF_ID: 0x0001, AEAD_ID: 0x0002 }),
  /** HPKE encapsulated key (X25519 public key) and ciphertext of a 32-byte session key + 16-byte tag. */
  HPKE_ENC_BYTES: 32,
  HPKE_SEALED_KEY_BYTES: 48,
  AES_GCM: Object.freeze({ KEY_BYTES: 32, IV_BYTES: 12, TAG_BYTES: 16 }),
  /** sigma_s: ECDSA P-256, IEEE-P1363 (r || s), 2 x 32 bytes. */
  SIGMA_S_BYTES: 64,
  OTP: Object.freeze({ DIGITS: 6, TTL_SECONDS: 180 }),
  PENDING_AUTH: Object.freeze({ TTL_SECONDS: 600, MAX_VERIFY_ATTEMPTS: 5 }),
  ARGON2ID: Object.freeze({ MEMORY_KIB: 19456, ITERATIONS: 2, PARALLELISM: 1, SALT_BYTES: 16 }),
  RECOVERY: Object.freeze({
    COUNT: 10,
    LENGTH: 10,
    /** Crockford base32: no I, L, O, U. */
    ALPHABET: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
  }),
} as const);

/** Protocol message number, used as AES-GCM additional authenticated data (RMR-5). */
export const MESSAGE_INDEX = Object.freeze({
  HELLO: 1,
  SERVER_HELLO: 2,
  PASSWORD: 3,
  CHALLENGE: 4,
  RESPONSE: 5,
  RESULT: 6,
} as const);

export const FACTOR_TYPES = ['fido2', 'voice', 'haptic'] as const;
export type FactorType = (typeof FACTOR_TYPES)[number];

/** Channels an OTP can be delivered over (the third input of the OTP HMAC). */
export const OTP_CHANNELS = ['voice', 'haptic'] as const;
export type OtpChannel = (typeof OTP_CHANNELS)[number];

// Our own bounds, not from the shared context. Team can change these.
export const IMPLEMENTATION_LIMITS = Object.freeze({
  U_ID_MAX_CHARS: 254,
  /** NIST SP 800-63B minimum for a password used with a second factor. Counted in code points. */
  PASSWORD_MIN_CHARS: 8,
  PASSWORD_MAX_CHARS: 1024,
  S_ID_MAX_BYTES: 253,
  MESSAGE_MAX_BYTES: 16 * 1024,
} as const);
