-- CreateEnum
CREATE TYPE "AuthenticatorType" AS ENUM ('fido2', 'voice', 'haptic');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "username" VARCHAR(128) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "recovery_codes_acknowledged_at" TIMESTAMPTZ(6),

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_credentials" (
    "user_id" UUID NOT NULL,
    "hash" TEXT NOT NULL,
    "memory_kib" INTEGER NOT NULL,
    "time_cost" INTEGER NOT NULL,
    "parallelism" INTEGER NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "password_credentials_pkey" PRIMARY KEY ("user_id")
);

-- CreateTable
CREATE TABLE "authenticators" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "type" "AuthenticatorType" NOT NULL,
    "nickname" VARCHAR(128) NOT NULL,
    "public_key" BYTEA,
    "credential_id_encrypted" BYTEA,
    "credential_id_digest" TEXT,
    "channel_address_encrypted" BYTEA,
    "address_hint" VARCHAR(16),
    "signature_counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "aaguid" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),

    CONSTRAINT "authenticators_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recovery_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "hash" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "used_at" TIMESTAMPTZ(6),

    CONSTRAINT "recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auth_events" (
    "id" BIGSERIAL NOT NULL,
    "user_id" UUID,
    "event_type" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "prev_hash" VARCHAR(64),
    "event_hash" VARCHAR(64),

    CONSTRAINT "auth_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "user_id" UUID NOT NULL,
    "factor_used" "AuthenticatorType" NOT NULL,
    "issued_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

-- CreateIndex
CREATE UNIQUE INDEX "authenticators_credential_id_digest_key" ON "authenticators"("credential_id_digest");

-- CreateIndex
CREATE INDEX "authenticators_user_id_revoked_at_idx" ON "authenticators"("user_id", "revoked_at");

-- CreateIndex
CREATE INDEX "recovery_codes_user_id_idx" ON "recovery_codes"("user_id");

-- CreateIndex
CREATE INDEX "auth_events_user_id_created_at_idx" ON "auth_events"("user_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_token_hash_key" ON "sessions"("token_hash");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- AddForeignKey
ALTER TABLE "password_credentials" ADD CONSTRAINT "password_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authenticators" ADD CONSTRAINT "authenticators_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_events" ADD CONSTRAINT "auth_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Audit rows are immutable even when accessed outside the service layer.
CREATE FUNCTION reject_auth_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'AUTH_EVENTS_APPEND_ONLY';
END;
$$;
CREATE TRIGGER auth_events_no_mutation
BEFORE UPDATE OR DELETE ON auth_events
FOR EACH ROW EXECUTE FUNCTION reject_auth_event_mutation();
CREATE TRIGGER auth_events_no_truncate
BEFORE TRUNCATE ON auth_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_auth_event_mutation();

ALTER TABLE password_credentials ADD CONSTRAINT password_parameters_positive
CHECK (memory_kib > 0 AND time_cost > 0 AND parallelism > 0);
ALTER TABLE authenticators ADD CONSTRAINT authenticator_material_matches_type CHECK (
  (type = 'fido2' AND public_key IS NOT NULL AND credential_id_encrypted IS NOT NULL AND credential_id_digest IS NOT NULL AND channel_address_encrypted IS NULL)
  OR (type = 'voice' AND channel_address_encrypted IS NOT NULL AND credential_id_encrypted IS NULL)
  OR (type = 'haptic' AND channel_address_encrypted IS NOT NULL AND public_key IS NOT NULL AND credential_id_encrypted IS NULL)
);
ALTER TABLE authenticators ADD CONSTRAINT masked_address_hint
CHECK (address_hint IS NULL OR address_hint ~ '^••••[0-9]{0,4}$');
