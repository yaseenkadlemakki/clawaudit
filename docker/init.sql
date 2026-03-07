-- ClawAudit PostgreSQL initialisation
-- Run automatically by docker-entrypoint-initdb.d on first start.
-- SQLAlchemy create_all() handles table creation; this script sets up
-- extensions and sensible defaults.

-- Enable uuid-ossp for gen_random_uuid() fallback (PG < 13 compat)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Ensure the clawaudit role can create tables in public schema
GRANT ALL ON SCHEMA public TO clawaudit;
