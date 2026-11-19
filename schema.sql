-- =====================================================
-- Hiro Space Link — schema.sql (Neon PostgreSQL)
-- Jalankan: node server.js init-db   (atau paste di Neon SQL Editor)
-- =====================================================

-- Kredensial login: hanya 1 baris, PIN disimpan sebagai hash bcrypt
CREATE TABLE IF NOT EXISTS admin_auth (
  id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  pin_hash    TEXT        NOT NULL,
  pin_version INTEGER     NOT NULL DEFAULT 1,   -- naik tiap PIN diganti -> semua sesi lama otomatis invalid
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Profil pemilik (tampil di dashboard)
CREATE TABLE IF NOT EXISTS profile (
  id           SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  display_name VARCHAR(80)  NOT NULL,
  headline     VARCHAR(120) NOT NULL DEFAULT '',
  bio          VARCHAR(300) NOT NULL DEFAULT '',
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

INSERT INTO profile (id, display_name, headline, bio)
VALUES (1, 'Komang Agus', 'Developer & Pembelajar Bahasa Jepang',
        'Perpustakaan link pribadi saya — rapi, aman, dan siap dibagikan.')
ON CONFLICT (id) DO NOTHING;

-- Library link
CREATE TABLE IF NOT EXISTS links (
  id               SERIAL PRIMARY KEY,
  code             VARCHAR(16)  NOT NULL UNIQUE,            -- kode pendek untuk /s/:code (target QR)
  name             VARCHAR(120) NOT NULL,
  url              TEXT         NOT NULL CHECK (url ~* '^https?://'),
  category         VARCHAR(30)  NOT NULL CHECK (category IN (
                     'Resources','Academic','Project','Work','Google Drive','Google Maps',
                     'Github','Japanese','Instagram','Tiktok','Discord','Invitation')),
  credential_enc   TEXT,                                    -- terenkripsi AES-256-GCM (opsional)
  click_count      INTEGER      NOT NULL DEFAULT 0,
  scan_count       INTEGER      NOT NULL DEFAULT 0,
  last_accessed_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_links_category ON links (category);
CREATE INDEX IF NOT EXISTS idx_links_created  ON links (created_at DESC);