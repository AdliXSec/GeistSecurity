-- ==============================================================================
-- SecAudit / AuraSec - Supabase PostgreSQL Schema
-- Jalankan skrip ini di SQL Editor pada Dashboard Supabase Anda:
-- https://supabase.com/dashboard/project/<PROJECT_ID>/sql
-- ==============================================================================

-- 1. Tabel audits: Menyimpan sesi audit, status recon, DAST, dan laporan JSON lengkap
CREATE TABLE IF NOT EXISTS audits (
    session_id TEXT PRIMARY KEY,
    user_id TEXT,
    project_name TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    target_url TEXT,
    github_repo_url TEXT,
    branch TEXT DEFAULT 'main',
    score INTEGER DEFAULT 0,
    grade TEXT DEFAULT 'D',
    grade_label TEXT DEFAULT '',
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    report_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Indeks untuk query performa tinggi
CREATE INDEX IF NOT EXISTS idx_audits_user_id ON audits (user_id);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits (created_at DESC);

-- 2. Tabel users: Menyimpan kredensial dan akun pengguna
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    created_at TEXT NOT NULL
);

-- Indeks pencarian username dan email
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- 3. Nonaktifkan Row Level Security (RLS) agar backend API dapat membaca/menulis data
ALTER TABLE audits DISABLE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- 4. Tabel presets: Menyimpan preset konfigurasi audit user dan demo
CREATE TABLE IF NOT EXISTS presets (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    project_name TEXT NOT NULL,
    mode TEXT NOT NULL,
    url TEXT,
    repo TEXT,
    branch TEXT DEFAULT 'main',
    is_demo BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Indeks untuk pencarian preset per user
CREATE INDEX IF NOT EXISTS idx_presets_user_id ON presets (user_id);
CREATE INDEX IF NOT EXISTS idx_presets_created_at ON presets (created_at ASC);

-- Pastikan kolom jika tabel presets sudah pernah dibuat sebelumnya
ALTER TABLE presets ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT FALSE;
ALTER TABLE presets ADD COLUMN IF NOT EXISTS branch TEXT DEFAULT 'main';
ALTER TABLE presets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW());

ALTER TABLE presets DISABLE ROW LEVEL SECURITY;

-- 5. Data Demo Awal (Optional)
INSERT INTO audits (
    session_id, user_id, project_name, mode, status,
    target_url, github_repo_url, branch,
    score, grade, grade_label, critical_count, high_count, duration_ms,
    created_at, updated_at
) VALUES (
    'demo-fintech', NULL, 'Fintech Payment Core', 'HYBRID', 'COMPLETED',
    'https://demo-fintech.auraglass.io', 'https://github.com/auraglass/fintech-core', 'main',
    38, 'D', 'Grade D (38/100)', 3, 3, 24200,
    '2026-10-24T02:15:22Z', '2026-10-24T02:15:22Z'
) ON CONFLICT (session_id) DO NOTHING;

INSERT INTO presets (
    id, user_id, project_name, mode, url, repo, branch, is_demo, created_at, updated_at
) VALUES (
    'demo-fintech', NULL, 'Fintech Payment Gateway (Demo)', 'HYBRID',
    'https://demo-fintech.auraglass.io', 'https://github.com/auraglass/fintech-dashboard-api', 'main', TRUE,
    '2026-10-24T02:15:22Z', '2026-10-24T02:15:22Z'
) ON CONFLICT (id) DO NOTHING;
