# PRD: Hybrid AI Web & Source Code Security Auditor Platform

**File Location:** `tasks/prd-hybrid-ai-security-auditor.md`  
**Version:** 1.0.0 (Hackathon & MVP Production Ready)  
**Target Stack:** Next.js (React + Tailwind CSS) | Python FastAPI | PostgreSQL (JSONB) | Redis / Async Worker | Semgrep CLI & OSV.dev API | Gemini 2.5 Flash API  

---

## 1. Introduction / Overview

Platform ini adalah sistem **Automated Web Security Posture & Source Code Auditor** yang menggabungkan pendekatan **Declarative Rule-Based Engine (ala Nuclei)**, **Static Application Security Testing (SAST / AST Taint Analysis)**, **Software Composition Analysis (SCA / CVE Mapping)**, dan **Generative AI Auto-Remediation** dalam satu dashboard web terpadu.

Aplikasi web modern sering kali memiliki celah di dua sisi sekaligus: kesalahan konfigurasi pada sisi server produksi (*Blackbox*) dan kelemahan logika kode, dependensi usang (CVE), atau kebocoran kredensial/informasi di dalam bundel JavaScript (*Whitebox*). Di sisi lain, *scanner* tradisional hanya menampilkan daftar temuan teknis tanpa memberikan kode perbaikan yang siap pakai, atau memakan waktu lama tanpa transparansi progres di antarmuka pengguna.

Platform ini menyelesaikan masalah tersebut melalui **3 Mode Audit** (**Blackbox URL**, **Whitebox GitHub Link**, dan **Hybrid Correlation Mode**), antarmuka **Real-Time Telemetry Loading berbasis Server-Sent Events (SSE)**, deteksi eksposur JavaScript modern menggunakan **Regex + Shannon Entropy + Auto-Redaction**, perhitungan **Security Posture Score (0–100 / Grade A–F)**, serta **Interactive Before vs. After Code Diff** yang dihasilkan secara kontekstual oleh AI.

---

## 2. Goals

- **Multi-Mode Security Auditing:** Mengizinkan pengguna melakukan audit keamanan melalui input URL aktif (*Blackbox*), tautan repositori GitHub (*Whitebox*), atau gabungan keduanya (*Hybrid Correlation*) dalam satu sesi.
- **Deep & Non-Destructive Vulnerability Detection:** Mendeteksi celah mendalam seperti **XSS** (melalui *AST Source-to-Sink Taint Analysis* & *DOM Sink Inspection*), **SQL Injection**, serta **CVE** pada dependensi dan komponen server (melalui integrasi **OSV.dev / NVD API**) secara aman tanpa mengirimkan payload destruktif ke target produksi.
- **Modern JavaScript Exposure & Secret Scanning:** Mendeteksi kebocoran *Private API Keys/Tokens* menggunakan kombinasi pola *prefix* dan perhitungan **Shannon Entropy**, serta mendeteksi temuan informatif (**INFO**) seperti alamat email internal yang tersebar di bundel JavaScript publik dan eksposur file `.js.map` (*Source Maps*).
- **Zero Plaintext Credential Leak (Mandatory Auto-Redaction):** Menjamin 100% temuan sensitif (API key, token, dan email) disensor secara otomatis (*masked/redacted*) sebelum disimpan ke database atau ditampilkan di UI.
- **Real-Time Loading UX via SSE:** Menampilkan progres pemindaian secara langsung (*live streaming* 5 tahap dari 15% hingga 100%) menggunakan *Server-Sent Events (SSE)* agar pengguna mendapatkan transparansi proses secara *real-time*.
- **Actionable AI Remediation & Code Diff:** Menghasilkan penjelasan risiko dan *patch* kode perbaikan (**Before vs. After Diff**) yang tervalidasi menggunakan skema Pydantic (*Structured JSON Output*) berdasarkan *tech stack* yang terdeteksi.

---

## 3. User Stories

### US-001: Penyimpanan Data Audit pada Skema Database PostgreSQL (Hybrid Relational + JSONB)
**Description:** Sebagai backend developer, saya membutuhkan skema database PostgreSQL yang terstruktur dengan dukungan kolom `JSONB` dan indeks performa tinggi agar data target, sesi audit, log progres SSE, daftar temuan (`CRITICAL` hingga `INFO`), serta kode perbaikan AI tersimpan secara konsisten.

**Acceptance Criteria:**
- [ ] Membuat ENUM types: `audit_mode_enum`, `audit_status_enum`, `severity_enum`, dan `finding_category_enum`.
- [ ] Membuat 5 tabel utama: `targets`, `audit_sessions`, `audit_findings`, `ai_remediations`, dan `audit_stage_logs`.
- [ ] Menambahkan indeks B-Tree pada foreign keys dan GIN Index pada kolom `evidence_metadata` (`JSONB`).
- [ ] Migrasi database berjalan sukses tanpa error.
- [ ] Typecheck/lint passes.

---

### US-002: Input Target Audit & Pemilihan Mode (Blackbox, Whitebox, Hybrid)
**Description:** Sebagai pengguna (developer/security auditor), saya ingin memasukkan URL website, link repositori GitHub, atau keduanya di halaman utama agar saya dapat memilih kedalaman audit sesuai kebutuhan.

**Acceptance Criteria:**
- [ ] Menampilkan pilihan tab/mode: **Blackbox (URL Only)**, **Whitebox (GitHub Repo Only)**, dan **Hybrid (Full-Stack URL + GitHub)**.
- [ ] Validasi format input URL (`https://...`) dan URL repositori GitHub (`https://github.com/owner/repo`) beserta input opsional nama *branch* (default: `main`).
- [ ] Saat tombol "Mulai Audit Keamanan" diklik, frontend mengirim request `POST /api/v1/audits` dan menerima `session_id` beserta `stream_endpoint`.
- [ ] Typecheck/lint passes.
- [ ] Verify in browser using dev-browser skill.

---

### US-003: Verifikasi Kepemilikan Domain & Demo Sandbox Mode (Auto-Bypass)
**Description:** Sebagai peninjau/juri hackathon, saya ingin sistem dapat menguji URL apa saja secara instan saat *live demo* tanpa harus repot mengatur DNS TXT record terlebih dahulu, namun tetap mempertahankan simulasi alur verifikasi yang profesional.

**Acceptance Criteria:**
- [ ] Worker tetap memblokir seluruh *outbound request* ke rentang IP privat/lokal (`127.0.0.0/8`, `10.0.0.0/8`, dll.) untuk mencegah SSRF.
- [ ] **Demo Sandbox Mode:** Jika flag environment `DEMO_MODE=true` aktif (standar hackathon), sistem secara otomatis menganggap target URL berstatus `Verified` setelah menampilkan animasi *check token* singkat di UI, sehingga tidak ada error DNS saat juri memasukkan URL uji coba.
- [ ] Typecheck/lint passes.
- [ ] Verify in browser using dev-browser skill.

---

### US-004: Engine Audit Blackbox Berbasis Template YAML (Ala Nuclei)
**Description:** Sebagai pengguna, saya ingin sistem mengaudit postur keamanan HTTP, TLS/SSL, Cookie, dan CORS dari URL yang saya masukkan menggunakan aturan deklaratif YAML agar celah konfigurasi server terdeteksi secara akurat.

**Acceptance Criteria:**
- [ ] Worker dapat mem-parsing file template YAML yang berisi blok `id`, `info` (name, severity, cwe, remediation), `http` (method, path), dan `matchers` (header, status, word, regex, negative match).
- [ ] Mengevaluasi keberadaan dan ketepatan konfigurasi `Strict-Transport-Security (HSTS)`, `Content-Security-Policy (CSP)`, `X-Frame-Options`, `X-Content-Type-Options`, dan `Referrer-Policy`.
- [ ] Memeriksa atribut keamanan pada header `Set-Cookie` (`HttpOnly`, `Secure`, `SameSite`).
- [ ] Memeriksa validitas sertifikat TLS/SSL serta kesalahan konfigurasi header `Access-Control-Allow-Origin` (CORS).
- [ ] Melakukan *tech stack fingerprinting* pasif dari respons header dan meta tag HTML (misal: mendeteksi versi Nginx, Next.js, React, atau Laravel).
- [ ] Typecheck/lint passes.

---

### US-005: Deteksi Mendalam Kerentanan CVE (Whitebox Lockfile & Blackbox Version Mapping)
**Description:** Sebagai pengguna, saya ingin mengetahui apakah proyek web saya menggunakan *library* atau komponen server yang memiliki kerentanan **CVE** yang telah dipublikasikan beserta informasi versi perbaikannya.

**Acceptance Criteria:**
- [ ] **Jalur Whitebox:** Melakukan *shallow clone* (`git clone --depth 1`) ke direktori sementara yang terisolasi, mengekstrak daftar paket beserta versinya dari `package-lock.json`, `yarn.lock`, `composer.lock`, `requirements.txt`, atau `go.sum`, lalu melakukan *batch query* ke **OSV.dev API** (`https://api.osv.dev/v1/querybatch`).
- [ ] **Analisis Reachability (Whitebox):** Memeriksa apakah paket yang terdampak CVE benar-benar di-import di dalam kode sumber proyek dan menandainya di `evidence_metadata.is_reachable_in_code`.
- [ ] **Jalur Blackbox:** Mencocokkan nama dan versi pustaka frontend/server yang terdeteksi dari *fingerprinting* aset publik ke database OSV/NVD API.
- [ ] Menghapus direktori sementara hasil *git clone* segera setelah sesi audit selesai.
- [ ] Typecheck/lint passes.

---

### US-006: Deteksi Mendalam XSS & Injeksi (AST Taint Analysis & DOM Sink Scanner)
**Description:** Sebagai pengguna, saya ingin sistem melacak aliran data input (*Source-to-Sink*) pada kode sumber maupun bundel DOM publik agar celah **Cross-Site Scripting (XSS)** dan **SQL Injection** terdeteksi hingga ke baris kodenya.

**Acceptance Criteria:**
- [ ] **Jalur Whitebox (AST Taint Analysis):** Menjalankan aturan SAST (Semgrep CLI / AST Analyzer) untuk melacak variabel dari *Source* (input user/request/query) yang masuk ke *Sink* berbahaya (seperti `dangerouslySetInnerHTML`, `v-html`, `{!! !!}`, `.innerHTML`, atau *raw SQL query*) tanpa melewati fungsi *Sanitizer* (seperti `DOMPurify.sanitize` atau *parameterized query*).
- [ ] **Jalur Blackbox (Passive DOM & CSP Evaluator):** Memindai file HTML dan bundel JS publik untuk mendeteksi penggunaan *unsafe DOM sinks* (`innerHTML`, `document.write`, `eval`) yang membaca sumber URL (`location.search`, `location.hash`), serta mengevaluasi kelemahan direktif CSP (seperti penggunaan `'unsafe-inline'` atau `'unsafe-eval'`).
- [ ] Menyimpan informasi `taint_source`, `taint_sink`, nomor baris kode, dan status sanitasi ke dalam `evidence_metadata`.
- [ ] Typecheck/lint passes.

---

### US-007: Audit Eksposur JavaScript Modern (Email Recon, Source Maps, & Secret Leak via Shannon Entropy)
**Description:** Sebagai pengguna, saya ingin sistem memindai kode JavaScript untuk menemukan kebocoran *API Key/Token* rahasia serta informasi internal yang tersebar (seperti alamat email developer atau URL staging) dengan tingkat *false positive* yang rendah.

**Acceptance Criteria:**
- [ ] **Lapis 1 (Contextual Regex & Allowlist):** Memindai pola email, URL internal/staging, eksposur file `.js.map` (*source map*), penggunaan variabel `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` yang salah, serta awalan token populer (`sk-`, `sk-proj-`, `AKIA`, `ghp_`, `AIza`, `xoxb-`). Mengabaikan domain *dummy* (`example.com`, `test.com`, `w3.org`).
- [ ] **Lapis 2 (Kalkulasi Shannon Entropy):** Menghitung nilai entropi karakter $H(X)$ pada nilai string yang berdekatan dengan kata kunci sensitif (`secret`, `token`, `apikey`, `key`, `password`). Menandai string dengan entropi di atas ambang batas (**4.2 bit/karakter** untuk Hex atau **4.5 bit/karakter** untuk Base64) sebagai temuan `JS_SECRET_LEAK` (`CRITICAL`/`HIGH`).
- [ ] **Klasifikasi Informational (`INFO`):** Mengelompokkan temuan alamat email tersebar di kode JS halaman utama dan endpoint internal ke dalam severity `INFO` (`JS_INFO_EXPOSURE`).
- [ ] **Mandatory Auto-Redaction:** Menyensor seluruh nilai token menjadi format `prefix-********************suffix` (contoh: `sk-proj-********************9b4e`) dan menyensor email menjadi `de***@domain.id` sebelum disimpan ke database atau dikirim ke AI dan Frontend.
- [ ] Typecheck/lint passes.

---

### US-008: Engine Remediasi AI & Pembuatan Patch Kode (Before vs. After Diff)
**Description:** Sebagai pengguna, saya ingin setiap temuan dilengkapi penjelasan risiko dalam bahasa Indonesia yang mudah dipahami serta contoh kode perbaikan (*Before vs. After*) yang sesuai dengan *framework* proyek saya.

**Acceptance Criteria:**
- [ ] Mengirimkan metadata temuan dan potongan kode yang telah di-*redact* ke **Gemini 2.5 Flash API** menggunakan fitur *Structured Outputs* (skema Pydantic `AIRemediationSchema`).
- [ ] Dalam mode **Hybrid**, AI mengkorelasikan temuan Blackbox (misal: header CSP yang hilang di URL produksi) dengan lokasi file konfigurasi yang tepat di repositori GitHub (misal: `next.config.mjs` atau `bootstrap/app.php`).
- [ ] Menyimpan hasil penjelasan risiko (`risk_explanation`), langkah perbaikan (`remediation_steps`), kode asli (`original_code`), dan kode perbaikan (`patched_code`) ke tabel `ai_remediations`.
- [ ] Typecheck/lint passes.

---

### US-009: Kalkulasi Security Posture Score (0–100) & Penentuan Grade (A–F)
**Description:** Sebagai pengguna, saya ingin melihat skor numerik (0–100) dan nilai huruf (Grade A–F) di bagian atas laporan agar saya dapat mengukur tingkat keamanan aplikasi saya secara cepat.

**Acceptance Criteria:**
- [ ] Menghitung skor dari nilai awal 100 dikurangi bobot penalti per temuan unik: `CRITICAL` (-25), `HIGH` (-15), `MEDIUM` (-7), `LOW` (-3), dengan batas minimum 0.
- [ ] Temuan dengan tingkat keparahan `INFO` (seperti email tersebar di file JS) memiliki **penalti 0 poin** (tidak mengurangi skor keamanan, namun tetap dihitung dalam jumlah ringkasan `info`).
- [ ] Menentukan Grade berdasarkan skor: **A** (90–100), **B** (80–89), **C** (65–79), **D** (50–64), **F** (di bawah 50).
- [ ] Menerapkan aturan *Grade Cap*: jika terdapat minimal 1 temuan berstatus `CRITICAL`, maka nilai huruf otomatis dikunci maksimal pada **Grade D** meskipun skor numeriknya di atas 64.
- [ ] Typecheck/lint passes.

---

### US-010: Halaman Loading Interaktif Real-Time (Server-Sent Events / SSE)
**Description:** Sebagai pengguna, saya ingin melihat halaman *loading* yang menampilkan tahapan pemeriksaan secara *real-time* (persentase, keterangan proses yang sedang diuji, dan log telemetri) selama proses audit berlangsung.

**Acceptance Criteria:**
- [ ] Backend menyediakan endpoint `GET /api/v1/audits/{session_id}/stream` dengan header `Content-Type: text/event-stream`.
- [ ] Mengirimkan pembaruan status secara berurutan pada 5 fase:
  1. `INIT` (15%): Inisialisasi sesi, validasi target, & akuisisi kode/metadata.
  2. `CVE_SCAN` (35%): Pemindaian dependensi & pencocokan database CVE (OSV.dev / NVD).
  3. `XSS_AUDIT` (60%): Analisis Taint Source-to-Sink (AST) & inspeksi DOM/CSP untuk celah XSS & injeksi.
  4. `JS_EXPOSURE` & `CONFIG_AUDIT` (80%): Analisis bundel JavaScript (Shannon Entropy API key & eksposur email) serta evaluasi konfigurasi keamanan.
  5. `AI_REMEDIATION` (95%): Penyusunan penjelasan risiko & kode perbaikan (*Before vs. After*) oleh AI.
- [ ] Saat mencapai `COMPLETED` (100%), halaman *loading* otomatis berpindah ke tampilan Dashboard Laporan Hasil Audit.
- [ ] Typecheck/lint passes.
- [ ] Verify in browser using dev-browser skill.

---

### US-011: Dashboard Laporan Hasil Audit, Kartu Skor, & Filter Severity (`CRITICAL` s/d `INFO`)
**Description:** Sebagai pengguna, saya ingin melihat ringkasan skor keamanan, *tech stack* yang terdeteksi, serta daftar temuan yang dapat difilter berdasarkan tingkat keparahan (termasuk tab khusus `INFO` untuk temuan informatif JavaScript).

**Acceptance Criteria:**
- [ ] Menampilkan *Gauge Chart / Score Card* (0–100) beserta badge warna **Grade A–F** dan daftar *badge Tech Stack* yang terdeteksi.
- [ ] Menampilkan tab filter berdasarkan tingkat keparahan beserta jumlah temuannya: `All`, `Critical`, `High`, `Medium`, `Low`, dan `Info (Recon & Exposure)`.
- [ ] Setiap kartu temuan menampilkan judul, badge severity, badge CWE/OWASP, skor CVSS, lokasi file/baris kode, nilai entropi (jika temuan secret), dan potongan bukti kode yang sudah disensor (*redacted*).
- [ ] Typecheck/lint passes.
- [ ] Verify in browser using dev-browser skill.

---

### US-012: Komponen Interactive "Before vs. After" Code Diff Viewer & Copy Patch
**Description:** Sebagai developer, saya ingin melihat perbandingan visual antara kode saya yang rentan (*Before*) dan kode hasil perbaikan AI (*After*) lengkap dengan tombol penyalin kode agar saya dapat langsung menambal celah tersebut.

**Acceptance Criteria:**
- [ ] Menampilkan komponen *Split / Unified Diff Viewer* dengan sorotan warna merah untuk baris kode rentan (`original_code`) dan warna hijau untuk baris kode aman hasil olahan AI (`patched_code`).
- [ ] Menampilkan daftar langkah perbaikan terstruktur (`remediation_steps`) di atas kotak kode.
- [ ] Menyediakan tombol **"Copy Patched Code"** dengan umpan balik visual ("Copied!") saat diklik.
- [ ] Typecheck/lint passes.
- [ ] Verify in browser using dev-browser skill.

---

## 4. Functional Requirements

### A. Input, Orchestration & Security Guardrails
- **FR-1:** Sistem harus menerima 3 mode input pada `POST /api/v1/audits`: `BLACKBOX` (wajib mengisi `target_url`), `WHITEBOX` (wajib mengisi `github_repo_url`), dan `HYBRID` (wajib mengisi `target_url` dan `github_repo_url`).
- **FR-2:** Sistem harus memvalidasi setiap `target_url` menggunakan resolusi DNS dan menolak *request* apabila IP tujuan berada dalam rentang IP privat/loopback/link-local (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `::1`) untuk mencegah serangan SSRF.
### Functional Requirements Tambahan (FR-2.1)
- **FR-2.1:** Sistem harus menyediakan sakelar konfigurasi `DEMO_MODE` pada FastAPI backend. Ketika aktif, pemeriksaan kepemilikan domain (DNS TXT / `.well-known`) otomatis me-return status `true` (Mocked Verification) guna memperlancar presentasi *live demo* 3 menit tanpa batasan domain eksternal milik juri.
- **FR-3:** Sistem harus membatasi ukuran repositori GitHub yang di-*clone* maksimal **50 MB** dengan parameter `--depth 1 --single-branch` dan batas waktu (*timeout*) kloning maksimal **15 detik**.

### B. Deep Vulnerability & Exposure Engines
- **FR-4:** Pada jalur Blackbox, sistem harus mengeksekusi pemeriksaan pasif terhadap header keamanan HTTP (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), atribut cookie (`HttpOnly`, `Secure`, `SameSite`), konfigurasi CORS, dan masa berlaku sertifikat TLS.
- **FR-5:** Pada jalur Whitebox dan Blackbox, sistem harus mengidentifikasi nama paket dan versi eksak dari *lockfile* atau *asset fingerprinting*, lalu mengirimkan kueri ke **OSV.dev API** untuk memetakan ID CVE, skor CVSS, dan versi paket yang telah diperbaiki (*patched version*).
- **FR-6:** Pada pemeriksaan XSS & Injeksi, sistem harus mendeteksi aliran data dari input eksternal (*Source*) ke fungsi eksekusi/render berbahaya (*Sink*) menggunakan analisis statis AST (Whitebox) serta memindai penggunaan *unsafe DOM sinks* pada bundel JS publik (Blackbox).
- **FR-7:** Pada pemindaian file JavaScript (baik di repositori maupun bundel JS halaman utama), sistem harus mengekstrak kandidat alamat email dan URL internal/staging, membuang domain *placeholder* (`example.com`, `test.com`, `localhost`), dan mengklasifikasikannya sebagai temuan `INFO` (`JS_INFO_EXPOSURE`).
- **FR-8:** Sistem harus menghitung nilai **Shannon Entropy** $H(X) = -\sum P(x_i) \log_2 P(x_i)$ untuk setiap string literal yang berasosiasi dengan variabel kunci/rahasia. String heksadesimal dengan $H(X) \ge 4.2$ atau string Base64/alfanumerik dengan $H(X) \ge 4.5$ atau string yang cocok dengan pola prefix kredensial populer harus diklasifikasikan sebagai `CRITICAL` atau `HIGH` (`JS_SECRET_LEAK`).
- **FR-9:** Sistem **wajib** menjalankan fungsi *Auto-Redaction* segera setelah string rahasia atau email terdeteksi, dengan hanya menyisakan maksimal 6 karakter awal dan 4 karakter akhir pada token (contoh: `sk-proj-********************9b4e`) sebelum data tersebut menyentuh database, log, LLM API, maupun respons JSON frontend.

### C. Scoring, Streaming & AI Remediation
- **FR-10:** Sistem harus mengalirkan pembaruan status progres melalui endpoint SSE (`GET /api/v1/audits/{session_id}/stream`) setiap kali transisi tahapan (`INIT` -> `CVE_SCAN` -> `XSS_AUDIT` -> `JS_EXPOSURE` -> `AI_REMEDIATION` -> `COMPLETED`) terjadi, sekaligus mencatatnya ke tabel `audit_stage_logs`.
- **FR-11:** Sistem harus memanggil Gemini API dengan kontrak skema Pydantic untuk menghasilkan `risk_explanation`, `remediation_steps`, `original_code`, dan `patched_code` pada setiap temuan unik.
- **FR-12:** Sistem harus menghitung `security_score` menggunakan rumus:
  $$\text{Score} = \max\left(0, 100 - (25 \times N_{\text{critical}} + 15 \times N_{\text{high}} + 7 \times N_{\text{medium}} + 3 \times N_{\text{low}})\right)$$
  di mana temuan `INFO` memiliki bobot pengurang **0**, serta menerapkan *Grade Cap* maksimal **Grade D** apabila $N_{\text{critical}} \ge 1$.

---

## 5. Non-Goals (Out of Scope)

- **Tidak Melakukan Eksploitasi Aktif / Destruktif:** Sistem tidak mengirimkan ratusan payload *fuzzing* SQLi/XSS aktif, *brute-force* login, atau serangan *Denial of Service (DoS)* ke URL target produksi. Seluruh deteksi XSS dan injeksi dilakukan melalui analisis *AST Taint Tracking* (Whitebox) dan *Passive DOM/CSP Inspection* (Blackbox).
- **Tidak Menyimpan Kredensial Utuh (Plaintext Secrets):** Sistem tidak boleh digunakan sebagai tempat penyimpanan nilai kunci API/token asli yang ditemukan selama pemindaian.
- **Tidak Melakukan Auto-Commit / Auto-Merge Tanpa Izin:** Pada versi MVP Hackathon ini, sistem menghasilkan *Code Diff* dan *Unified Patch* untuk disalin oleh developer, bukan melakukan *push* langsung ke *branch* utama repositori pengguna.
- **Tidak Memproses Repositori Privat Tanpa Token OAuth:** Fokus utama MVP adalah repositori GitHub publik (atau repositori yang dapat diakses oleh token lingkungan demo).

---

## 6. Design Considerations (UI/UX Requirements)

1. **Halaman Utama (Target Input View):**
   - Desain *clean dark-mode cybersecurity aesthetic* (menggunakan Tailwind CSS + `shadcn/ui`).
   - Pilihan kartu mode interaktif (**Blackbox URL**, **Whitebox GitHub**, **Hybrid Full-Stack**) dengan indikator fitur yang aktif di tiap mode.
2. **Halaman Loading Interaktif (Live Telemetry SSE View):**
   - Menampilkan **Animated Progress Bar (0% – 100%)** di bagian tengah atas.
   - Menampilkan **5 Stepper Nodes** (Inisialisasi -> Pemindaian CVE -> Audit XSS & AST -> Analisis Bundel JS & Secret -> Sintesis Patch AI) yang menyala secara berurutan.
   - Menampilkan **Live Terminal Log Box** di bagian bawah yang mencetak pesan tahapan dari *event stream* SSE secara *real-time* (contoh: `"[80% - JS_EXPOSURE] Menganalisis bundel JavaScript terhadap kebocoran token API (Shannon Entropy) & eksposur email..."`).
3. **Halaman Laporan Audit (Security Report Dashboard):**
   - **Header Ringkasan:** Lingkaran *Security Posture Score* (0–100), Badge besar **Grade A–F**, durasi pemindaian, dan daftar *pill badges* untuk *Detected Tech Stack*.
   - **Tab Navigasi Severity:** `Semua (5)` | `Critical (1)` | `High (1)` | `Medium (1)` | `Low (0)` | `Info / JS Recon (2)`.
   - **Detail Kartu Temuan & Code Diff:** Accordion/Card yang menampilkan bukti temuan (*Redacted Snippet* + metadata seperti *Shannon Entropy* atau *Taint Source/Sink*) berdampingan dengan panel **AI Remediation** yang memuat komponen `react-diff-viewer` (*Before* berwarna merah vs. *After* berwarna hijau).

---

## 7. Technical Considerations (Architecture, DB Schema & API Contracts)

### 7.1 Arsitektur Alur Sistem

```text
+-------------------------------------------------------------------------+
|                   FRONTEND: Next.js + Tailwind + shadcn/ui              |
|  [Input Form]  --->  [Live SSE Loading Screen]  --->  [Report & Diff UI]|
+---------+-----------------------+-----------------------------+---------+
          | POST /audits          | GET /audits/{id}/stream     | GET /audits/{id}/report
          v                       v (Server-Sent Events)        v
+-------------------------------------------------------------------------+
|                    BACKEND: Python FastAPI Orchestrator                 |
+---------+-----------------------------------------------------+---------+
          |                                                     |
          v                                                     v
+----------------------------------+          +----------------------------------+
|   BLACKBOX ENGINE (URL Target)   |          |  WHITEBOX ENGINE (GitHub Repo)   |
| - Anti-SSRF & DNS Verifier       |          | - Isolated Shallow Git Cloner    |
| - YAML Template Engine (Headers) |          | - AST Taint Analyzer (XSS/SQLi)  |
| - Passive DOM Sink & CSP Scanner |          | - Lockfile Parser & OSV.dev API  |
| - JS Bundle Secret & Email Recon |          | - Source Secret & Entropy Scanner|
+-----------------+----------------+          +-----------------+----------------+
                  |                                             |
                  +----------------------+----------------------+
                                         |
                                         v
                  +---------------------------------------------+
                  |   MANDATORY SECRET & EMAIL AUTO-REDACTOR    |
                  |  (Masks tokens: sk-proj-****9b4e & emails)  |
                  +----------------------+----------------------+
                                         |
                                         v
                  +---------------------------------------------+
                  |     AI REMEDIATION ENGINE (Gemini API)      |
                  |  - Structured Output via Pydantic Schema    |
                  |  - Generates Risk Explanation & Code Diff   |
                  +----------------------+----------------------+
                                         |
                                         v
                  +---------------------------------------------+
                  |   POSTGRESQL DATABASE (Relational + JSONB)  |
                  +---------------------------------------------+
```

---

### 7.2 Skema Database Lengkap (PostgreSQL DDL)

```sql
-- 1. ENUM Types
CREATE TYPE audit_mode_enum AS ENUM ('BLACKBOX', 'WHITEBOX', 'HYBRID');
CREATE TYPE audit_status_enum AS ENUM (
    'QUEUED', 'INIT', 'CVE_SCAN', 'XSS_AUDIT', 
    'JS_EXPOSURE', 'CONFIG_AUDIT', 'AI_REMEDIATION', 
    'COMPLETED', 'FAILED'
);
CREATE TYPE severity_enum AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE finding_category_enum AS ENUM (
    'XSS_INJECTION', 'DEPENDENCY_CVE', 'JS_SECRET_LEAK', 
    'JS_INFO_EXPOSURE', 'SECURITY_HEADER_MISCONFIG', 'TLS_COOKIE_POSTURE'
);

-- 2. Tabel Targets
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) NOT NULL,
    target_url VARCHAR(500),
    github_repo_url VARCHAR(500),
    default_branch VARCHAR(100) DEFAULT 'main',
    ownership_token VARCHAR(128) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    detected_tech_stack JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Tabel Audit Sessions
CREATE TABLE audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    mode audit_mode_enum NOT NULL,
    status audit_status_enum NOT NULL DEFAULT 'QUEUED',
    progress_percent SMALLINT NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    current_stage_message TEXT,
    security_score SMALLINT CHECK (security_score BETWEEN 0 AND 100),
    security_grade CHAR(1),
    summary_counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}'::jsonb,
    duration_ms INTEGER,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Tabel Audit Findings
CREATE TABLE audit_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    rule_id VARCHAR(120) NOT NULL,
    category finding_category_enum NOT NULL,
    severity severity_enum NOT NULL,
    title VARCHAR(255) NOT NULL,
    cwe_id VARCHAR(50),
    owasp_category VARCHAR(100),
    cvss_score NUMERIC(3,1),
    source_origin VARCHAR(30) NOT NULL,
    location_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    redacted_code_snippet TEXT,
    evidence_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Tabel AI Remediations
CREATE TABLE ai_remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID UNIQUE NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    ai_model_version VARCHAR(60) NOT NULL DEFAULT 'gemini-2.5-flash',
    risk_explanation TEXT NOT NULL,
    remediation_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    language VARCHAR(40),
    original_code TEXT,
    patched_code TEXT,
    unified_diff TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Tabel Audit Stage Logs (SSE History)
CREATE TABLE audit_stage_logs (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    stage audit_status_enum NOT NULL,
    progress_percent SMALLINT NOT NULL,
    message TEXT NOT NULL,
    logged_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_sessions_target_created ON audit_sessions(target_id, created_at DESC);
CREATE INDEX idx_findings_session_severity ON audit_findings(session_id, severity);
CREATE INDEX idx_findings_metadata_gin ON audit_findings USING GIN (evidence_metadata);
CREATE INDEX idx_stage_logs_session ON audit_stage_logs(session_id, id ASC);
```

---

### 7.3 Kontrak JSON API (FastAPI <-> Frontend)

#### 1. `POST /api/v1/audits` — Inisialisasi Sesi Audit
**Request Payload:**
```json
{
  "project_name": "Portal E-Commerce UMKM",
  "mode": "HYBRID",
  "target_url": "[https://demo-toko.startupkamu.id](https://demo-toko.startupkamu.id)",
  "github_repo_url": "[https://github.com/username/demo-toko-web](https://github.com/username/demo-toko-web)",
  "branch": "main"
}
```

**Response Payload (`202 Accepted`):**
```json
{
  "status": "accepted",
  "data": {
    "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "mode": "HYBRID",
    "initial_status": "INIT",
    "stream_endpoint": "/api/v1/audits/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/stream",
    "report_endpoint": "/api/v1/audits/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/report"
  }
}
```

#### 2. `GET /api/v1/audits/{session_id}/stream` — Server-Sent Events (SSE)
```text
event: progress
data: {"stage": "INIT", "progress": 15, "message": "Menginisialisasi ruang kerja & melakukan shallow clone repositori GitHub...", "timestamp": "2026-10-24T02:15:02Z"}

event: progress
data: {"stage": "CVE_SCAN", "progress": 35, "message": "Memindai 142 paket di package-lock.json & mencocokkan database CVE (OSV.dev)...", "timestamp": "2026-10-24T02:15:06Z"}

event: progress
data: {"stage": "XSS_AUDIT", "progress": 60, "message": "Melacak aliran data (AST Taint Analysis) & DOM sinks untuk mendeteksi celah XSS/Injeksi...", "timestamp": "2026-10-24T02:15:11Z"}

event: progress
data: {"stage": "JS_EXPOSURE", "progress": 80, "message": "Menganalisis bundel JavaScript terhadap kebocoran token API (Shannon Entropy) & eksposur email...", "timestamp": "2026-10-24T02:15:15Z"}

event: progress
data: {"stage": "AI_REMEDIATION", "progress": 95, "message": "Menyusun penjelasan risiko & kode perbaikan (Before vs. After Diff) menggunakan AI...", "timestamp": "2026-10-24T02:15:19Z"}

event: completed
data: {"stage": "COMPLETED", "progress": 100, "message": "Audit selesai! Mengalihkan ke halaman laporan...", "redirect_report_url": "/api/v1/audits/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/report"}
```

#### 3. `GET /api/v1/audits/{session_id}/report` — Kontrak JSON Laporan Lengkap
```json
{
  "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "project_name": "Portal E-Commerce UMKM",
  "mode": "HYBRID",
  "status": "COMPLETED",
  "audited_at": "2026-10-24T02:15:22Z",
  "duration_ms": 20450,
  "target_info": {
    "target_url": "[https://demo-toko.startupkamu.id](https://demo-toko.startupkamu.id)",
    "github_repo_url": "[https://github.com/username/demo-toko-web](https://github.com/username/demo-toko-web)",
    "branch": "main",
    "detected_tech_stack": ["Next.js 14.1.0", "React 18.2.0", "Tailwind CSS", "Nginx 1.24.0"]
  },
  "posture_score": {
    "score": 55,
    "max_score": 100,
    "grade": "D",
    "grade_label": "High Risk — Immediate Remediation Required",
    "summary_counts": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 2
    }
  },
  "findings": [
    {
      "id": "f101-dc4a-4812-9a11-001",
      "rule_id": "JS-SECRET-OPENAI",
      "category": "JS_SECRET_LEAK",
      "severity": "CRITICAL",
      "title": "Kebocoran Private API Key pada Bundel JavaScript Publik",
      "cwe_id": "CWE-798",
      "owasp_category": "A07:2021-Identification and Authentication Failures",
      "cvss_score": 9.1,
      "location": {
        "source_origin": "WHITEBOX_AND_CLIENT_JS",
        "path": "src/services/aiAssistant.ts (Terekspos di /_next/static/chunks/main-8f2a.js)",
        "line_start": 8,
        "line_end": 10
      },
      "redacted_code_snippet": "const OPENAI_KEY = process.env.NEXT_PUBLIC_OPENAI_KEY || \"sk-proj-********************9b4e\";",
      "evidence_metadata": {
        "secret_type": "OpenAI Project API Key",
        "redacted_match": "sk-proj-********************9b4e",
        "shannon_entropy": 4.78,
        "entropy_threshold": 4.2,
        "exposed_in_production_bundle": true
      },
      "ai_remediation": {
        "model": "gemini-2.5-flash",
        "risk_explanation": "Penggunaan prefix NEXT_PUBLIC_ memaksa bundler menyisipkan kunci API rahasia langsung ke dalam bundel JavaScript browser.",
        "remediation_steps": [
          "Segera cabut (revoke) kunci API yang bocor di dashboard OpenAI.",
          "Hapus prefix NEXT_PUBLIC_ dari nama variabel di file .env.",
          "Pindahkan pemanggilan API ke Route Handler sisi server (app/api/chat/route.ts)."
        ],
        "code_patch": {
          "language": "typescript",
          "original_code": "const apiKey = process.env.NEXT_PUBLIC_OPENAI_KEY;\nconst res = await fetch('[https://api.openai.com/v1/chat/completions](https://api.openai.com/v1/chat/completions)', {\n  headers: { 'Authorization': `Bearer ${apiKey}` }\n});",
          "patched_code": "// app/api/chat/route.ts (Server Route Handler)\nexport async function POST(req: Request) {\n  const apiKey = process.env.OPENAI_API_KEY;\n  // Request dieksekusi dengan aman di sisi server\n}"
        }
      }
    },
    {
      "id": "f104-dc4a-4812-9a11-004",
      "rule_id": "JS-INFO-EMAIL-EXPOSURE",
      "category": "JS_INFO_EXPOSURE",
      "severity": "INFO",
      "title": "Ditemukan Alamat Email & Endpoint Internal Tersebar pada Kode JavaScript Halaman Utama",
      "cwe_id": "CWE-200",
      "owasp_category": "A05:2021-Security Misconfiguration",
      "cvss_score": 0.0,
      "location": {
        "source_origin": "CLIENT_JS_BUNDLE",
        "path": "/_next/static/chunks/pages/index-3a91c.js",
        "line_start": 1,
        "line_end": 1
      },
      "redacted_code_snippet": "...const DEV_CONTACTS=[\"de***@startupkamu.id\",\"in***@startupkamu.id\"],STAGING_API=\"[https://staging-api.internal.startupkamu.id/v1](https://staging-api.internal.startupkamu.id/v1)\"...",
      "evidence_metadata": {
        "exposed_emails_count": 2,
        "redacted_emails": ["de***@startupkamu.id", "in***@startupkamu.id"],
        "internal_urls_found": ["[https://staging-api.internal.startupkamu.id/v1](https://staging-api.internal.startupkamu.id/v1)"],
        "source_map_accessible": true
      },
      "ai_remediation": {
        "model": "gemini-2.5-flash",
        "risk_explanation": "Temuan informatif: keberadaan email internal dan URL staging di bundel JS publik memudahkan pemetaan target phishing atau rekayasa sosial.",
        "remediation_steps": [
          "Hapus konstanta daftar email developer internal dari bundel frontend.",
          "Atur productionBrowserSourceMaps: false pada next.config.mjs."
        ],
        "code_patch": {
          "language": "javascript",
          "original_code": "const nextConfig = {\n  productionBrowserSourceMaps: true\n};",
          "patched_code": "const nextConfig = {\n  productionBrowserSourceMaps: false\n};"
        }
      }
    }
  ]
}
```

---

## 8. Success Metrics

- **End-to-End Audit Speed:** Rata-rata waktu penyelesaian audit mode **Hybrid** (URL + GitHub) berada di bawah **25 detik** sehingga sangat ideal untuk *live demo* di hadapan juri hackathon.
- **Zero Plaintext Leak Rate:** **100%** kredensial/token dan email yang terdeteksi melewati fungsi *Auto-Redaction* sebelum disimpan ke database atau ditampilkan di UI.
- **Schema Compliance Rate:** **100%** respons remediasi dari Gemini API valid terhadap skema Pydantic tanpa menghasilkan error *JSON parsing* di frontend.
- **Precision pada JS Secret Scanner:** Tingkat *false positive* di bawah **10%** berkat kombinasi *Contextual Regex Allowlist* dan ambang batas *Shannon Entropy* ($H(X) \ge 4.2$).

---

## 9. Open Questions (Clarifikasi Tambahan Sebelum Implementasi Kode)

Untuk memastikan tahap *coding* selanjutnya berjalan presisi sesuai kebutuhan tim hackathon kamu, silakan jawab pertanyaan singkat berikut (cukup balas dengan format seperti **`1A, 2B, 3A`**):

    1. Bagaimana aturan verifikasi kepemilikan domain (DNS TXT / .well-known) saat sesi Live Demo Hackathon berlangsung?
       A. Gunakan "Demo Sandbox Mode" (bypass verifikasi DNS otomatis untuk domain demo/pilihan juri, namun tampilkan UI verifikasi sebagai fitur)
       B. Wajibkan verifikasi DNS TXT / file .well-known secara penuh untuk semua URL tanpa terkecuali
       C. Bypass verifikasi untuk mode Read-Only/Passive Blackbox, dan wajibkan hanya untuk Deep Scan
       D. Lainnya: [sebutkan]

    2. Apakah pengguna perlu login (Autentikasi) untuk menjalankan audit pada versi MVP Hackathon ini?
       A. Tanpa login (Guest Mode langsung pakai di halaman utama agar juri mudah mencoba, riwayat disimpan via Session ID / LocalStorage)
       B. Login menggunakan GitHub OAuth (sekalian agar bisa mengaudit repositori GitHub Private milik user)
       C. Login standar menggunakan Email & Password (JWT)
       D. Lainnya: [sebutkan]

    3. Fitur ekspor atau tindak lanjut apa yang paling ingin kamu tonjolkan di halaman Report selain tombol "Copy Patched Code"?
       A. Tombol "Export PDF Executive Report" (cetak laporan audit resmi siap unduh)
       B. Tombol "Re-Scan & Compare Score" (untuk memamerkan kenaikan skor dari Grade D ke Grade A saat demo)
       C. Keduanya (Export PDF + Re-Scan Score Comparison)
       D. Cukup tampilan Dashboard Web & Copy Patch saja