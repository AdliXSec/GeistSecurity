# SecAudit Curated Nuclei Templates

Koleksi template Nuclei pilihan berbobot tinggi, berdampak kritis, dan berakurasi tinggi yang dikurasi khusus untuk web scanner **SecAudit**.

## Mengapa Tidak Menjalankan Seluruh 14.000+ Template?
1. **Durasi Eksekusi**: Menjalankan 14.165 template membutuhkan waktu 2-5 jam per domain audit dan menghasilkan puluhan ribu request HTTP.
2. **WAF Blocking**: Request masif memicu auto-ban IP dari Cloudflare, AWS WAF, dan Akamai dalam hitungan detik.
3. **Target Instability**: Payload berat dapat mendegradasi performa server target.
4. **Noise & Irrelevant**: Ribuan template lama ditujukan untuk perangkat keras usang (router ZTE lawas, CCTV tua, dsb.) yang tidak relevan dengan audit aplikasi web modern.

---

## Struktur Kurasi (119 Template Terpilih)

```
backend/rules/nuclei/
├── 01-sensitive-exposures/       # Kebocoran data rahasia & kredensial
│   ├── environment-secrets/      # .env, Laravel/Django config
│   ├── version-control-git/      # .git/config, credentials, logs
│   ├── backups-and-dumps/        # .sql dump, backup .zip, db schema
│   ├── sourcemaps-and-ide/       # Webpack source map, .vscode, .idea, tfstate
│   └── api-tokens/               # AWS, GitHub, OpenAI, Stripe, Slack, FCM
│
├── 02-misconfigurations/         # Miskonfigurasi keamanan web
│   ├── headers-and-cors/         # Missing security headers, CORS origin reflection
│   ├── tls-and-ssl/              # Expired SSL, weak TLS/ciphers
│   └── debug-and-info-leaks/     # phpinfo, server-status, debug bar, cloud metadata
│
├── 03-often-overlooked/          # Celah yang sering terlewat saat audit
│   ├── takeovers/                # Subdomain takeover (S3, GitHub, Fastly, dll.)
│   └── subtle-flaws/             # Host header injection, cache poisoning, CRLF
│
├── 04-panels-and-actuators/      # Panel administrasi & endpoint internal
│   ├── spring-actuators/         # Spring Boot /actuator (env, heapdump, mappings)
│   ├── api-and-graphql/          # Swagger UI/OpenAPI, GraphQL introspection
│   └── admin-dashboards/         # Adminer, Kibana, Grafana, Docker API
│
├── 05-core-dast/                 # Active parameter fuzzing (OWASP Top 10)
│   ├── sqli-and-xss/             # Error-based SQLi, Reflected & DOM XSS
│   └── lfi-and-ssrf-ssti/        # Linux/Windows LFI, SSRF response, SSTI
│
├── 06-cisa-kev-popular/          # CISA Known Exploited Vulnerabilities
│   └── critical-cves/            # Log4j, Spring4Shell, Confluence, PHP CGI RCE
│
└── profiles/
    ├── secaudit-quick.yml        # Mode cepat (~15-45 detik)
    └── secaudit-full.yml         # Mode audit komprehensif (~1-3 menit)
```

---

## Cara Menjalankan Manual via CLI

### 1. Validasi Sintaks Template
```bash
nuclei -validate -t backend/rules/nuclei
```

### 2. Mode Quick Scan
```bash
nuclei -target https://example.com \
  -profile backend/rules/nuclei/profiles/secaudit-quick.yml \
  -silent -jsonl -o hasil-quick.jsonl
```

### 3. Mode Full Audit
```bash
nuclei -target https://example.com \
  -profile backend/rules/nuclei/profiles/secaudit-full.yml \
  -silent -jsonl -o hasil-full.jsonl
```
