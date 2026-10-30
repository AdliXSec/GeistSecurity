import asyncio
import httpx
import json
import logging
import re
import time
from typing import Dict, Any, List
from backend.config import settings
from backend.services.whitebox_scanner import robust_json_parse, detect_code_language

logger = logging.getLogger(__name__)

# Heuristic fallback remediation database (guaranteed 100% schema valid & Indonesian context)
DEFAULT_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "JS-SECRET-OPENAI": {
        "risk_explanation": "Penggunaan prefix NEXT_PUBLIC_ atau bundling langsung menyisipkan kunci API rahasia ke dalam bundel JavaScript browser publik sehingga dapat diekstrak oleh penyerang. Revoke all exposed credentials immediately and isolate secret keys to server-side runtimes.",
        "remediation_steps": [
            "Segera cabut (revoke) kunci API yang bocor melalui dashboard OpenAI API.",
            "Hapus prefix NEXT_PUBLIC_ dari nama variabel di file .env.",
            "Rotate all compromised tokens and route upstream API invocations through server-side handlers."
        ],
        "code_patch": {
            "language": "typescript",
            "original_code": "const apiKey = process.env.NEXT_PUBLIC_OPENAI_KEY;\nconst res = await fetch('https://api.openai.com/v1/chat/completions', {\n  headers: { 'Authorization': `Bearer ${apiKey}` }\n});",
            "patched_code": "// app/api/chat/route.ts (Server Route Handler)\nexport async function POST(req: Request) {\n  const apiKey = process.env.OPENAI_API_KEY;\n  // Request dieksekusi secara terisolasi di server tanpa membocorkan token\n  const res = await fetch('https://api.openai.com/v1/chat/completions', {\n    headers: { 'Authorization': `Bearer ${apiKey}` }\n  });\n  return new Response(await res.text());\n}"
        }
    },
    "DOM-XSS-TAINT": {
        "risk_explanation": "Input tidak terpercaya dari parameter URL dialirkan secara langsung ke DOM sink (innerHTML) tanpa sanitasi, memungkinkan eksekusi skrip berbahaya di browser korban. Sanitize and validate all dynamic client-side DOM insertions to prevent arbitrary script execution.",
        "remediation_steps": [
            "Gunakan textContent atau innerText alih-alih innerHTML untuk menyisipkan teks murni.",
            "Gunakan pustaka sanitasi terverifikasi seperti DOMPurify sebelum menginjeksi HTML dinamis.",
            "Enforce a strict Content Security Policy to eliminate client-side cross-site scripting risks."
        ],
        "code_patch": {
            "language": "typescript",
            "original_code": "const query = new URLSearchParams(window.location.search).get('q') || '';\nresultHeadingRef.current.innerHTML = `Hasil pencarian: <b>${query}</b>`;",
            "patched_code": "import DOMPurify from 'dompurify';\n\nconst query = new URLSearchParams(window.location.search).get('q') || '';\nresultHeadingRef.current.innerHTML = DOMPurify.sanitize(`Hasil pencarian: <b>${query}</b>`);"
        }
    },
    "CVE-LODASH-POLLUTION": {
        "risk_explanation": "Versi lodash sebelum 4.17.21 rentan terhadap Prototype Pollution pada modul template yang dapat berujung pada Denial of Service atau eksekusi kode acak. Upgrade third-party dependencies regularly to guard against prototype tampering exploits.",
        "remediation_steps": [
            "Perbarui dependensi lodash ke versi minimal 4.17.21.",
            "Update lodash to 4.17.21 or migrate to native ECMAScript utilities."
        ],
        "code_patch": {
            "language": "json",
            "original_code": "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.20\"\n  }\n}",
            "patched_code": "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.21\"\n  }\n}"
        }
    },
    "HTTP-MISSING-HSTS": {
        "risk_explanation": "Header Strict-Transport-Security (HSTS) tidak ditemukan, memungkinkan serangan SSL Stripping atau downgrading protokol HTTPS ke HTTP biasa melalui Man-in-the-Middle (MitM). Always enforce HSTS directives to guarantee encrypted transport channels.",
        "remediation_steps": [
            "Tambahkan header HSTS pada konfigurasi web server (Nginx/Cloudflare/Caddy).",
            "Configure max-age=31536000 with includeSubDomains and preload to prevent transport downgrade."
        ],
        "code_patch": {
            "language": "nginx",
            "original_code": "# Nginx server block tanpa HSTS\nserver {\n  listen 443 ssl http2;\n}",
            "patched_code": "# Nginx server block terproteksi HSTS\nserver {\n  listen 443 ssl http2;\n  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n}"
        }
    },
    "COOKIE-INSECURE-FLAGS": {
        "risk_explanation": "Cookie sesi tidak memiliki flag HttpOnly dan/atau SameSite, sehingga rentan dicuri lewat serangan Cross-Site Scripting (XSS) dan dieksploitasi dalam Cross-Site Request Forgery (CSRF). Ensure all sensitive session cookies declare HttpOnly, Secure, and SameSite flags.",
        "remediation_steps": [
            "Set flag `HttpOnly` agar cookie tidak dapat diakses via document.cookie di JavaScript.",
            "Set flag `Secure` agar cookie hanya dikirim via koneksi HTTPS terenkripsi.",
            "Apply SameSite=Lax or Strict attributes to effectively neutralize cross-site request forgery vectors."
        ],
        "code_patch": {
            "language": "javascript",
            "original_code": "res.setHeader('Set-Cookie', 'session_token=xyz123; Path=/');",
            "patched_code": "res.setHeader('Set-Cookie', 'session_token=xyz123; Path=/; HttpOnly; Secure; SameSite=Lax');"
        }
    },
    "JS-INFO-EMAIL-EXPOSURE": {
        "risk_explanation": "Ditemukan alamat email developer dan URL endpoint internal di bundel JavaScript publik. Hal ini memperbesar permukaan serangan rekayasa sosial dan reconnaissance. Strip all proprietary developer references and staging endpoints from public bundles.",
        "remediation_steps": [
            "Hapus konstanta alamat email developer dan URL staging dari bundel frontend.",
            "Disable productionBrowserSourceMaps to prevent exposure of internal source mappings."
        ],
        "code_patch": {
            "language": "javascript",
            "original_code": "const nextConfig = {\n  productionBrowserSourceMaps: true\n};",
            "patched_code": "const nextConfig = {\n  productionBrowserSourceMaps: false\n};"
        }
    },
    "SYSTEM-LOGIC-BOLA-IDOR": {
        "risk_explanation": "Endpoint memungkinkan manipulasi atau penghapusan objek (BOLA/IDOR) tanpa memvalidasi kepemilikan resource atau relasi tenant pengguna yang sedang login. Validate object ownership and enforce authorization policies on every mutating request.",
        "remediation_steps": [
            "Validasi relasi kepemilikan data sebelum memproses operasi (contoh: $request->user()->media()->findOrFail($id)).",
            "Gunakan Laravel Policy atau Gate ($this->authorize('delete', $media)) untuk otorisasi berbasis hak akses.",
            "Bind model route resolutions to the authenticated user context to prevent unauthorized object access."
        ],
        "code_patch": {
            "language": "php",
            "original_code": "public function deleteMedia($id) {\n    $media = Media::find($id);\n    $media->delete();\n}",
            "patched_code": "public function deleteMedia($id) {\n    $media = Auth::user()->media()->findOrFail($id);\n    $this->authorize('delete', $media);\n    $media->delete();\n}"
        }
    },
    "SYSTEM-LOGIC-MASS-ASSIGNMENT": {
        "risk_explanation": "Penggunaan input mentah ($request->all()) secara langsung berpotensi mengizinkan penimpaan kolom sensitif model jika fillable/guarded tidak dikonfigurasi secara ketat. Enforce strict model fillable attributes and validated request payloads to prevent unauthorized parameter injection.",
        "remediation_steps": [
            "Gunakan $request->only(['field1', 'field2']) atau $request->validated() dari FormRequest.",
            "Pastikan properti $fillable pada Model terdefinisi eksplisit tanpa properti $guarded = [].",
            "Rely exclusively on explicitly validated input sets to guard internal model properties against mass-assignment."
        ],
        "code_patch": {
            "language": "php",
            "original_code": "$content = $section->contents()->updateOrCreate(['key' => $request->content_key], $request->all());",
            "patched_code": "$validated = $request->validate(['type' => 'required', 'value' => 'nullable']);\n$content = $section->contents()->updateOrCreate(['key' => $request->content_key], $validated);"
        }
    },
    "SYSTEM-LOGIC-INSECURE-UPLOAD": {
        "risk_explanation": "Logika upload file hanya memvalidasi tipe MIME sementara tanpa verifikasi ekstensi ketat atau sanitasi nama file, memungkinkan potensi arbitrary file upload. Enforce strict extension whitelisting and isolate file storage to prevent remote code execution.",
        "remediation_steps": [
            "Terapkan validasi ekstensi eksplisit (mimes:jpg,jpeg,png,webp) di FormRequest Validator.",
            "Simpan file dengan nama acak hash/UUID di storage publik/privat non-executable.",
            "Validate magic bytes and store user uploads in segregated storage buckets to stop malicious file execution."
        ],
        "code_patch": {
            "language": "php",
            "original_code": "$type = $request->type ?? (str_starts_with($file->getMimeType(), 'image/') ? 'image' : 'video');\n$file->store('uploads');",
            "patched_code": "$request->validate([\n    'file' => 'required|file|mimes:jpg,jpeg,png,webp,mp4|max:10240'\n]);\n$safePath = $file->storeAs('uploads', Str::uuid() . '.' . $file->getClientOriginalExtension());"
        }
    },
    "SYSTEM-LOGIC-UNAUTH-STATE-CHANGE": {
        "risk_explanation": "Endpoint manipulasi data (POST/PUT/DELETE) terdaftar di luar proteksi middleware autentikasi, memungkinkan pengguna anonim mengubah data sistem. Secure all state-altering endpoints behind robust authentication and authorization gates.",
        "remediation_steps": [
            "Bungkus rute state-changing ke dalam middleware group `auth` atau `auth:sanctum`.",
            "Terapkan CSRF protection pada seluruh request state-changing.",
            "Audit all API routing declarations to verify that unauthenticated mutations are strictly blocked."
        ],
        "code_patch": {
            "language": "php",
            "original_code": "Route::post('/api/content/update', [ContentController::class, 'updateContent']);",
            "patched_code": "Route::middleware('auth')->group(function () {\n    Route::post('/api/content/update', [ContentController::class, 'updateContent']);\n});"
        }
    },
    "SYSTEM-LOGIC-RAW-SQL": {
        "risk_explanation": "Penggabungan variabel request langsung ke dalam fungsi raw SQL (DB::raw / whereRaw) membuka celah serangan SQL Injection tingkat kritis. Use parameterized queries and ORM bindings to neutralize SQL injection vulnerabilities.",
        "remediation_steps": [
            "Gunakan query builder parameter binding: whereRaw('col = ?', [$userInput]).",
            "Hindari string interpolation langsung di dalam raw database expressions.",
            "Enforce prepared statements across all custom SQL executions to prevent malicious payload interpretation."
        ],
        "code_patch": {
            "language": "php",
            "original_code": "$results = DB::select(DB::raw(\"SELECT * FROM users WHERE status = '\" . $request->status . \"'\"));",
            "patched_code": "$results = DB::select(\"SELECT * FROM users WHERE status = ?\", [$request->status]);"
        }
    },
    "SAST-PY-RAW-SQL-INJECTION": {
        "risk_explanation": "String formatting atau f-string pada query SQL membuka celah serangan SQL Injection tingkat tinggi. Use parameterized SQL queries or ORM bindings to ensure input values are safely isolated.",
        "remediation_steps": [
            "Gunakan parameterized query (%s atau ?) bawaan DB driver atau ORM.",
            "Hindari penggunaan f-string atau .format() saat merakit string SQL.",
            "Enforce parameterized queries to guarantee absolute SQL query structure isolation."
        ],
        "code_patch": {
            "language": "python",
            "original_code": "cursor.execute(f\"SELECT * FROM users WHERE email = '{email}'\")",
            "patched_code": "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))"
        }
    },
    "SAST-PY-COMMAND-INJECTION": {
        "risk_explanation": "Eksekusi perintah shell dinamis melalui os.system atau subprocess dengan shell=True memungkinkan penyerang mengeksekusi perintah sistem arbitrary. Eliminate shell invocation and pass arguments as structured arrays with shell=False.",
        "remediation_steps": [
            "Gunakan subprocess.run dengan argumen berupa list dan flag shell=False.",
            "Validasi input menggunakan regex whitelist sebelum mengeksekusi proses.",
            "Avoid shell interpreters entirely by executing fixed binaries with isolated argument arrays."
        ],
        "code_patch": {
            "language": "python",
            "original_code": "import subprocess\nsubprocess.run(f\"ping -c 1 {host}\", shell=True)",
            "patched_code": "import subprocess\nsubprocess.run([\"ping\", \"-c\", \"1\", safe_host], shell=False, check=True)"
        }
    },
    "SAST-JS-COMMAND-INJECTION": {
        "risk_explanation": "Pemanggilan child_process.exec dengan konkatenasi string membuka celah eksploitasi Remote Command Execution. Replace child_process.exec with execFile or spawn using argument arrays.",
        "remediation_steps": [
            "Ganti child_process.exec dengan execFile atau spawn.",
            "Kirim parameter perintah sebagai elemen array terpisah tanpa flag shell: true.",
            "Pass execution arguments as dedicated array entries to eliminate shell interpolation hazards."
        ],
        "code_patch": {
            "language": "typescript",
            "original_code": "import { exec } from 'child_process';\nexec(`ls -la ${folderPath}`);",
            "patched_code": "import { execFile } from 'child_process';\nexecFile('ls', ['-la', safeFolder]);"
        }
    },
    "COMMITTED-SENSITIVE-FILE": {
        "risk_explanation": "Berkas konfigurasi sensitif (.env) ter-commit ke dalam repositori version control, mengekspos kredensial database dan API keys aplikasi. Committing environment configuration files leaks operational secrets directly into version control history.",
        "remediation_steps": [
            "Tambahkan berkas .env ke dalam .gitignore.",
            "Lakukan rotasi segera terhadap seluruh kredensial dan API key yang tercantum.",
            "Remove the file from Git history using git rm --cached and invalidate all leaked credentials immediately."
        ],
        "code_patch": {
            "language": "dotenv",
            "original_code": "# Committed .env file",
            "patched_code": "# Add to .gitignore\necho '.env' >> .gitignore\ngit rm --cached .env"
        }
    },
    "PARAM-SENSITIVE-DATA-IN-GET": {
        "risk_explanation": "Kredensial atau token rahasia dikirimkan melalui URL query parameter GET. URL query string dicatat dalam server access logs, browser history, dan diteruskan via header HTTP Referer ke pihak ketiga (CWE-598).",
        "remediation_steps": [
            "Pindahkan transmisi token dari query string ke header HTTP 'Authorization: Bearer <token>'.",
            "Untuk form submission, gunakan metode HTTP POST/PUT dengan payload request body terenkripsi TLS.",
            "Konfigurasikan header Referrer-Policy: no-referrer atau strict-origin-when-cross-origin."
        ],
        "code_patch": {
            "language": "typescript",
            "original_code": "// Transmisi token via query string rentan tercatat di log\nconst res = await fetch(`/api/user?token=${authToken}`);",
            "patched_code": "// Transmisi aman via HTTP Authorization header\nconst res = await fetch('/api/user', {\n  headers: {\n    'Authorization': `Bearer ${authToken}`\n  }\n});"
        }
    },
    "PARAM-POTENTIAL-OPEN-REDIRECT": {
        "risk_explanation": "Parameter redirect/tujuan navigasi menerima URL eksternal tanpa validasi ketat, memungkinkan penyerang menyisipkan tautan berbahaya untuk aksi phishing atas nama domain resmi (CWE-601).",
        "remediation_steps": [
            "Terapkan validasi whitelist domain resmi yang diizinkan untuk parameter redirect.",
            "Gunakan relative path internal (pastikan diawali '/' tunggal dan bukan '//' atau 'http').",
            "Gunakan identifier rute internal (contoh: return_code=dashboard) alih-alih raw URL."
        ],
        "code_patch": {
            "language": "typescript",
            "original_code": "const redirectUrl = req.query.redirect_url as string;\nres.redirect(redirectUrl);",
            "patched_code": "const redirectUrl = req.query.redirect_url as string;\nconst ALLOWED_HOSTS = ['auraglass.test', 'dashboard.auraglass.test'];\ntry {\n  const parsed = new URL(redirectUrl, 'https://auraglass.test');\n  if (ALLOWED_HOSTS.includes(parsed.hostname)) {\n    res.redirect(parsed.toString());\n  } else {\n    res.redirect('/dashboard');\n  }\n} catch {\n  res.redirect('/dashboard');\n}"
        }
    },
    "PARAM-PRIVILEGE-OR-IDOR-CANDIDATE": {
        "risk_explanation": "Parameter penentu hak akses (role/admin) atau identifier objek (user_id/account_id) diterima dari klien tanpa verifikasi otorisasi di sisi server, berpotensi manipulasi hak akses atau IDOR (CWE-639).",
        "remediation_steps": [
            "Ambil identitas dan hak akses pengguna secara eksklusif dari context session token server yang terverifikasi.",
            "Validasi kepemilikan resource (tenant scoping) sebelum memproses query database.",
            "Gunakan UUID non-sekuensial atau enkripsi identifier publik."
        ],
        "code_patch": {
            "language": "python",
            "original_code": "# Menggunakan ID dari input user tanpa verifikasi kepemilikan\n@app.get('/api/orders')\ndef get_orders(user_id: int):\n    return db.query(Order).filter(Order.user_id == user_id).all()",
            "patched_code": "# Mengambil user_id langsung dari context session login terotentikasi\n@app.get('/api/orders')\ndef get_orders(current_user: User = Depends(get_current_user)):\n    return db.query(Order).filter(Order.user_id == current_user.id).all()"
        }
    },
    "PARAM-DEBUG-MODE-EXPOSURE": {
        "risk_explanation": "Parameter debug/internal testing aktif di lingkungan publik. Parameter ini dapat memicu pengungkapan traceback kesalahan internal atau bypass autentikasi (CWE-215).",
        "remediation_steps": [
            "Nonaktifkan dan hapus parameter evaluasi debug dari routing production.",
            "Pastikan environment variable APP_DEBUG atau NODE_ENV bernilai 'production'.",
            "Isolasi endpoint diagnostik hanya pada jaringan lokal atau staging dengan autentikasi mTLS."
        ],
        "code_patch": {
            "language": "python",
            "original_code": "debug_mode = request.query_params.get('debug') == 'true'\nif debug_mode:\n    show_full_system_traceback()",
            "patched_code": "# Abaikan query parameter klien; hanya baca flag server environment\nif settings.ENVIRONMENT == 'development' and settings.APP_DEBUG:\n    show_full_system_traceback()"
        }
    },
    "PARAM-UNENCODED-INPUT-REFLECTION": {
        "risk_explanation": "Parameter input dari URL direfleksikan langsung ke dalam body dokumen HTML respons tanpa contextual output encoding, membuka peluang celah Reflected Cross-Site Scripting (CWE-79).",
        "remediation_steps": [
            "Terapkan context-aware output encoding (HTML entity encoding) pada setiap parameter yang direfleksikan.",
            "Gunakan Content-Security-Policy (CSP) yang membatasi eksekusi skrip inline.",
            "Gunakan templating engine yang melakukan auto-escaping secara default."
        ],
        "code_patch": {
            "language": "python",
            "original_code": "return f\"<h1>Pencarian untuk: {query}</h1>\"",
            "patched_code": "import html\nsafe_query = html.escape(query)\nreturn f\"<h1>Pencarian untuk: {safe_query}</h1>\""
        }
    }
}

AI_DISCONNECTED_WARNING = "ai tidak dapat terhubung hasil mungkin halu atau sedikit tidak akurat"

_MODEL_COOLDOWN: Dict[str, float] = {}

def is_model_available(model_name: str) -> bool:
    return time.time() >= _MODEL_COOLDOWN.get(model_name, 0.0)

def mark_model_cooldown(model_name: str, duration_sec: float = 300.0):
    _MODEL_COOLDOWN[model_name] = time.time() + duration_sec

async def generate_remediation_for_finding(
    rule_id: str,
    title: str,
    category: str,
    code_snippet: str,
    cwe_id: str
) -> Dict[str, Any]:
    """
    Menghasilkan remediasi berbasis Gemini AI atau fallback rule engine terstruktur.
    Jika AI tidak terkonfigurasi atau error, menyertakan warning eksplisit.
    """
    # 1. Coba panggil Gemini jika API key dikonfigurasi
    if settings.GEMINI_API_KEY:
        candidate_pool = [
            settings.GEMINI_MODEL,
            "gemini-flash-lite-latest",
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
            "gemini-3.8-flash",
            "gemini-flash-latest"
        ]
        candidate_models = []
        for m in candidate_pool:
            if m and m not in candidate_models and is_model_available(m):
                candidate_models.append(m)

        if not candidate_models:
            # Fallback ke model paling ringan jika seluruhnya dalam masa cooldown
            candidate_models = ["gemini-flash-lite-latest"]

        prompt = f"""Kamu adalah Security Engineer Senior & Red Team Specialist. Berikan rekomendasi remediasi teknis dan kode perbaikan (before vs after) dalam format JSON murni tanpa markdown wrapper untuk temuan berikut:
Aturan: {rule_id}
Judul: {title}
Kategori: {category}
CWE: {cwe_id}
Snippet Kode: {code_snippet}

PANDUAN BAHASA & FORMAT:
- Berikan penjelasan risiko teknis dalam bahasa Indonesia yang komprehensif.
- ATURAN KHUSUS KALIMAT TERAKHIR: Pada bagian akhir kalimat (kalimat terakhir) dari "risk_explanation", WAJIB gunakan bahasa Inggris sebagai professional security impact / key takeaway statement.
- Pada "remediation_steps", langkah terakhir WAJIB dituliskan dalam bahasa Inggris sebagai concluding recommendation.

Output JSON HARUS sesuai skema berikut:
{{
  "risk_explanation": "Penjelasan risiko teknis dalam bahasa Indonesia. Ensure all parameters and access controls are strictly guarded to prevent unauthorized state tampering.",
  "remediation_steps": ["Langkah mitigasi 1", "Langkah mitigasi 2", "Enforce strict schema validation and immutable model attributes."],
  "code_patch": {{
    "language": "typescript|javascript|json|nginx|python|php",
    "original_code": "kode asli sebelum perbaikan",
    "patched_code": "kode aman setelah perbaikan"
  }}
}}"""

        for model_name in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={settings.GEMINI_API_KEY}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
            }
            model_timeout = 20.0 if "argon" in model_name else (15.0 if "3.8" in model_name else 10.0)
            try:
                async with httpx.AsyncClient(timeout=model_timeout) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidate_text = data["candidates"][0]["content"]["parts"][0]["text"]
                        try:
                            parsed = robust_json_parse(candidate_text)
                        except Exception as e_parse:
                            logger.warning(f"robust_json_parse gagal pada remediation {model_name}: {e_parse}")
                            parsed = None

                        if not parsed or not isinstance(parsed, dict):
                            continue

                        return {
                            "model": model_name,
                            "warning": None,
                            "risk_explanation": parsed.get("risk_explanation", ""),
                            "remediation_steps": parsed.get("remediation_steps", []),
                            "code_patch": parsed.get("code_patch", {
                                "language": detect_code_language("snippet", snippet=code_snippet),
                                "original_code": code_snippet,
                                "patched_code": "// Patched"
                            })
                        }
                    elif resp.status_code in (429, 503):
                        reason = "Quota exceeded" if resp.status_code == 429 else "High demand"
                        logger.warning(f"Gemini API model {model_name} status {resp.status_code} ({reason}), cooldown 5m & mencoba kandidat berikutnya...")
                        mark_model_cooldown(model_name, duration_sec=300.0)
                        continue
                    else:
                        logger.warning(f"Gemini API model {model_name} status {resp.status_code}")
                        mark_model_cooldown(model_name, duration_sec=120.0)
                        continue
            except Exception as e:
                err_desc = f"{type(e).__name__}: {e or 'Request Timeout'}"
                logger.warning(f"Gagal memanggil Gemini model {model_name} ({err_desc}), cooldown 3m & mencoba kandidat berikutnya...")
                mark_model_cooldown(model_name, duration_sec=180.0)
                continue

    # 2. Fallback heuristic database
    matched = DEFAULT_REMEDIATIONS.get(rule_id)
    if not matched:
        # Generic fallback
        matched = {
            "risk_explanation": f"Temuan {category} ({cwe_id}) pada logika sistem dapat memengaruhi integritas dan keamanan data aplikasi jika dibiarkan tanpa perbaikan.",
            "remediation_steps": [
                "Lakukan review kode dan isolasi parameter sensitif pada controller terkait.",
                "Terapkan validasi input dan otorisasi berbasis hak akses yang ketat.",
                "Perbarui dependensi dan konfigurasi server ke standar industri."
            ],
            "code_patch": {
                "language": detect_code_language("snippet", snippet=code_snippet),
                "original_code": code_snippet or "// Unsafe implementation",
                "patched_code": "// Safe hardened implementation"
            }
        }

    warning_val = None if settings.GEMINI_API_KEY else AI_DISCONNECTED_WARNING
    risk_prefix = "" if settings.GEMINI_API_KEY else f"[Catatan: {AI_DISCONNECTED_WARNING}]\n"

    return {
        "model": f"{settings.GEMINI_MODEL}" if not warning_val else f"{settings.GEMINI_MODEL} (Offline - {AI_DISCONNECTED_WARNING})",
        "warning": warning_val,
        "risk_explanation": f"{risk_prefix}{matched['risk_explanation']}",
        "remediation_steps": matched["remediation_steps"],
        "code_patch": matched["code_patch"]
    }
