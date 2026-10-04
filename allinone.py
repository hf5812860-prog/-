#!/usr/bin/env python3
"""
مفكك Luraph AI — نظام كامل في ملف واحد.
FastAPI + SQLite + asyncio workers + تحليل ثابت + تقرير AI.

التشغيل:
    pip install fastapi "uvicorn[standard]" sqlalchemy aiofiles \
        python-multipart anthropic openai
    python3 allinone.py

المتغيرات البيئية:
    PORT=8080                          (Fly.io يوفّره)
    DEOBF_ROOT=/app/deobf
    STORAGE_DIR=/app/storage
    API_KEYS=admin
    AI_PROVIDER=anthropic | openai
    ANTHROPIC_API_KEY=sk-ant-xxx
    OPENAI_API_KEY=sk-xxx
    AI_MODEL=claude-sonnet-4-5
    MAX_UPLOAD_MB=100
    MAX_RUNTIME_SEC=3600
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import aiofiles
from fastapi import (FastAPI, File, Header, HTTPException, UploadFile, WebSocket,
                     WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from sqlalchemy import (Column, DateTime, Float, Integer, String, Text,
                        create_engine)
from sqlalchemy.orm import declarative_base, sessionmaker


# ============================================================
# الإعدادات
# ============================================================
PORT            = int(os.environ.get("PORT", "8080"))
DEOBF_ROOT      = os.environ.get("DEOBF_ROOT", "./deobf")
STORAGE_DIR     = os.environ.get("STORAGE_DIR", "./storage")
MAX_UPLOAD_MB   = int(os.environ.get("MAX_UPLOAD_MB", "100"))
MAX_RUNTIME_SEC = int(os.environ.get("MAX_RUNTIME_SEC", "3600"))
API_KEYS        = [k.strip() for k in os.environ.get("API_KEYS", "").split(",") if k.strip()]

AI_PROVIDER       = os.environ.get("AI_PROVIDER", "anthropic")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.environ.get("OPENAI_API_KEY", "")
AI_MODEL          = os.environ.get("AI_MODEL", "claude-sonnet-4-5")
AI_MAX_TOKENS     = int(os.environ.get("AI_MAX_TOKENS", "8192"))

DATABASE_URL = f"sqlite:///{STORAGE_DIR}/jobs.db"

Path(STORAGE_DIR, "inputs").mkdir(parents=True, exist_ok=True)
Path(STORAGE_DIR, "outputs").mkdir(parents=True, exist_ok=True)


# ============================================================
# قاعدة البيانات
# ============================================================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Job(Base):
    __tablename__ = "jobs"
    id             = Column(String(32), primary_key=True, default=lambda: uuid.uuid4().hex)
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status         = Column(String(16), default="queued")
    stage          = Column(String(64), default="uploaded")
    progress       = Column(Integer, default=0)
    input_name     = Column(String(255))
    input_size     = Column(Integer, default=0)
    input_path     = Column(String(512), default="")
    obfuscator     = Column(String(64))
    output_path    = Column(String(512))
    output_size    = Column(Integer)
    report_path    = Column(String(512))
    ai_report_path = Column(String(512))
    error          = Column(Text)
    runtime_sec    = Column(Float)
    analysis_json  = Column(Text)


Base.metadata.create_all(engine)


# ============================================================
# pubsub داخلي (بلا Redis)
# ============================================================
class LocalPubSub:
    def __init__(self):
        self.subs = {}

    def subscribe(self, job_id: str) -> asyncio.Queue:
        q = asyncio.Queue()
        self.subs.setdefault(job_id, []).append(q)
        return q

    def unsubscribe(self, job_id: str, q: asyncio.Queue):
        try:
            self.subs.get(job_id, []).remove(q)
        except ValueError:
            pass

    async def publish(self, job_id: str, data: dict):
        for q in self.subs.get(job_id, [])[:]:
            try:
                q.put_nowait(data)
            except Exception:
                pass


BUS = LocalPubSub()


def publish(job_id: str, **kw):
    """يحدّث قاعدة البيانات + يبث على المشتركين."""
    with SessionLocal() as db:
        j = db.get(Job, job_id)
        if j:
            for k, v in kw.items():
                if hasattr(j, k):
                    setattr(j, k, v)
            db.commit()
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(BUS.publish(job_id, kw))
    except RuntimeError:
        # (من subprocess/thread بلا loop) — نتجاهل، الواجهة تعتمد على polling
        pass


# ============================================================
# التحليل الثابت
# ============================================================
URL_RE     = re.compile(rb"https?://[^\s\"'<>]{4,200}")
WEBHOOK_RE = re.compile(rb"(discord\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com)")
IP_RE      = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
DOMAIN_RE  = re.compile(rb"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
KEY_RE     = re.compile(
    rb"[\"']?([A-Za-z_]*(?:key|token|secret|passwd|password|auth)[A-Za-z_]*)[\"']?\s*[:=]\s*[\"']([^\"']{6,200})[\"']",
    re.I)

SUSPICIOUS = {
    b"loadstring": "تنفيذ كود ديناميكي",
    b"getfenv": "الوصول للبيئة",
    b"setfenv": "تعديل البيئة",
    b"getgenv": "بيئة المنفذ",
    b"HttpGet": "طلب شبكي",
    b"HttpPost": "إرسال شبكي",
    b"request": "طلب شبكي",
    b"syn.request": "طلب Synapse",
    b"firesignal": "إطلاق إشارة",
    b"hookfunction": "اعتراض دالة",
    b"hookmetamethod": "اعتراض ميتا",
    b"getrawmetatable": "قراءة ميتا الجدول",
    b"setreadonly": "تعديل حماية الجدول",
    b"getconnections": "استخراج اتصالات",
    b"decompile": "تفكيك بايت كود",
    b"getscriptbytecode": "استخراج بايت كود",
    b"debug.getinfo": "تسريب معلومات",
    b"debug.getupvalue": "تسريب upvalue",
    b"Instance.new": "إنشاء كائن",
    b"game:GetService": "وصول للخدمة",
    b"Players.LocalPlayer": "اللاعب المحلي",
    b"Kick(": "طرد لاعب",
    b"teleport": "انتقال",
    b"robux": "عملة",
    b"powershell": "تشغيل PowerShell",
    b"cmd.exe": "تشغيل CMD",
    b"discord.com/api/webhooks": "ويب هوك ديسكورد",
    b"api.telegram.org": "تسريب تيليجرام",
    b"pastebin.com/raw": "جلب من Pastebin",
    b"transferFrom": "نقل توكن",
    b"approve(": "موافقة توكن",
    b"signTransaction": "توقيع محفظة",
    b"drain": "تفريغ محفظة",
    b"private key": "مفتاح خاص",
    b"aes": "تشفير AES",
    b"rc4": "تشفير RC4",
    b"base64": "Base64",
    b"keylogger": "مسجل مفاتيح",
    b"GetAsyncKeyState": "قراءة المفاتيح",
    b"SetWindowsHookEx": "تثبيت هوك",
    b"CreateRemoteThread": "خيط بعيد",
    b"VirtualAllocEx": "تخصيص بعيد",
    b"WriteProcessMemory": "كتابة بالعملية",
    b"LoadLibrary": "تحميل DLL",
    b"ShellExecute": "تنفيذ shell",
    b"os.execute": "تنفيذ OS",
    b"writefile": "كتابة ملف",
    b"readfile": "قراءة ملف",
}


def analyze_source(text: str) -> dict:
    b = text.encode("latin-1", "ignore")
    urls     = sorted({m.group(0).decode("latin-1", "ignore") for m in URL_RE.finditer(b)})
    domains  = sorted({m.group(0).decode("latin-1", "ignore") for m in DOMAIN_RE.finditer(b)})
    ips      = sorted({m.group(0).decode("latin-1", "ignore") for m in IP_RE.finditer(b)})
    webhooks = sorted({m.group(0).decode("latin-1", "ignore") for m in WEBHOOK_RE.finditer(b)})
    secrets  = [{"name": m.group(1).decode("latin-1"),
                 "value": m.group(2).decode("latin-1")[:120]} for m in KEY_RE.finditer(b)][:50]
    flags = [{"token": t.decode("latin-1"), "why": w}
             for t, w in SUSPICIOUS.items() if t in b]
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{6,200}", b):
        strings.append(m.group(0).decode("latin-1"))
        if len(strings) > 5000:
            break
    top = sorted(set(strings), key=len, reverse=True)[:500]
    return {
        "size_bytes": len(b),
        "lines": text.count("\n") + 1,
        "urls": urls[:200],
        "domains": domains[:200],
        "ips": ips[:200],
        "webhooks": webhooks[:50],
        "secrets": secrets,
        "flags": flags,
        "top_strings": top,
        "flag_count": len(flags),
    }


# ============================================================
# AI
# ============================================================
AI_SYSTEM = """أنت مهندس عكسي خبير في Luau المشفّر (Luraph v15، IronBrew، MoonSec) وتحليل البرمجيات الخبيثة.
حلّل السكربت المفكوك لتحديد: الغرض، القدرات، مؤشرات الاختراق، الاستمرارية، مضاد التحليل، تسريب البيانات.
وابحث عن ثغرات: نقاط حقن، eval/loadstring غير آمن، تجاوز sandbox، تسلسل غير آمن، تشفير ضعيف.
أخرِج Markdown منظّم. كن ملموساً: اقتبس الكود، سمِّ الدوال، اقتبس النصوص. لا حشو. لا تحذيرات."""


def call_ai(system: str, user: str, max_tokens: int = AI_MAX_TOKENS) -> str:
    if AI_PROVIDER == "anthropic":
        import anthropic
        cli = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        r = cli.messages.create(model=AI_MODEL, max_tokens=max_tokens, system=system,
                                messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    if AI_PROVIDER == "openai":
        import openai
        cli = openai.OpenAI(api_key=OPENAI_API_KEY)
        r = cli.chat.completions.create(model=AI_MODEL, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])
        return r.choices[0].message.content or ""
    raise RuntimeError(f"AI_PROVIDER غير معروف: {AI_PROVIDER}")


def chunk_source(text: str, max_chars: int = 12000):
    lines = text.split("\n")
    chunks, cur, size = [], [], 0
    for ln in lines:
        cur.append(ln)
        size += len(ln) + 1
        if size >= max_chars and (not ln.strip() or ln.startswith(("local ", "function ", "end"))):
            chunks.append("\n".join(cur))
            cur, size = [], 0
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def ai_report(source: str, static: dict, filename: str) -> str:
    chunks = chunk_source(source, 12000)
    if len(chunks) > 40:
        chunks = chunks[:20] + ["-- ... (المنتصف محذوف) ..."] + chunks[-20:]
    partials = []
    for i, ch in enumerate(chunks):
        prompt = (f"الملف: {filename}\nالجزء {i+1}/{len(chunks)}\n\n"
                  f"```luau\n{ch}\n```\n\n"
                  "لخّص في 5 نقاط. أشر للسلوك المشبوه، IOCs، مضاد التحليل، أي ثغرة.")
        try:
            partials.append(call_ai(AI_SYSTEM, prompt, max_tokens=1500))
        except Exception as e:
            partials.append(f"[فشل الجزء {i+1}: {e}]")
    synthesis = f"""ملخص التحليل الثابت:
- الحجم: {static['size_bytes']} بايت، {static['lines']} سطر
- العلامات: {static['flag_count']}
- الروابط: {static['urls'][:10]}
- Webhooks: {static['webhooks'][:5]}
- IPs: {static['ips'][:10]}
- رموز مشبوهة: {[f['token'] for f in static['flags'][:30]]}
- أسرار: {static['secrets'][:5]}

ملخصات الأجزاء:
{chr(10).join(f'--- الجزء {i+1} ---' + chr(10) + p for i, p in enumerate(partials))}

أخرج التقرير النهائي بصيغة Markdown بهذه الأقسام:
# الملخص التنفيذي
# الغرض
# القدرات
# مؤشرات الاختراق
# مضاد التحليل
# تسريب البيانات
# الثغرات المكتشفة
# الخطورة
# التوصيات
"""
    return call_ai(AI_SYSTEM, synthesis, max_tokens=AI_MAX_TOKENS)


# ============================================================
# مهمة التفكيك
# ============================================================
async def run_job(job_id: str):
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if not job:
            return
        inp = job.input_path
        name = job.input_name

    t0 = time.time()
    out = os.path.join(STORAGE_DIR, "outputs", f"{job_id}.devirt.luau")
    rep_path = os.path.join(STORAGE_DIR, "outputs", f"{job_id}.analysis.json")
    ai_path  = os.path.join(STORAGE_DIR, "outputs", f"{job_id}.report.md")

    publish(job_id, status="running", stage="كشف", progress=2)

    # --- كشف نوع التشويش
    obf = "unknown"
    try:
        d = subprocess.run(
            [sys.executable, os.path.join(DEOBF_ROOT, "deob.py"), inp, "--detect"],
            capture_output=True, text=True, timeout=60,
        )
        parts = (d.stdout.strip().splitlines()[-1] if d.stdout.strip() else "").split("\t")
        if parts:
            obf = parts[0]
    except Exception:
        pass
    publish(job_id, obfuscator=obf, stage="تفكيك", progress=5)

    # --- تفكيك
    cmd = [
        sys.executable, os.path.join(DEOBF_ROOT, "deob.py"),
        inp, "-o", out,
        "--timeout", str(MAX_RUNTIME_SEC),
        "--budget", str(MAX_RUNTIME_SEC - 60),
        "--devirt-rounds", "200",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip()
            m = re.search(r"round (\d+)", line)
            if m:
                pct = min(70, 5 + int(m.group(1)) // 3)
                publish(job_id, stage=f"جولة {m.group(1)}", progress=pct)
            if time.time() - t0 > MAX_RUNTIME_SEC:
                proc.kill()
                publish(job_id, status="failed", stage="مهلة",
                        error=f"تجاوز {MAX_RUNTIME_SEC} ثانية")
                return
        await proc.wait()
    except Exception as e:
        publish(job_id, status="failed", stage="خطأ", error=str(e)[:500])
        return

    if proc.returncode != 0 or not Path(out).exists():
        publish(job_id, status="failed", stage="تفكيك",
                error=f"deob.py فشل برمز {proc.returncode}")
        return

    # --- تحليل ثابت
    publish(job_id, stage="تحليل ثابت", progress=75)
    try:
        with open(out, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        publish(job_id, status="failed", stage="قراءة", error=str(e))
        return

    static = analyze_source(source)
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(static, f, ensure_ascii=False, indent=2)

    # --- تقرير AI
    has_ai = ((AI_PROVIDER == "anthropic" and ANTHROPIC_API_KEY) or
              (AI_PROVIDER == "openai" and OPENAI_API_KEY))
    if has_ai:
        publish(job_id, stage="تحليل AI", progress=80)
        try:
            report = await asyncio.to_thread(ai_report, source, static, name)
            with open(ai_path, "w", encoding="utf-8") as f:
                f.write(report)
        except Exception as e:
            with open(ai_path, "w", encoding="utf-8") as f:
                f.write(f"# فشل تقرير AI\n\n{e}")
    else:
        with open(ai_path, "w", encoding="utf-8") as f:
            f.write("# AI معطّل (لا يوجد مفتاح API)\n")

    # --- انتهى
    publish(
        job_id,
        status="done",
        stage="تم",
        progress=100,
        output_path=out,
        output_size=os.path.getsize(out),
        report_path=rep_path,
        ai_report_path=ai_path,
        runtime_sec=time.time() - t0,
        analysis_json=json.dumps(static, ensure_ascii=False),
    )


# ============================================================
# FastAPI
# ============================================================
app = FastAPI(title="مفكك Luraph AI", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------
# الصفحة الرئيسية
# ------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index():
    """يخدم index.html من نفس المجلد، أو صفحة تشخيص بسيطة."""
    here = Path(__file__).parent
    for cand in (here / "index.html", here / "static" / "index.html"):
        if cand.exists():
            return HTMLResponse(cand.read_text(encoding="utf-8"))
    return HTMLResponse("""<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>مفكك Luraph AI</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:40px}
code{background:#161b22;padding:2px 6px;border-radius:3px;color:#79c0ff}
a{color:#58a6ff}</style></head><body>
<h1>مفكك Luraph AI</h1>
<p>الخادم يعمل. لكن <code>index.html</code> غير موجود بجانب <code>allinone.py</code>.</p>
<p>تحقق من:</p>
<ul>
  <li><a href="/api/health">/api/health</a> — صحة الخادم</li>
  <li><a href="/docs">/docs</a> — توثيق API</li>
</ul>
</body></html>""")


# ------------------------------------------------------------
# الصحة
# ------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "ok": True,
        "version": "1.0.0",
        "deobf_root": os.path.abspath(DEOBF_ROOT),
        "deobf_exists": os.path.exists(os.path.join(DEOBF_ROOT, "deob.py")),
        "storage": os.path.abspath(STORAGE_DIR),
        "ai_provider": AI_PROVIDER,
        "ai_model": AI_MODEL,
        "ai_enabled": bool(
            (AI_PROVIDER == "anthropic" and ANTHROPIC_API_KEY) or
            (AI_PROVIDER == "openai" and OPENAI_API_KEY)
        ),
    }


# ------------------------------------------------------------
# مساعدة المصادقة
# ------------------------------------------------------------
def require_key(x_api_key: str = Header(default=""), k: str = ""):
    supplied = x_api_key or k
    if API_KEYS and supplied not in API_KEYS:
        raise HTTPException(401, "مفتاح API غير صحيح")
    return supplied or "anonymous"


# ------------------------------------------------------------
# الرفع
# ------------------------------------------------------------
@app.post("/api/upload")
async def upload(file: UploadFile = File(...), k: str = "",
                 x_api_key: str = Header(default="")):
    require_key(x_api_key, k)

    if file.size and file.size > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"الملف أكبر من {MAX_UPLOAD_MB} ميغا")
    if not file.filename.lower().endswith((".lua", ".luau", ".txt")):
        raise HTTPException(400, "فقط .lua أو .luau أو .txt")

    with SessionLocal() as db:
        job = Job(input_name=file.filename, input_size=0, input_path="")
        db.add(job)
        db.commit()
        db.refresh(job)
        job_id = job.id

    safe = re.sub(r"[^\w.\-]", "_", file.filename)[:120]
    path = os.path.join(STORAGE_DIR, "inputs", f"{job_id}__{safe}")
    size = 0
    async with aiofiles.open(path, "wb") as f:
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD_MB * 1024 * 1024:
                await f.close()
                try:
                    os.remove(path)
                except Exception:
                    pass
                with SessionLocal() as db:
                    j = db.get(Job, job_id)
                    if j:
                        db.delete(j)
                        db.commit()
                raise HTTPException(413, f"الملف أكبر من {MAX_UPLOAD_MB} ميغا")
            await f.write(chunk)

    with SessionLocal() as db:
        j = db.get(Job, job_id)
        j.input_path = path
        j.input_size = size
        db.commit()

    asyncio.create_task(run_job(job_id))
    return {"id": job_id, "status": "queued"}


# ------------------------------------------------------------
# المهام
# ------------------------------------------------------------
def _job_dict(j: Job) -> dict:
    out = {}
    for c in j.__table__.columns:
        v = getattr(j, c.name)
        if isinstance(v, datetime):
            v = v.isoformat()
        out[c.name] = v
    return out


@app.get("/api/jobs")
def list_jobs(k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        rows = db.query(Job).order_by(Job.created_at.desc()).limit(200).all()
        return [_job_dict(r) for r in rows]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r:
            raise HTTPException(404, "لا يوجد هذا العنصر")
        return _job_dict(r)


@app.get("/api/jobs/{job_id}/source", response_class=PlainTextResponse)
def get_source(job_id: str, k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r or not r.output_path or not os.path.exists(r.output_path):
            raise HTTPException(404, "لم يكتمل التفكيك")
        with open(r.output_path, encoding="utf-8", errors="replace") as f:
            return f.read()


@app.get("/api/jobs/{job_id}/source/download")
def download_source(job_id: str, k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r or not r.output_path or not os.path.exists(r.output_path):
            raise HTTPException(404, "لم يكتمل التفكيك")
        return FileResponse(
            r.output_path,
            media_type="text/plain",
            filename=f"{r.input_name}.devirt.luau",
        )


@app.get("/api/jobs/{job_id}/report", response_class=PlainTextResponse)
def get_report(job_id: str, k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r or not r.ai_report_path or not os.path.exists(r.ai_report_path):
            raise HTTPException(404, "لا يوجد تقرير")
        with open(r.ai_report_path, encoding="utf-8") as f:
            return f.read()


@app.get("/api/jobs/{job_id}/analysis")
def get_analysis(job_id: str, k: str = "", x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r or not r.analysis_json:
            raise HTTPException(404, "لا يوجد تحليل")
        return json.loads(r.analysis_json)


@app.post("/api/jobs/{job_id}/chat")
async def chat(job_id: str, body: dict, k: str = "",
               x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r or not r.output_path or not os.path.exists(r.output_path):
            raise HTTPException(404, "لم يكتمل التفكيك")
        with open(r.output_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    q = (body.get("q") or "").strip()
    if not q:
        raise HTTPException(400, "سؤال فارغ")
    chunks = chunk_source(source, 12000)
    qw = set(re.findall(r"\w+", q.lower()))
    scored = sorted(chunks, key=lambda c: -len(qw & set(re.findall(r"\w+", c.lower()))))[:3]
    ctx = "\n\n".join(f"```luau\n{c}\n```" for c in scored)
    try:
        ans = await asyncio.to_thread(
            call_ai, AI_SYSTEM,
            f"السؤال: {q}\n\nالكود:\n{ctx}\n\nأجب مع مراجع الكود.", 2000,
        )
    except Exception as e:
        raise HTTPException(502, f"AI: {e}")
    return {"answer": ans}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str, confirm: str = "", k: str = "",
               x_api_key: str = Header(default="")):
    require_key(x_api_key, k)
    if confirm != "yes":
        raise HTTPException(400, "أضف ?confirm=yes للتأكيد")
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if not r:
            raise HTTPException(404)
        for p in (r.input_path, r.output_path, r.report_path, r.ai_report_path):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        db.delete(r)
        db.commit()
    return {"deleted": job_id}


# ------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------
@app.websocket("/ws/jobs/{job_id}")
async def ws_job(ws: WebSocket, job_id: str):
    await ws.accept()
    with SessionLocal() as db:
        r = db.get(Job, job_id)
        if r:
            await ws.send_text(json.dumps({
                "status": r.status, "stage": r.stage,
                "progress": r.progress, "error": r.error,
            }, ensure_ascii=False))
    q = BUS.subscribe(job_id)
    try:
        while True:
            try:
                data = await asyncio.wait_for(q.get(), timeout=30)
                await ws.send_text(json.dumps(data, ensure_ascii=False))
                if data.get("status") in ("done", "failed"):
                    break
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"ping": True}))
    except WebSocketDisconnect:
        pass
    finally:
        BUS.unsubscribe(job_id, q)


# ============================================================
# التشغيل
# ============================================================
if __name__ == "__main__":
    import uvicorn
    print(f"▶ مفكك Luraph AI على http://0.0.0.0:{PORT}")
    print(f"  DEOBF_ROOT = {os.path.abspath(DEOBF_ROOT)}")
    print(f"  STORAGE    = {os.path.abspath(STORAGE_DIR)}")
    print(f"  AI         = {AI_PROVIDER} / {AI_MODEL}")
    print(f"  AI enabled = {bool((AI_PROVIDER == 'anthropic' and ANTHROPIC_API_KEY) or (AI_PROVIDER == 'openai' and OPENAI_API_KEY))}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
