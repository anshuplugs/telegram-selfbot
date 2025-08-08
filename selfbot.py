#!/usr/bin/env python3
"""
ANSHU Self-Bot (no keep-alive)
- First-run interactive login for API_ID, API_HASH, PHONE
- Handles 2-step password (SessionPasswordNeededError)
- Saves session to 'SESSION_NAME.session' (default: anshu.session)
- Reads PREFIXES from .env
- Ads/Bulk feature available but gated (ADS_ENABLED in .env + runtime confirm token)
- Optionally encrypts config.json using Fernet if ENCRYPT_CONFIG_KEY set
- Educational only. Use a throwaway/test account.
"""

import os, sys, time, json, re, random, sqlite3, asyncio, getpass
from contextlib import suppress
from pathlib import Path

# Third-party
try:
    from telethon import TelegramClient, events, utils
    from telethon.errors import SessionPasswordNeededError, FloodWaitError
    from telethon.tl import functions
except Exception as e:
    print("Missing dependency: telethon. Install with: pip install telethon")
    raise

try:
    import requests
except Exception:
    print("Missing dependency: requests. Install with: pip install requests")
    raise

# Optional cryptography for config encryption
try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None

# load .env simple parser
def load_env(envfile=".env"):
    if not os.path.exists(envfile):
        return
    with open(envfile, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if "=" in ln:
                k,v = ln.split("=",1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()

# Settings
API_ID = os.getenv("API_ID", "").strip()
API_HASH = os.getenv("API_HASH", "").strip()
PHONE_NUMBER = os.getenv("PHONE_NUMBER", "").strip()  # optional prefill
PREFIXES_RAW = os.getenv("PREFIXES", ". # / !")
PREFIXES = [p for p in re.split(r"\s+", PREFIXES_RAW.strip()) if p]
if not PREFIXES:
    PREFIXES = ["."]

ADS_ENABLED = os.getenv("ADS_ENABLED", "false").lower() in ("1","true","yes")
ENCRYPT_CONFIG_KEY = os.getenv("ENCRYPT_CONFIG_KEY", "").strip() or None
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip() or None
SESSION_NAME = os.getenv("SESSION_NAME", "anshu")

CONFIG_FILE = "config.json"   # may be encrypted
DB_FILE = "anshu_selfbot.db"
SESSION_FILE = f"{SESSION_NAME}.session"

# Database for custom commands
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS custom_cmds (id INTEGER PRIMARY KEY, trigger TEXT UNIQUE, reply TEXT)")
conn.commit()

# Helper: encrypt / decrypt config if key present
def encrypt_data(key, data: bytes) -> bytes:
    if Fernet is None:
        raise RuntimeError("cryptography not installed")
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(key, token: bytes) -> bytes:
    if Fernet is None:
        raise RuntimeError("cryptography not installed")
    f = Fernet(key)
    return f.decrypt(token)

def save_config(cfg: dict, encrypt_key: str | None):
    raw = json.dumps(cfg, ensure_ascii=False).encode()
    if encrypt_key:
        if Fernet is None:
            raise RuntimeError("cryptography not installed (needed to encrypt config)")
        token = encrypt_data(encrypt_key.encode(), raw)
        with open(CONFIG_FILE, "wb") as f:
            f.write(token)
    else:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

def load_config(encrypt_key: str | None):
    if not os.path.exists(CONFIG_FILE):
        return None
    if encrypt_key:
        if Fernet is None:
            raise RuntimeError("cryptography not installed")
        with open(CONFIG_FILE, "rb") as f:
            token = f.read()
        try:
            raw = decrypt_data(encrypt_key.encode(), token)
            return json.loads(raw.decode())
        except InvalidToken:
            print("Invalid ENCRYPT_CONFIG_KEY: cannot decrypt config.json")
            raise
    else:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

# Console UI small helpers
def print_banner(status_user=None):
    sep = "="*46
    print("\n" + sep)
    print("   🚀 ANSHU SELF-BOT STARTED 🚀")
    print(sep)
    print(f"[✓] Prefixes: {' '.join(PREFIXES)}")
    if status_user:
        print(f"[✓] Logged in as: {status_user}")
    print(f"[✓] Session file: {SESSION_FILE}")
    print(sep + "\n")

# normalize prefix
def find_prefix(text):
    for p in PREFIXES:
        if text.startswith(p):
            return p
    return None

# simple safe math eval (limited)
import math
def safe_eval_math(expr):
    allowed = {"pi": math.pi, "e": math.e, "abs":abs, "round":round}
    # allow math functions
    for fname in ("sin","cos","tan","sqrt","ceil","floor","fabs","factorial","log","log10","exp"):
        allowed[fname] = getattr(math, fname)
    if re.search(r"[;_@`\\]", expr):
        raise ValueError("Unsafe characters.")
    for name in re.findall(r"[A-Za-z_]\w*", expr):
        if name not in allowed:
            raise ValueError(f"Use of '{name}' not allowed.")
    return eval(expr, {"__builtins__": {}}, allowed)

# Create / start Telethon client with interactive login if needed
async def ensure_logged_in():
    global API_ID, API_HASH, PHONE_NUMBER
    # Load config if exists
    cfg = None
    if os.path.exists(CONFIG_FILE):
        try:
            cfg = load_config(ENCRYPT_CONFIG_KEY)
        except Exception as e:
            print("Failed to load encrypted config:", e)
            cfg = None
    if cfg:
        API_ID = str(cfg.get("api_id", API_ID))
        API_HASH = cfg.get("api_hash", API_HASH)
        PHONE_NUMBER = cfg.get("phone", PHONE_NUMBER)
    # If API_ID or API_HASH missing, prompt
    if not API_ID:
        API_ID = input("Enter API_ID (from my.telegram.org): ").strip()
    if not API_HASH:
        API_HASH = input("Enter API_HASH (from my.telegram.org): ").strip()
    # Prepare client
    client = TelegramClient(SESSION_NAME, int(API_ID), API_HASH)
    await client.connect()
    if not await client.is_user_authorized():
        if not PHONE_NUMBER:
            PHONE_NUMBER = input("Enter phone number (with country code, e.g. +91...): ").strip()
        try:
            # send code
            print("Sending code request...")
            await client.send_code_request(PHONE_NUMBER)
            code = input("Enter the code you received: ").strip()
            try:
                await client.sign_in(PHONE_NUMBER, code)
            except SessionPasswordNeededError:
                # ask for 2FA password
                pw = getpass.getpass("Two-step password is enabled. Enter your Telegram 2-step password: ")
                await client.sign_in(password=pw)
                # optionally ask to store encrypted
                store_pw = input("Store 2-step password encrypted in config.json? (y/N): ").strip().lower() == "y"
                if store_pw:
                    cfg = {"api_id": API_ID, "api_hash": API_HASH, "phone": PHONE_NUMBER, "password": pw}
                    # if ENCRYPT_CONFIG_KEY not set, generate one (if cryptography available)
                    if not ENCRYPT_CONFIG_KEY:
                        if Fernet is None:
                            print("cryptography not installed; cannot auto-generate ENCRYPT_CONFIG_KEY. Please set ENCRYPT_CONFIG_KEY in .env to enable saving encrypted config.")
                        else:
                            gen = Fernet.generate_key().decode()
                            print("\nGenerated ENCRYPT_CONFIG_KEY (store this safely; you will need it to read config.json):")
                            print(gen + "\n")
                            ENCRYPT_CONFIG_KEY = gen
                    if ENCRYPT_CONFIG_KEY:
                        save_config(cfg, ENCRYPT_CONFIG_KEY)
                        print("Encrypted config saved to config.json")
            # successful sign in - save config without password unless we had it
            if not cfg:
                cfg = {"api_id": API_ID, "api_hash": API_HASH, "phone": PHONE_NUMBER}
            # Save config encrypted if key available
            try:
                save_config(cfg, ENCRYPT_CONFIG_KEY)
            except Exception as e:
                print("Warning: failed to save config:", e)
        except Exception as ex:
            print("Login failed:", ex)
            await client.disconnect()
            raise
    else:
        # already authorized
        pass
    me = await client.get_me()
    # print banner and return client
    print_banner(f"{me.username or me.first_name} ({me.id})")
    return client

# ---------- Command handling basics ----------
# Commands will be outgoing (you type them)
DB = conn

async def handle_outgoing(event):
    raw = (event.raw_text or "").strip()
    if not raw:
        return
    p = find_prefix(raw)
    if not p:
        return
    body = raw[len(p):].strip()
    if not body:
        return
    cmd, *rest = body.split(" ",1)
    cmd = cmd.lower()
    arg = rest[0] if rest else ""
    # dispatch
    await dispatch_command(event, cmd, arg)

# Command implementations (subset + ads/bulk)
async def dispatch_command(event, cmd, arg):
    # basic help
    if cmd in ("help","cmds"):
        await cmd_help(event)
        return
    if cmd == "ping":
        t0 = time.time()
        await event.edit("🏓 Pinging...")
        await asyncio.sleep(0.12)
        await event.edit(f"🏓 Pong! `{int((time.time()-t0)*1000)}ms`")
        return
    if cmd == "math":
        if not arg:
            await event.edit("Usage: .math <expression>")
            return
        try:
            r = safe_eval_math(arg)
            await event.edit(f"🧮 `{arg}` = `{r}`")
        except Exception as e:
            await event.edit(f"Error: {e}")
        return
    if cmd == "insta":
        if not arg:
            await event.edit("Usage: .insta <username>")
            return
        await event.edit("Fetching (best-effort)...")
        try:
            headers = {"User-Agent":"Mozilla/5.0"}
            r = requests.get(f"https://www.instagram.com/{arg}/", headers=headers, timeout=10)
            if r.status_code != 200:
                await event.edit(f"Insta fetch HTTP {r.status_code}")
                return
            m = re.search(r"window\._sharedData = (.+?);</script>", r.text)
            if not m:
                await event.edit("Profile data not found")
                return
            data = json.loads(m.group(1))
            user = data["entry_data"]["ProfilePage"][0]["graphql"]["user"]
            out = (f"📸 @{user.get('username')}\nName: {user.get('full_name')}\nBio: {user.get('biography')}\n"
                   f"Followers: {user.get('edge_followed_by',{}).get('count')}  Private: {user.get('is_private')}")
            pic = user.get("profile_pic_url_hd") or user.get("profile_pic_url")
            if pic:
                bio = requests.get(pic, timeout=10).content
                await event.client.send_file(event.chat_id, io.BytesIO(bio), caption=out)
                await event.delete()
                return
            await event.edit(out)
        except Exception as e:
            await event.edit(f"Insta error: {e}")
        return

    if cmd == "ads":
        # Ads flow: only allowed if ADS_ENABLED true
        if not ADS_ENABLED:
            await event.edit("⚠️ Ads/Bulk is disabled by configuration. Set ADS_ENABLED=true in .env to enable (use responsibly).")
            return
        # require message body
        if not arg:
            await event.edit("Usage: .ads <your message text>\nThis will forward to groups/channels only after you confirm the runtime token.")
            return
        # generate confirmation token
        token = "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
        await event.edit(f"⚠️ ADS SAFETY: To confirm sending this ad to groups/channels, type the confirmation token in chat exactly:\n\n`{token}`\n\nYou have 60 seconds.")
        # wait for user reply in same chat with the token
        def check(ev):
            return (ev.out and (ev.raw_text or "").strip() == token)
        try:
            ev = await event.client.wait_for(events.NewMessage(outgoing=True, chats=event.chat_id, timeout=60), check=check)
        except asyncio.TimeoutError:
            await event.edit("Confirmation timed out. Ads cancelled.")
            return
        # if confirmed, collect target chats (groups/channels only), limit to 50 by default
        MAX_RECIPIENTS = 50
        await event.edit("Confirmation received. Gathering your group/channel dialogs (this may take a few seconds)...")
        dialogs = []
        async for d in event.client.iter_dialogs():
            if d.is_group or d.is_channel:
                # skip broadcast-only channels? We'll include channels
                dialogs.append(d)
        if not dialogs:
            await event.edit("No groups/channels found to send.")
            return
        # limit recipients
        recipients = dialogs[:MAX_RECIPIENTS]
        await event.edit(f"Preparing to send to {len(recipients)} groups/channels (max {MAX_RECIPIENTS}). Starting in 5s...")
        await asyncio.sleep(5)
        # send to each with randomized delay and minor variation
        base_text = arg
        sent = 0
        for d in recipients:
            # safety: skip if it's the same chat where command issued? still allow
            # create variation: append a random emoji or small suffix (keeps messages different)
            suffix = random.choice(["", " ✨", " 🔥", "✅", " — Join now!"])
            msg = base_text + suffix
            try:
                await event.client.send_message(d.id, msg)
                sent += 1
            except FloodWaitError as f:
                print("Flood wait:", f.seconds)
                await asyncio.sleep(f.seconds + 1)
            except Exception as e:
                # skip errors
                print("Send error to", d.id, e)
            # randomized delay between 2 and 6 seconds
            await asyncio.sleep(random.uniform(2.0, 6.0))
        await event.edit(f"Ads/Bulk completed. Sent to approx {sent} groups/channels. Respect platform rules.")
        return

    # custom commands from sqlite
    if cmd in ("add","list_cmds","remove"):
        # add: .add trigger | reply
        if cmd == "add":
            if "|" not in arg:
                await event.edit("Usage: .add <trigger> | <reply>")
                return
            trig, reply = [s.strip() for s in arg.split("|",1)]
            try:
                cur = conn.cursor()
                cur.execute("INSERT INTO custom_cmds (trigger, reply) VALUES (?, ?)", (trig, reply))
                conn.commit()
                await event.edit(f"Added custom command `{trig}`")
            except Exception as e:
                await event.edit(f"DB error: {e}")
            return
        if cmd == "list_cmds":
            cur = conn.cursor()
            cur.execute("SELECT trigger FROM custom_cmds")
            rows = cur.fetchall()
            if not rows:
                await event.edit("No custom commands.")
                return
            out = "Custom commands:\n" + "\n".join("- " + r[0] for r in rows)
            await event.edit(out)
            return
        if cmd == "remove":
            trig = arg.strip()
            cur = conn.cursor()
            cur.execute("DELETE FROM custom_cmds WHERE trigger=?", (trig,))
            conn.commit()
            await event.edit(f"Removed `{trig}` (if existed)")
            return

    # if it matches a custom command trigger, reply with stored reply
    cur = conn.cursor()
    cur.execute("SELECT reply FROM custom_cmds WHERE trigger=?", (cmd,))
    res = cur.fetchone()
    if res:
        await event.edit(res[0])
        return

    # default unknown
    await event.edit(f"Unknown command: {cmd}. Use {PREFIXES[0]}help to see commands.")

# Help text (grouped and descriptive)
async def cmd_help(event=None):
    parts = []
    parts.append("ANSHU SELF-BOT — Commands (prefixes: " + " ".join(PREFIXES) + ")")
    parts.append("\nInstagram 📸")
    parts.append(f" {PREFIXES[0]}insta <username>  → Get Instagram profile (best-effort)")
    parts.append(f" {PREFIXES[0]}reset <username>  → Simulated IG reset (educational)")
    parts.append("\nCrypto & Finance 💰")
    parts.append(f" {PREFIXES[0]}crypto <id>  → CoinGecko price (e.g. bitcoin)")
    parts.append(f" {PREFIXES[0]}usdt2inr <amt> / {PREFIXES[0]}inr2usdt <amt>")
    parts.append("\nMedia & Downloads 🎧")
    parts.append(f" {PREFIXES[0]}ytmp3 <query>  → YouTube -> MP3 (yt-dlp required)")
    parts.append(f" {PREFIXES[0]}pic  → Random picture")
    parts.append("\nUtilities 🛠️")
    parts.append(f" {PREFIXES[0]}ping  → latency")
    parts.append(f" {PREFIXES[0]}math <expr>  → calculate")
    parts.append(f" {PREFIXES[0]}trans <lang> <text>  → translate (libretranslate)")
    parts.append("\nAccount Actions 🔒")
    parts.append(f" {PREFIXES[0]}block / {PREFIXES[0]}unblock  (reply)")
    parts.append(f" {PREFIXES[0]}delete / {PREFIXES[0]}del  (reply or self)")
    parts.append("\nCustom & Premium ✨")
    parts.append(f" {PREFIXES[0]}add <trig> | <reply>  → custom cmd")
    parts.append(f" {PREFIXES[0]}list_cmds  {PREFIXES[0]}remove <trig>")
    parts.append(f" {PREFIXES[0]}pyenc generate|encrypt|decrypt  → (requires cryptography)")
    parts.append(f" {PREFIXES[0]}afk [text]  → toggle AFK")
    parts.append(f" {PREFIXES[0]}ai <prompt>  → (requires OPENAI_API_KEY)")
    parts.append("\nBulk / Ads")
    parts.append(f" {PREFIXES[0]}ads <message>  → Send to your groups/channels (requires ADS_ENABLED=true + runtime confirm token)")
    return "\n".join(parts)

# Attach handlers to client events after login
async def register_handlers(client):
    # outgoing commands (you type them)
    @client.on(events.NewMessage(outgoing=True))
    async def _outgoing(event):
        # skip if it's a forwarded/edited or service message
        await handle_outgoing(event)

    # simple incoming AFK auto-reply placeholder (you can expand)
    # (not enabling heavy auto-responses to avoid abuse)

# Main
async def main():
    client = await ensure_logged_in()
    await register_handlers(client)
    # attach help method accessible to dispatch
    global cmd_help
    # run until disconnected
    await client.run_until_disconnected()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down.")
    except Exception as e:
        print("Fatal error:", e)
        raise
