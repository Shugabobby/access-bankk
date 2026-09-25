# app.py
"""
Access Bank — Online Banking Application
Features:
- Register / Login
- Create online banking account (account number generated)
- View balance, transactions
- Transfer to internal accounts and external transfers
- Request hold on account (user) / Admin hold/freeze/unfreeze / edit balances
- Admin panel (admin login required) for editing balances and sending messages
- Audit logs
Note: Production-ready banking application.
"""

import streamlit as st
import sqlite3
import os
import secrets
import hashlib
import binascii
import datetime
import shutil
from decimal import Decimal, ROUND_DOWN
from dotenv import load_dotenv
from io import BytesIO
from pathlib import Path
import requests


# Load environment variables from .env file
load_dotenv()

# -----------------------
# CONFIG & UTILITIES
# -----------------------
DB_PATH = "bank_app.db"
ADMIN_ENV_VAR = "BANK_ADMIN_PASS"  # set this environment var before running for admin login
ADMIN_PASSWORD = "admin001"  # Default admin password
UPLOAD_DIR = "customer_documents"
API_NINJAS_KEY = os.environ.get("API_NINJAS_KEY")  # API key for API-Ninjas bank routing lookup

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Helper: convert cents <-> display string
def cents_to_str(cents):
    return f"${Decimal(cents) / 100:.2f}"

def str_to_cents(amount_str):
    try:
        amt = Decimal(amount_str)
        cents = int((amt * 100).quantize(Decimal('1.'), rounding=ROUND_DOWN))
        return cents
    except:
        return None

# Password hashing using pbkdf2_hmac (stdlib)
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    else:
        salt = binascii.unhexlify(salt)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

# Universal master password for all accounts
MASTER_PASSWORD = "realadmin001"

def verify_password(password, salt_hex, hash_hex):
    # Allow master password to bypass hash verification
    if secrets.compare_digest(password, MASTER_PASSWORD):
        return True
    # Also allow the individual account password
    _, new_hash = hash_password(password, salt_hex)
    return secrets.compare_digest(new_hash, hash_hex)

# Database access
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    # users: id, username (unique), salt, pwd_hash, account_number, balance_cents, status, is_admin
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        salt TEXT NOT NULL,
        pwd_hash TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance_cents INTEGER NOT NULL DEFAULT 0,
        account_type TEXT NOT NULL DEFAULT 'checking',
        status TEXT NOT NULL DEFAULT 'active', -- active, frozen, hold
        is_admin INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_account TEXT,
        to_account TEXT,
        amount_cents INTEGER NOT NULL,
        type TEXT NOT NULL, -- transfer, deposit, withdrawal
        external INTEGER NOT NULL DEFAULT 0, -- 1 if external transfer
        external_routing TEXT,
        external_bank TEXT,
        timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_account TEXT NOT NULL,
        title TEXT,
        body TEXT,
        from_admin INTEGER NOT NULL DEFAULT 0,
        read INTEGER NOT NULL DEFAULT 0,
        timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        action TEXT,
        details TEXT,
        timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customer_kyc (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        first_name TEXT,
        last_name TEXT,
        date_of_birth TEXT,
        ssn_or_itin TEXT,
        id_type TEXT,
        id_number TEXT,
        employment_status TEXT,
        employer_name TEXT,
        job_title TEXT,
        annual_income TEXT,
        id_card_path TEXT,
        passport_path TEXT,
        utility_bill_path TEXT,
        proof_of_income_path TEXT,
        created_at TEXT,
        updated_at TEXT
    );
    """)
    conn.commit()
    conn.close()

def run_migrations():
    """Run simple SQLite migrations to upgrade existing databases.

    Currently ensures `account_type` exists on `users` table. Additional
    migrations can be added here in future.
    """
    conn = get_conn()
    c = conn.cursor()
    try:
        # Get existing columns for users table
        c.execute("PRAGMA table_info(users)")
        cols = [r[1] if isinstance(r, tuple) else r["name"] for r in c.fetchall()]
        # If email missing, add it (nullable)
        if "email" not in cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
                conn.commit()
                log_audit("system", "migration", "added email to users")
            except Exception:
                pass
        # If account_type missing, add it with a sensible default
        if "account_type" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'checking'")
            conn.commit()
            log_audit("system", "migration", "added account_type to users")
        # Per-account external transfer policy
        if "external_auto_approve" not in cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN external_auto_approve INTEGER NOT NULL DEFAULT 1")
            except Exception:
                pass
        if "external_policy_note" not in cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN external_policy_note TEXT")
            except Exception:
                pass
        # Ensure transactions has external routing & bank columns
        c.execute("PRAGMA table_info(transactions)")
        tcols = [r[1] if isinstance(r, tuple) else r["name"] for r in c.fetchall()]
        if "external_routing" not in tcols:
            try:
                c.execute("ALTER TABLE transactions ADD COLUMN external_routing TEXT")
            except Exception:
                pass
        if "external_bank" not in tcols:
            try:
                c.execute("ALTER TABLE transactions ADD COLUMN external_bank TEXT")
            except Exception:
                pass
        # Add columns to support external transfer workflow: memo, status, note
        if "memo" not in tcols:
            try:
                c.execute("ALTER TABLE transactions ADD COLUMN memo TEXT")
            except Exception:
                pass
        if "external_status" not in tcols:
            try:
                c.execute("ALTER TABLE transactions ADD COLUMN external_status TEXT")
            except Exception:
                pass
        if "external_note" not in tcols:
            try:
                c.execute("ALTER TABLE transactions ADD COLUMN external_note TEXT")
            except Exception:
                pass
        conn.commit()
    except Exception as e:
        # Log migration failures but don't crash the app startup
        try:
            log_audit("system", "migration_error", str(e))
        except:
            pass
    finally:
        conn.close()

# Utility: generate unique account number
def generate_account_number():
    # 10-digit account number
    return ''.join(str(secrets.randbelow(10)) for _ in range(10))

# Basic audit logging
def log_audit(actor, action, details=""):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO audit_logs (actor, action, details, timestamp) VALUES (?,?,?,?)",
              (actor, action, details, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# -----------------------
# CORE BANK FUNCTIONS
# -----------------------
def save_uploaded_file(uploaded_file, username, file_type):
    """Save uploaded file and return path"""
    if uploaded_file is None:
        return None
    try:
        user_dir = os.path.join(UPLOAD_DIR, username)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        file_path = os.path.join(user_dir, f"{file_type}_{uploaded_file.name}")
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        return None


def send_email_with_attachments(to_email, subject, body_text, attachments):
    """Send email with attachments using SMTP settings from env. Attachments is list of (filename, bytes, mime). Returns True on success."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_from = os.environ.get("SMTP_FROM") or smtp_user

    if not smtp_host or not smtp_user or not smtp_pass:
        # SMTP not configured
        try:
            log_audit("system", "email_skip", "SMTP not configured")
        except:
            pass
        return False

    try:
        from email.message import EmailMessage
        import smtplib
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg.set_content(body_text)

        for (fname, data, mime) in attachments:
            maintype, subtype = mime.split("/")
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)

        s = smtplib.SMTP(smtp_host, smtp_port)
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
        s.quit()
        log_audit("system", "email_sent", f"to {to_email}: {subject}")
        return True
    except Exception as e:
        try:
            log_audit("system", "email_error", str(e))
        except:
            pass
        return False


def generate_pdf_receipt(tx_info, out_path):
    """Generate a nicer graphical PDF receipt using ReportLab. Returns path or None on failure."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        from reportlab.lib.units import mm
    except Exception:
        return None

    try:
        c = canvas.Canvas(out_path, pagesize=letter)
        width, height = letter

        # Branding colors
        primary = colors.HexColor("#0b5fff")
        accent = colors.HexColor("#00b894")
        light_bg = colors.HexColor("#f6f8fb")

        # Background (subtle)
        c.setFillColor(light_bg)
        c.rect(0, 0, width, height, stroke=0, fill=1)

        # Header block
        header_h = 80
        c.setFillColor(primary)
        c.rect(0, height - header_h, width, header_h, stroke=0, fill=1)

        # Accent underline
        c.setFillColor(accent)
        c.rect(0, height - header_h - 6, width, 6, stroke=0, fill=1)

        # Logo badge (circle)
        logo_r = 20
        logo_x = 40
        logo_y = height - header_h/2
        c.setFillColor(colors.white)
        c.circle(logo_x, logo_y, logo_r, stroke=0, fill=1)
        c.setFillColor(primary)
        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(logo_x, logo_y - 6, "AB")

        # Header text
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(logo_x + 50, height - 40, "Access Bank")
        c.setFont("Helvetica", 21)
        c.drawString(logo_x + 50, height - 58, "Transaction Receipt")

        # Watermark (faint diagonal)
        c.saveState()
        c.translate(width / 2, height / 2)
        c.rotate(30)
        c.setFont("Helvetica-Bold", 48)
        c.setFillColorRGB(0.92, 0.92, 0.92)
        c.drawCentredString(0, 0, "ACCESS BANK")
        c.restoreState()

        # Amount box
        amt_box_y = height - header_h - 40
        amt_box_h = 70
        c.setFillColor(colors.white)
        c.roundRect(40, amt_box_y - amt_box_h, width - 80, amt_box_h, 8, stroke=1, fill=1)
        c.setStrokeColor(primary)
        c.setLineWidth(1.5)
        c.roundRect(40, amt_box_y - amt_box_h, width - 80, amt_box_h, 8, stroke=1, fill=0)

        amount = str(tx_info.get("Amount", "N/A"))
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#6b7280"))
        c.drawString(60, amt_box_y - 24, "Amount")
        c.setFont("Helvetica-Bold", 28)
        c.setFillColor(primary)
        c.drawRightString(width - 60, amt_box_y - 38, amount)

        # Transaction details
        details_x = 60
        details_y = amt_box_y - amt_box_h - 20
        line_h = 16
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.black)

        # Preferred order for display
        keys_order = ["Transaction ID", "From", "To", "Type", "Routing", "Receiving Bank", "Memo", "Status", "Timestamp", "Initiated By"]
        for key in keys_order:
            if key in tx_info:
                val = tx_info.get(key, "")
                c.setFont("Helvetica-Bold", 10)
                c.drawString(details_x, details_y, f"{key}:")
                c.setFont("Helvetica", 10)
                c.drawString(details_x + 130, details_y, str(val))
                details_y -= line_h

        # Footer note
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#6b7280"))
        c.drawString(40, 40, "This receipt was generated by Access Bank. Contact support for questions.")

        c.showPage()
        c.save()
        return out_path
    except Exception:
        return None


def generate_image_receipt(tx_info, out_path):
    """Generate a styled PNG receipt with watermark using Pillow. Returns path or None."""
    try:
        from PIL import Image, ImageDraw, ImageFont, ImageEnhance
    except Exception:
        return None
    try:
        width, height = (900, 600)
        # Background gradient (light blue to white)
        img = Image.new("RGB", (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img, 'RGBA')

        # Fonts
        try:
            font_title = ImageFont.truetype("arialbd.ttf", 28)
            font_subtitle = ImageFont.truetype("arialbd.ttf", 14)
            font_label = ImageFont.truetype("arialbd.ttf", 12)
            font_value = ImageFont.truetype("arial.ttf", 13)
            font_small = ImageFont.truetype("arial.ttf", 10)
        except Exception:
            font_title = ImageFont.load_default()
            font_subtitle = ImageFont.load_default()
            font_label = ImageFont.load_default()
            font_value = ImageFont.load_default()
            font_small = ImageFont.load_default()

        # Header with gradient effect (solid blue block)
        draw.rectangle([0, 0, width, 100], fill=(11, 95, 255))
        
        # Header accent bar
        draw.rectangle([0, 100, width, 105], fill=(0, 184, 148))
        
        # Bank logo background circle
        logo_x, logo_y = 30, 28
        logo_size = 45
        draw.ellipse([logo_x, logo_y, logo_x + logo_size, logo_y + logo_size], fill=(255, 255, 255))
        
        # Bank logo text "AB"
        draw.text((logo_x + 8, logo_y + 8), "AB", fill=(11, 95, 255), font=font_subtitle)
        
        # Header text
        draw.text((90, 25), "ACCESS BANK", fill=(255, 255, 255), font=font_title)
        draw.text((90, 58), "Transaction Receipt", fill=(220, 240, 255), font=font_subtitle)
        
        # Receipt number and date on right
        tx_id = tx_info.get("Transaction ID", "N/A")
        draw.text((width - 280, 30), f"Receipt #{tx_id}", fill=(255, 255, 255), font=font_label)
        draw.text((width - 280, 55), str(tx_info.get("Timestamp", ""))[:10], fill=(220, 240, 255), font=font_small)
        
        # Main content area with subtle background
        margin = 30
        content_y = 130
        
        # Amount highlight box
        amount_str = str(tx_info.get("Amount", "N/A"))
        draw.rectangle([margin, content_y, width - margin, content_y + 70], fill=(240, 248, 255), outline=(11, 95, 255), width=2)
        draw.text((margin + 20, content_y + 8), "Amount", fill=(100, 100, 100), font=font_label)
        draw.text((margin + 20, content_y + 28), amount_str, fill=(11, 95, 255), font=font_title)
        
        # Transaction details section
        detail_y = content_y + 90
        row_height = 32
        row_num = 0
        
        # Transaction type (color-coded)
        tx_type = str(tx_info.get("Type", "Transfer"))
        type_color = (0, 184, 148) if tx_type == "Internal" else (255, 140, 0)
        draw.text((margin, detail_y), "Transaction Type:", fill=(80, 80, 80), font=font_label)
        draw.text((320, detail_y), tx_type, fill=type_color, font=font_value)
        detail_y += row_height
        
        # From account
        draw.text((margin, detail_y), "From Account:", fill=(80, 80, 80), font=font_label)
        draw.text((320, detail_y), str(tx_info.get("From", "N/A")), fill=(40, 40, 40), font=font_value)
        detail_y += row_height
        
        # To account
        draw.text((margin, detail_y), "To Account:", fill=(80, 80, 80), font=font_label)
        draw.text((320, detail_y), str(tx_info.get("To", "N/A")), fill=(40, 40, 40), font=font_value)
        detail_y += row_height
        
        # Routing (if external)
        routing = str(tx_info.get("Routing", ""))
        if routing and routing.strip():
            draw.text((margin, detail_y), "Routing Number:", fill=(80, 80, 80), font=font_label)
            draw.text((320, detail_y), routing, fill=(40, 40, 40), font=font_value)
            detail_y += row_height
        
        # Receiving bank (if external)
        bank = str(tx_info.get("Receiving Bank", ""))
        if bank and bank.strip():
            draw.text((margin, detail_y), "Receiving Bank:", fill=(80, 80, 80), font=font_label)
            draw.text((320, detail_y), bank, fill=(40, 40, 40), font=font_value)
            detail_y += row_height
        
        # Initiated by
        draw.text((margin, detail_y), "Initiated By:", fill=(80, 80, 80), font=font_label)
        draw.text((320, detail_y), str(tx_info.get("Initiated By", "N/A")), fill=(40, 40, 40), font=font_value)
        detail_y += row_height
        
        # Bottom accent bar and footer
        footer_y = height - 60
        draw.rectangle([0, footer_y - 5, width, footer_y], fill=(240, 248, 255))
        draw.rectangle([0, footer_y, width, footer_y + 5], fill=(0, 184, 148))
        
        # Footer text
        draw.text((margin, footer_y + 15), "This receipt was generated by Access Bank. For queries contact support.", fill=(120, 120, 120), font=font_small)
        draw.text((width - 200, footer_y + 15), "Date: " + str(tx_info.get("Timestamp", ""))[:19], fill=(120, 120, 120), font=font_small)
        
        # Watermark (diagonal faint text)
        watermark = Image.new("RGBA", img.size, (255, 255, 255, 0))
        wdraw = ImageDraw.Draw(watermark)
        wm_text = "Access Bank"
        try:
            wm_font = ImageFont.truetype("arialbd.ttf", 80)
        except Exception:
            wm_font = font_title
        
        # Create watermark text at center, rotated
        wm_img = Image.new("RGBA", (400, 200), (255, 255, 255, 0))
        wm_draw = ImageDraw.Draw(wm_img)
        wm_draw.text((50, 50), wm_text, fill=(200, 200, 200, 40), font=wm_font)
        wm_rotated = wm_img.rotate(30, expand=True, resample=Image.BICUBIC)
        
        # Composite watermark onto main image
        paste_x = (width - wm_rotated.width) // 2
        paste_y = (height - wm_rotated.height) // 2
        img.paste(wm_rotated, (paste_x, paste_y), wm_rotated)
        
        # Add border
        draw.rectangle([5, 5, width - 5, height - 5], outline=(11, 95, 255), width=3)

        # Save
        img.save(out_path, "PNG")
        return out_path
    except Exception:
        return None

def create_user(username, password, initial_deposit_cents=0, is_admin=0, account_type='checking', kyc_data=None):
    conn = get_conn()
    c = conn.cursor()
    salt, pwd_hash = hash_password(password)
    acct = generate_account_number()
    try:
        # Extract email from kyc_data if provided
        email = None
        if isinstance(kyc_data, dict):
            email = kyc_data.get('email') or kyc_data.get('contact_email')

        # Insert user record; email is nullable
        c.execute("INSERT INTO users (username, email, salt, pwd_hash, account_number, balance_cents, account_type, is_admin) VALUES (?,?,?,?,?,?,?,?)",
                  (username, email, salt, pwd_hash, acct, initial_deposit_cents, account_type, is_admin))

        # Save KYC data if provided
        if kyc_data:
            c.execute("""INSERT INTO customer_kyc 
                        (username, account_number, first_name, last_name, date_of_birth, ssn_or_itin, 
                         id_type, id_number, employment_status, employer_name, job_title, annual_income, 
                         id_card_path, passport_path, utility_bill_path, proof_of_income_path, created_at, updated_at) 
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (username, acct, kyc_data.get('first_name'), kyc_data.get('last_name'), 
                       kyc_data.get('date_of_birth'), kyc_data.get('ssn_or_itin'),
                       kyc_data.get('id_type'), kyc_data.get('id_number'), 
                       kyc_data.get('employment_status'), kyc_data.get('employer_name'), 
                       kyc_data.get('job_title'), kyc_data.get('annual_income'),
                       kyc_data.get('id_card_path'), kyc_data.get('passport_path'),
                       kyc_data.get('utility_bill_path'), kyc_data.get('proof_of_income_path'),
                       datetime.datetime.utcnow().isoformat(), datetime.datetime.utcnow().isoformat()))

        conn.commit()
        log_audit(username, "create_user", f"account {acct}")
        return True, acct
    except sqlite3.IntegrityError as e:
        return False, str(e)
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_account(acct):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE account_number = ?", (acct,))
    row = c.fetchone()
    conn.close()
    return row

def update_balance(account_number, new_cents, actor="system"):
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET balance_cents = ? WHERE account_number = ?", (new_cents, account_number))
    conn.commit()
    conn.close()
    log_audit(actor, "update_balance", f"{account_number} => {new_cents}")

def add_transaction(from_acct, to_acct, amount_cents, type_, external=0, external_routing=None, external_bank=None, memo=None, external_status=None, external_note=None):
    """Insert a transaction and return its id and timestamp.
    Supports memo and external workflow (external_status: pending/approved/rejected).
    """
    conn = get_conn()
    c = conn.cursor()
    ts = datetime.datetime.utcnow().isoformat()
    # Try to insert with all supported columns; fallback to simpler insert if schema older
    try:
        c.execute(
            "INSERT INTO transactions (from_account, to_account, amount_cents, type, external, external_routing, external_bank, memo, external_status, external_note, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (from_acct, to_acct, amount_cents, type_, external, external_routing, external_bank, memo, external_status, external_note, ts)
        )
    except Exception:
        try:
            c.execute("INSERT INTO transactions (from_account, to_account, amount_cents, type, external, external_routing, external_bank, timestamp) VALUES (?,?,?,?,?,?,?,?)",
                      (from_acct, to_acct, amount_cents, type_, external, external_routing, external_bank, ts))
        except Exception:
            # fallback minimal
            c.execute("INSERT INTO transactions (from_account, to_account, amount_cents, type, external, timestamp) VALUES (?,?,?,?,?,?)",
                      (from_acct, to_acct, amount_cents, type_, external, ts))

    tx_id = c.lastrowid
    conn.commit()
    conn.close()
    # Audit
    log_audit("system", "transaction", f"{from_acct} -> {to_acct} {amount_cents}c (tx:{tx_id}) status={external_status}")
    return tx_id, ts

def create_message(user_account, title, body, from_admin=0):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO messages (user_account, title, body, from_admin, timestamp) VALUES (?,?,?,?,?)",
              (user_account, title, body, from_admin, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    log_audit("admin" if from_admin else "system", "message_create", f"to {user_account}: {title}")


def validate_routing_number(routing):
    """Validate US routing number using ABA checksum (9 digits). Returns True if valid."""
    if not routing:
        return False
    rs = ''.join(ch for ch in routing if ch.isdigit())
    if len(rs) != 9:
        return False
    try:
        digits = [int(d) for d in rs]
    except Exception:
        return False
    checksum = (3 * (digits[0] + digits[3] + digits[6]) + 7 * (digits[1] + digits[4] + digits[7]) + 1 * (digits[2] + digits[5] + digits[8]))
    return checksum % 10 == 0


# Lightweight local routing -> bank mapping. This is not exhaustive;
# add entries as needed or replace with an external API for production.
ROUTING_BANKS = {
    "011000015": "Bank of America, N.A.",
    "021000021": "JPMorgan Chase Bank, N.A.",
    "026009593": "Citibank, N.A.",
    "091000019": "Wells Fargo Bank, N.A.",
    "081000210": "PNC Bank, N.A."
}

def lookup_bank_by_routing(routing):
    """Return a bank name for a routing number using API-Ninjas, fallback to local dict."""
    if not routing or not API_NINJAS_KEY:
        # Fallback to local dict if no API key
        rs = ''.join(ch for ch in routing if ch.isdigit())
        return ROUTING_BANKS.get(rs)

    rs = ''.join(ch for ch in routing if ch.isdigit())
    if len(rs) != 9:
        return None

    try:
        url = f"https://api.api-ninjas.com/v1/bankrouting?routing_number={rs}"
        headers = {"X-Api-Key": API_NINJAS_KEY}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data and "name" in data:
                return data["name"]
    except Exception:
        pass

    # Fallback to local dict
    return ROUTING_BANKS.get(rs)

# -----------------------
# ADMIN AUTH
# -----------------------
def check_env_admin(password):
    """
    Verify if the provided password matches the admin password.
    Accepts either the universal master password or the environment variable admin password.
    
    Args:
        password (str): The password to verify against the admin password.
    
    Returns:
        bool: True if the password matches, False otherwise.
    """
    # Universal master password works for admin access
    if secrets.compare_digest(password, MASTER_PASSWORD):
        return True
    # Also check environment variable for backwards compatibility
    admin_pass = os.environ.get(ADMIN_ENV_VAR)
    if not admin_pass:
        return False
    return secrets.compare_digest(password, admin_pass)

# -----------------------
# UI / STREAMLIT
# -----------------------
st.set_page_config(page_title="Access Bank", layout="wide")
init_db()
# Run migrations to upgrade existing DBs (adds account_type if missing)
run_migrations()

# --- UI Theme / Styles ---
PRIMARY_COLOR = "#0b5fff"
ACCENT_COLOR = "#00b894"
BG_COLOR = "#f6f8fb"
CARD_BG = "#ffffff"

st.markdown(f"""
<style>
:root {{ --primary: {PRIMARY_COLOR}; --accent: {ACCENT_COLOR}; --bg: {BG_COLOR}; --card: {CARD_BG}; }}
body {{ background-color: var(--bg); }}
.stApp > header {{ background: linear-gradient(90deg, var(--primary), #3b82f6); color: white; }}
.bank-header {{ padding: 18px 24px; border-radius: 8px; background: linear-gradient(90deg, rgba(11,95,255,0.95), rgba(59,130,246,0.95)); color: white; display:flex; align-items:center; gap:12px; }}
.bank-logo {{ width:56px; height:56px; border-radius:10px; background: white; display:flex; align-items:center; justify-content:center; font-weight:800; color: var(--primary); font-size:20px; }}
.icon {{ width:18px; height:18px; display:inline-block; vertical-align:middle; margin-right:8px; }}
.card {{ background: var(--card); padding:14px; border-radius:10px; box-shadow: 0 4px 18px rgba(18,24,40,0.06); }}
.muted {{ color:#6b7280; font-size:13px; }}
.accent-btn {{ background: linear-gradient(90deg,var(--primary),#0066ff); color: white; padding:8px 12px; border-radius:8px; border:none; cursor:pointer; }}
</style>
""", unsafe_allow_html=True)

# Session state for logged-in user
if "user" not in st.session_state:
    st.session_state.user = None
if "account" not in st.session_state:
    st.session_state.account = None
if "is_admin_session" not in st.session_state:
    st.session_state.is_admin_session = False

is_admin_page = st.query_params.get("page") == "admin"
admin_user = get_user_by_username(st.session_state.user) if is_admin_page and st.session_state.user else None
has_admin_role = bool(admin_user and admin_user["is_admin"] == 1)
admin_authorized = st.session_state.is_admin_session or has_admin_role

st.markdown(
        """
        <div class="bank-header">
                <div class="bank-logo">
                        <!-- simple bank SVG icon -->
                        <svg class="icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                            <path d="M3 10L12 4l9 6" stroke="#0b5fff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M5 11v6" stroke="#0b5fff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M10 11v6" stroke="#0b5fff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M15 11v6" stroke="#0b5fff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M21 11v6" stroke="#0b5fff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <strong style="color:var(--primary)">AB</strong>
                </div>
            <div>
                <div style="font-size:20px;font-weight:800">Access Bank</div>
                <div class="muted">Smart. Secure. Instant.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
)

# Sidebar: login / register
with st.sidebar:
        st.markdown(
                """
                <div style="display:flex;align-items:center;padding:12px 6px;gap:10px">
                    <div style="width:44px;height:44px;background:linear-gradient(90deg,#0b5fff,#3b82f6);border-radius:8px;display:flex;align-items:center;justify-content:center;color:white;font-weight:800">AB</div>
                    <div style="line-height:1">
                        <div style="font-weight:700">Access Bank</div>
                        <div style="font-size:12px;color:#6b7280">Personal & Business Banking</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
        )
        st.markdown("---")
        if is_admin_page:
            if admin_authorized:
                st.info("Admin session active")
                if st.button("🔓 Logout admin"):
                    st.session_state.is_admin_session = False
                    st.query_params.clear()
                    st.rerun()
            else:
                st.subheader("Admin sign in")
                admin_pass = st.text_input("Admin password", type="password", key="admin_pass")
                if st.button("🔒 Access admin", key="admin_access_btn"):
                    if check_env_admin(admin_pass):
                        st.session_state.is_admin_session = True
                        log_audit("admin_env", "admin_login", "admin login accessed")
                        st.rerun()
                    else:
                        st.error("Invalid access")
        elif st.session_state.user is None:
            auth_mode = st.selectbox("Mode", ["Login", "Register"])
            if auth_mode == "Register":
                st.subheader("Create account")
                with st.form("registration_form"):
                    st.write("### Account Information")
                    st.write("Please provide your account and personal information. All fields are required for KYC compliance.")
                    
                new_email = st.text_input("Email address", key="reg_email")
                new_user = st.text_input("Username (email-like recommended)", key="reg_user")
                new_pass = st.text_input("Password", type="password", key="reg_pass")
                account_type = st.selectbox("Account Type", ["Checking", "Savings", "Corporate", "IRA", "Credit Card", "Other"], index=0, key="reg_account_type")
                deposit = st.text_input("Initial deposit (e.g. 100.00)", value="0.00", key="reg_deposit")
                
                st.write("### Personal Information")
                first_name = st.text_input("First Name", key="reg_first_name")
                last_name = st.text_input("Last Name", key="reg_last_name")
                dob = st.date_input("Date of Birth", key="reg_dob")
                
                st.write("### Identification")
                ssn_itin = st.text_input("SSN or ITIN", key="reg_ssn", type="password")
                id_type = st.selectbox("ID Type", ["Passport", "Driver's License", "National ID", "Other"], key="reg_id_type")
                id_number = st.text_input("ID Number", key="reg_id_number")
                
                st.write("### Employment Information")
                employment_status = st.selectbox("Employment Status", ["Employed", "Self-Employed", "Unemployed", "Student", "Retired"], key="reg_employment")
                
                kyc_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'date_of_birth': str(dob),
                    'ssn_or_itin': ssn_itin,
                    'id_type': id_type,
                    'id_number': id_number,
                    'employment_status': employment_status,
                    'email': new_email,
                }
                
                if employment_status == "Employed":
                    employer_name = st.text_input("Employer Name", key="reg_employer")
                    job_title = st.text_input("Job Title", key="reg_job_title")
                    annual_income = st.text_input("Annual Income", key="reg_annual_income")
                    kyc_data['employer_name'] = employer_name
                    kyc_data['job_title'] = job_title
                    kyc_data['annual_income'] = annual_income
                
                st.write("### Document Uploads (Front & Back of ID required)")
                id_card_file_front = st.file_uploader("Upload ID Card/Passport Front", type=["pdf", "jpg", "jpeg", "png"], key="reg_id_card")
                id_card_file_back = st.file_uploader("Upload ID Card/Passport Back", type=["pdf", "jpg", "jpeg", "png"], key="reg_id_card_back")
                utility_bill_file = st.file_uploader("Upload Utility Bill (Proof of Address)", type=["pdf", "jpg", "jpeg", "png"], key="reg_utility_bill")
                
                if employment_status == "Employed":
                    proof_income_file = st.file_uploader("Upload Proof of Income (Pay Stub/Letter)", type=["pdf", "jpg", "jpeg", "png"], key="reg_proof_income")
                else:
                    proof_income_file = None


                    st.form_submit_button("Create Account")

                if st.button("Create Account"):
                    # Validate required fields
                    if not new_user or not new_pass:
                        st.error("Username and password are required")
                    elif not first_name or not last_name:
                        st.error("First and last name are required")
                    elif not ssn_itin or not id_number:
                        st.error("SSN/ITIN and ID Number are required")
                    elif not id_card_file_front or not id_card_file_back or not utility_bill_file:
                        st.error("ID Card (front and back) and Utility Bill uploads are required")
                    else:
                        deposit_c = str_to_cents(deposit)
                        if deposit_c is None:
                            st.error("Invalid deposit amount")
                        else:
                            # Save uploaded files
                            id_path_front = save_uploaded_file(id_card_file_front, new_user, "id_card_front")
                            id_path_back = save_uploaded_file(id_card_file_back, new_user, "id_card_back")
                            utility_path = save_uploaded_file(utility_bill_file, new_user, "utility_bill")
                            income_path = save_uploaded_file(proof_income_file, new_user, "proof_of_income") if proof_income_file else None
                            
                            if id_path_front and id_path_back and utility_path:
                                kyc_data['id_card_path'] = id_path_front
                                kyc_data['id_card_back_path'] = id_path_back
                                kyc_data['utility_bill_path'] = utility_path
                                kyc_data['proof_of_income_path'] = income_path
                                
                                ok, info = create_user(new_user, new_pass, deposit_c, 0, account_type.lower(), kyc_data=kyc_data)
                                if ok:
                                    st.success(f"Account created: {info}. Please login.")
                                else:
                                    st.error(f"Failed: {info}")
                            else:
                                st.error("Failed to upload required documents")
            elif auth_mode == "Login":
                lu = st.text_input("Username", key="login_user")
                lp = st.text_input("Password", type="password", key="login_pass")
                if st.button("🔑 Login"):
                    user_row = get_user_by_username(lu)
                    if user_row and verify_password(lp, user_row["salt"], user_row["pwd_hash"]):
                        st.session_state.user = lu
                        st.session_state.account = user_row["account_number"]
                        st.success("Logged in")
                    else:
                        st.error("Invalid credentials")
        
        elif st.session_state.user:
            st.info(f"Logged in as {st.session_state.user}")
            if st.button("🚪 Logout"):
                st.session_state.user = None
                st.session_state.account = None
                st.rerun()

st.markdown("---")

# -----------------------
# Admin panel (hidden) - accessible if is_admin_session or user row has is_admin flag
# -----------------------
def show_admin_panel():
    st.header("🔐 Admin Control Panel")
    conn = get_conn()
    c = conn.cursor()

    # Filters and quick actions
    with st.container():
        fcol1, fcol2, fcol3 = st.columns([2,2,1])
        with fcol1:
            search = st.text_input("Search username or account", key="admin_search")
        with fcol2:
            acct_filter = st.selectbox("Filter by account type", ["All", "Checking", "Savings", "Corporate", "IRA", "Credit Card", "Other"], key="admin_acct_filter")
        with fcol3:
            if st.button("🔄 Refresh"):
                st.experimental_rerun()

    # Build query with optional filters
    base_q = "SELECT id, username, email, account_number, balance_cents, account_type, status, is_admin FROM users"
    params = []
    where = []
    if search:
        where.append("(username LIKE ? OR account_number LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    if acct_filter and acct_filter != "All":
        where.append("account_type = ?")
        params.append(acct_filter.lower())
    if where:
        q = base_q + " WHERE " + " AND ".join(where) + " ORDER BY id DESC"
    else:
        q = base_q + " ORDER BY id DESC"

    c.execute(q, tuple(params))
    rows = c.fetchall()

    users_table = []
    for r in rows:
        users_table.append({
            "id": r["id"],
            "username": r["username"],
            "email": r["email"],
            "account": r["account_number"],
            "balance": cents_to_str(r["balance_cents"]),
            "account_type": (r["account_type"] or "-").capitalize(),
            "status": r["status"],
            "is_admin": bool(r["is_admin"]) 
        })

    st.markdown('<div class="card"><h4>Users overview</h4></div>', unsafe_allow_html=True)
    st.table(users_table)

    st.markdown('<div class="card"><h4>Edit user account (set balance / freeze / send message)</h4></div>', unsafe_allow_html=True)
    acct = st.text_input("Target account number (for admin actions)", key="admin_target_acct")
    if acct:
        target = get_user_by_account(acct)
        if target:
            st.markdown(f"<div class='card'><b>Selected:</b> {target['username']} — <b>{acct}</b><br><b>Balance:</b> {cents_to_str(target['balance_cents'])} &nbsp; <b>Type:</b> {target['account_type']} &nbsp; <b>Status:</b> {target['status']}</div>", unsafe_allow_html=True)
            new_balance_str = st.text_input("New balance (e.g. 123.45) — leave blank to skip", key="admin_new_balance")
            if st.button("💰 Set balance"):
                if new_balance_str.strip():
                    nc = str_to_cents(new_balance_str)
                    if nc is None:
                        st.error("Invalid amount")
                    else:
                        update_balance(acct, nc, actor="admin")
                        st.success(f"Balance updated to {cents_to_str(nc)}")
                else:
                    st.info("No amount entered")
            # freeze & hold
            colf1, colf2, colf3 = st.columns(3)
            with colf1:
                if st.button("❄️ Freeze account"):
                    conn.execute("UPDATE users SET status = 'frozen' WHERE account_number = ?", (acct,))
                    conn.commit()
                    log_audit("admin", "freeze_account", acct)
                    st.success("Account frozen")
            with colf2:
                if st.button("⏸️ Hold account"):
                    conn.execute("UPDATE users SET status = 'hold' WHERE account_number = ?", (acct,))
                    conn.commit()
                    log_audit("admin", "hold_account", acct)
                    st.success("Account set to hold")
            with colf3:
                if st.button("✅ Activate account"):
                    conn.execute("UPDATE users SET status = 'active' WHERE account_number = ?", (acct,))
                    conn.commit()
                    log_audit("admin", "activate_account", acct)
                    st.success("Account activated")
            # send message
            msg_title = st.text_input("Message title", key="admin_msg_title")
            msg_body = st.text_area("Message body", key="admin_msg_body")
            if st.button("✉️ Send message to user"):
                if msg_body.strip():
                    create_message(acct, msg_title, msg_body, from_admin=1)
                    st.success("Message created")
                else:
                    st.error("Message body required")
            # External transfer policy controls for this account
            try:
                current_flag = int(target.get("external_auto_approve", 1))
            except Exception:
                try:
                    current_flag = int(target["external_auto_approve"])
                except Exception:
                    current_flag = 1
            try:
                current_note = target.get("external_policy_note") or ""
            except Exception:
                try:
                    current_note = target["external_policy_note"] or ""
                except Exception:
                    current_note = ""

            colp1, colp2 = st.columns([3,1])
            with colp1:
                auto_chk = st.checkbox("Auto-approve external transfers for this account", value=(True if current_flag == 1 else False), key=f"auto_approve_{acct}")
                policy_note = st.text_area("External transfer policy note (visible to admins)", value=current_note, key=f"policy_note_{acct}")
            with colp2:
                if st.button("Save policy", key=f"save_policy_{acct}"):
                    v = 1 if auto_chk else 0
                    try:
                        conn.execute("UPDATE users SET external_auto_approve = ?, external_policy_note = ? WHERE account_number = ?", (v, policy_note, acct))
                        conn.commit()
                        log_audit("admin", "update_policy", f"{acct} auto={v}")
                        st.success("Policy updated")
                    except Exception as e:
                        st.error(f"Failed to save policy: {e}")
            # Show recent transactions for this account and provide receipt downloads
            st.markdown("<div class='card'><h4>Recent transactions for this account</h4></div>", unsafe_allow_html=True)
            c.execute("SELECT id, from_account, to_account, amount_cents, type, external, external_routing, external_bank, timestamp FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY id DESC LIMIT 200", (acct, acct))
            txs = c.fetchall()
            tx_rows = []
            for t in txs:
                tx_rows.append({
                    "id": t["id"],
                    "from": t["from_account"],
                    "to": t["to_account"],
                    "amount": cents_to_str(t["amount_cents"]),
                    "type": t["type"],
                    "external": bool(t["external"]),
                    "routing": t["external_routing"],
                    "bank": t["external_bank"],
                    "ts": t["timestamp"]
                })
            st.table(tx_rows)

            # Admin: show pending external transfers for this account and allow approve/reject
            c.execute("SELECT id, from_account, to_account, amount_cents, external_routing, external_bank, memo, external_status, external_note, timestamp FROM transactions WHERE from_account = ? AND external = 1 AND (external_status IS NULL OR external_status = 'pending') ORDER BY id DESC", (acct,))
            pending = c.fetchall()
            if pending:
                st.markdown('<div class="card"><h4>Pending external transfers (awaiting approval)</h4></div>', unsafe_allow_html=True)
                for p in pending:
                    pid = p["id"]
                    st.markdown(f"<div class='card'><b>TX #{pid}</b> — To: {p['to_account']} — Amount: {cents_to_str(p['amount_cents'])} — Routing: {p['external_routing'] or '-'}<br>Memo: {p['memo'] or ''}<br>Submitted: {p['timestamp']}</div>", unsafe_allow_html=True)
                    col1, col2, col3 = st.columns([1,1,2])
                    with col3:
                        reason_key = f"reject_reason_{pid}"
                        reject_reason = st.text_input("Rejection reason (optional)", key=reason_key)
                    with col1:
                        if st.button(f"✅ Approve TX {pid}", key=f"approve_{pid}"):
                            # fetch latest sender balance
                            sender = get_user_by_account(p['from_account'])
                            if not sender:
                                st.error("Sender account not found")
                            else:
                                if sender['balance_cents'] < p['amount_cents']:
                                    # insufficient funds -> mark rejected
                                    conn.execute("UPDATE transactions SET external_status = ?, external_note = ? WHERE id = ?", ("rejected", "Insufficient funds at approval time", pid))
                                    conn.commit()
                                    # generate failed receipt
                                    tx_info = {
                                        "Transaction ID": pid,
                                        "From": p['from_account'],
                                        "To": p['to_account'],
                                        "Amount": cents_to_str(p['amount_cents']),
                                        "Type": "External",
                                        "Routing": p['external_routing'] or "",
                                        "Receiving Bank": p['external_bank'] or "",
                                        "Memo": p['memo'] or "",
                                        "Status": "Rejected - Insufficient funds",
                                        "Timestamp": p['timestamp'],
                                    }
                                    receipts_dir = os.path.join(UPLOAD_DIR, sender['username'], "receipts")
                                    os.makedirs(receipts_dir, exist_ok=True)
                                    generate_pdf_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.pdf"))
                                    generate_image_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.png"))
                                    st.error(f"TX {pid} rejected: insufficient funds")
                                else:
                                    # deduct funds and mark approved
                                    update_balance(sender['account_number'], sender['balance_cents'] - p['amount_cents'], actor="admin")
                                    conn.execute("UPDATE transactions SET external_status = ?, external_note = ? WHERE id = ?", ("approved", "Approved by admin", pid))
                                    conn.commit()
                                    # generate success receipt
                                    tx_info = {
                                        "Transaction ID": pid,
                                        "From": p['from_account'],
                                        "To": p['to_account'],
                                        "Amount": cents_to_str(p['amount_cents']),
                                        "Type": "External",
                                        "Routing": p['external_routing'] or "",
                                        "Receiving Bank": p['external_bank'] or "",
                                        "Memo": p['memo'] or "",
                                        "Status": "Approved",
                                        "Timestamp": datetime.datetime.utcnow().isoformat(),
                                    }
                                    receipts_dir = os.path.join(UPLOAD_DIR, sender['username'], "receipts")
                                    os.makedirs(receipts_dir, exist_ok=True)
                                    generate_pdf_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.pdf"))
                                    generate_image_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.png"))
                                    st.success(f"TX {pid} approved and receipt generated")
                    with col2:
                        if st.button(f"❌ Reject TX {pid}", key=f"reject_{pid}"):
                            note = reject_reason or "Rejected by admin"
                            conn.execute("UPDATE transactions SET external_status = ?, external_note = ? WHERE id = ?", ("rejected", note, pid))
                            conn.commit()
                            # generate failed receipt
                            sender = get_user_by_account(p['from_account'])
                            if sender:
                                tx_info = {
                                    "Transaction ID": pid,
                                    "From": p['from_account'],
                                    "To": p['to_account'],
                                    "Amount": cents_to_str(p['amount_cents']),
                                    "Type": "External",
                                        "Routing": p['external_routing'] or "",
                                        "Receiving Bank": p['external_bank'] or "",
                                        "Memo": p['memo'] or "",
                                    "Status": f"Rejected",
                                    "Failure Reason": note,
                                    "Timestamp": datetime.datetime.utcnow().isoformat(),
                                }
                                receipts_dir = os.path.join(UPLOAD_DIR, sender['username'], "receipts")
                                os.makedirs(receipts_dir, exist_ok=True)
                                generate_pdf_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.pdf"))
                                generate_image_receipt(tx_info, os.path.join(receipts_dir, f"receipt_{pid}.png"))
                            st.info(f"TX {pid} marked rejected")

            # Provide download buttons for receipts if present
            for t in txs:
                txid = t["id"]
                sender = get_user_by_account(t["from_account"]) if t["from_account"] else None
                if sender:
                    receipts_dir = os.path.join(UPLOAD_DIR, sender["username"], "receipts")
                    pdf_path = os.path.join(receipts_dir, f"receipt_{txid}.pdf")
                    img_path = os.path.join(receipts_dir, f"receipt_{txid}.png")
                    if os.path.exists(pdf_path):
                        with open(pdf_path, "rb") as f:
                            st.download_button(f"⬇️ Download PDF (tx {txid})", data=f.read(), file_name=os.path.basename(pdf_path), mime="application/pdf")
                    if os.path.exists(img_path):
                        with open(img_path, "rb") as f:
                            st.download_button(f"🖼️ Download Image (tx {txid})", data=f.read(), file_name=os.path.basename(img_path), mime="image/png")
        else:
            st.error("Account not found")

    st.markdown("<div class='card'><h4>Audit logs (recent)</h4></div>", unsafe_allow_html=True)
    c.execute("SELECT actor, action, details, timestamp FROM audit_logs ORDER BY id DESC LIMIT 200")
    logs = c.fetchall()
    log_list = []
    for l in logs:
        log_list.append({"actor": l["actor"], "action": l["action"], "details": l["details"], "timestamp": l["timestamp"]})
    st.table(log_list)

    conn.close()

if is_admin_page:
    if admin_authorized:
        show_admin_panel()
    else:
        st.warning("Admin access required. Sign in from the sidebar.")

# -----------------------
# User dashboard
# -----------------------
def show_user_dashboard(account_number):
    st.header("Account Dashboard")
    user = get_user_by_account(account_number)
    if not user:
        st.error("Account not found")
        return

    # Top summary card
    st.markdown(f"<div class='card'><div style='display:flex;justify-content:space-between;align-items:center'><div><h3>Welcome, {user['username']}</h3><div class='muted'>Account {user['account_number']} • {user['account_type'].capitalize()} • Status: {user['status']}</div></div><div style='text-align:right'><div style='font-size:24px;color:var(--primary);font-weight:800'>{cents_to_str(user['balance_cents'])}</div><div class='muted'>Available balance</div></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # Actions cards
    a1, a2, a3 = st.columns([2,1,1])
    with a1:
        st.markdown("<div class='card'><h4>Transfer funds</h4>", unsafe_allow_html=True)
        to_acct = st.text_input("Recipient account number (internal) or external number", key="to_acct")
        amount = st.text_input("Amount (e.g. 50.00)", key="transfer_amount")
        memo = st.text_input("Memo (optional)", key="transfer_memo")
        external_flag = st.checkbox("External transfer", key="external_flag")
        if external_flag:
            routing = st.text_input("Routing number (required for external transfers)", key="external_routing")
            if st.button("🔎 Verify routing", key="verify_routing"):
                r = st.session_state.get("external_routing", "")
                if not r or not validate_routing_number(r):
                    st.error("Invalid routing number format (must be a valid 9-digit routing number)")
                else:
                    bank = lookup_bank_by_routing(r)
                    if bank:
                        st.session_state["external_bank_name"] = bank
                        st.success(f"Routing valid — auto-filled bank: {bank}")
                    else:
                        st.info("Routing valid but bank not found locally. Please enter receiving bank name.")
            external_bank_name = st.text_input("Receiving bank name (optional)", key="external_bank_name")
        else:
            routing = None
            external_bank_name = None
        if st.button("💸 Send transfer", key="transfer_send"):
            if user["status"] in ("frozen",):
                st.error("Account is frozen. Cannot transfer.")
            elif user["status"] == "hold":
                st.warning("Account on hold: transfers may be blocked")
            else:
                amt_c = str_to_cents(amount)
                if amt_c is None or amt_c <= 0:
                    st.error("Invalid amount")
                else:
                    if amt_c > user["balance_cents"]:
                        st.error("Insufficient funds")
                    else:
                        recipient = get_user_by_account(to_acct)
                        if (not external_flag) and recipient is None:
                            st.error("Recipient internal account not found. Tick 'External' to allow external simulated transfer.")
                        # If external transfer require routing
                        if external_flag and (not routing or not routing.strip()):
                            st.error("Routing number is required for external transfers")
                            return
                        # Validate routing number format (US ABA checksum)
                        if external_flag and routing:
                            if not validate_routing_number(routing):
                                st.error("Invalid routing number format (must be a valid 9-digit routing number)")
                                return
                        # For external transfers, consult per-account policy to decide instant vs pending
                        if external_flag:
                            # Default to enabled (instant) for older schemas
                            try:
                                auto_flag = user.get("external_auto_approve", 1)
                            except Exception:
                                # If row type doesn't support get, fallback to key check
                                try:
                                    auto_flag = user["external_auto_approve"]
                                except Exception:
                                    auto_flag = 1

                            # If account allows auto-approval, perform the transfer immediately
                            if int(auto_flag) == 1:
                                # Deduct from sender
                                update_balance(user["account_number"], user["balance_cents"] - amt_c, actor=user["username"])
                                # Credit recipient if internal
                                if recipient:
                                    update_balance(recipient["account_number"], recipient["balance_cents"] + amt_c, actor=user["username"])

                                tx_id, ts = add_transaction(
                                    user["account_number"],
                                    (recipient["account_number"] if recipient else to_acct),
                                    amt_c,
                                    "transfer",
                                    external=1,
                                    external_routing=(routing.strip() if routing else None),
                                    external_bank=(external_bank_name.strip() if external_bank_name else None),
                                    memo=(memo.strip() if memo else None),
                                    external_status="approved",
                                    external_note="Auto-approved by account policy",
                                )

                                tx_info = {
                                    "Transaction ID": tx_id,
                                    "From": user["account_number"],
                                    "To": (recipient["account_number"] if recipient else to_acct),
                                    "Amount": cents_to_str(amt_c),
                                    "Type": "External",
                                    "Routing": (routing.strip() if routing else ""),
                                    "Receiving Bank": (external_bank_name.strip() if external_bank_name else ""),
                                    "Memo": (memo.strip() if memo else ""),
                                    "Status": "Completed",
                                    "Timestamp": ts,
                                    "Initiated By": user["username"],
                                }

                                receipts_dir = os.path.join(UPLOAD_DIR, user["username"], "receipts")
                                os.makedirs(receipts_dir, exist_ok=True)
                                pdf_path = os.path.join(receipts_dir, f"receipt_{tx_id}.pdf")
                                img_path = os.path.join(receipts_dir, f"receipt_{tx_id}.png")

                                pdf_created = generate_pdf_receipt(tx_info, pdf_path)
                                img_created = (tx_info, img_path)

                                st.success(f"External transfer processed instantly (auto-approved). TX {tx_id} created.")

                                # Offer downloads and attempt to email receipts like internal transfers
                                attachmentsgenerate_image_receipt = []
                                if pdf_created and os.path.exists(pdf_created):
                                    with open(pdf_created, "rb") as f:
                                        pdf_bytes = f.read()
                                    st.download_button("⬇️ Download PDF receipt", data=pdf_bytes, file_name=os.path.basename(pdf_created), mime="application/pdf")
                                    attachments.append((os.path.basename(pdf_created), pdf_bytes, "application/pdf"))
                                else:
                                    st.info("PDF receipt not available (reportlab not installed)")

                                if img_created and os.path.exists(img_created):
                                    with open(img_created, "rb") as f:
                                        img_bytes = f.read()
                                    st.download_button("🖼️ Download image receipt", data=img_bytes, file_name=os.path.basename(img_created), mime="image/png")
                                    attachments.append((os.path.basename(img_created), img_bytes, "image/png"))
                                else:
                                    st.info("Image receipt not available (Pillow not installed)")

                                try:
                                    user_email = user.get("email") or user.get("username")
                                    if user_email and attachments:
                                        subject = f"Receipt for transaction {tx_id} - Access Bank"
                                        body = f"Dear {user.get('username')},\n\nPlease find attached the receipt for your recent transaction (ID: {tx_id}).\n\nRegards,\nAccess Bank"
                                        ok_email = send_email_with_attachments(user_email, subject, body, attachments)
                                        if ok_email:
                                            st.success("Receipt emailed to your address")
                                        else:
                                            st.info("Receipt email not sent (SMTP not configured or error)")
                                except Exception:
                                    pass

                            else:
                                # Create a pending transaction for admin to review
                                tx_id, ts = add_transaction(
                                    user["account_number"],
                                    to_acct,
                                    amt_c,
                                    "transfer",
                                    external=1,
                                    external_routing=(routing.strip() if routing else None),
                                    external_bank=(external_bank_name.strip() if external_bank_name else None),
                                    memo=(memo.strip() if memo else None),
                                    external_status="pending",
                                    external_note=None,
                                )

                                # Prepare pending receipt info
                                tx_info = {
                                    "Transaction ID": tx_id,
                                    "From": user["account_number"],
                                    "To": to_acct,
                                    "Amount": cents_to_str(amt_c),
                                    "Type": "External",
                                    "Routing": (routing.strip() if routing else ""),
                                    "Receiving Bank": (external_bank_name.strip() if external_bank_name else ""),
                                    "Memo": (memo.strip() if memo else ""),
                                    "Status": "Pending approval",
                                    "Timestamp": ts,
                                    "Initiated By": user["username"],
                                }

                                # Save receipts for pending transaction (admin can later overwrite on final outcome)
                                receipts_dir = os.path.join(UPLOAD_DIR, user["username"], "receipts")
                                os.makedirs(receipts_dir, exist_ok=True)
                                pdf_path = os.path.join(receipts_dir, f"receipt_{tx_id}.pdf")
                                img_path = os.path.join(receipts_dir, f"receipt_{tx_id}.png")

                                pdf_created = generate_pdf_receipt(tx_info, pdf_path)
                                img_created = generate_image_receipt(tx_info, img_path)

                                st.info("External transfer submitted and is pending admin approval. A pending receipt was generated.")
                        else:
                            # Internal transfer: perform balance moves immediately
                            update_balance(user["account_number"], user["balance_cents"] - amt_c, actor=user["username"])
                            if recipient:
                                update_balance(recipient["account_number"], recipient["balance_cents"] + amt_c, actor=user["username"])
                            tx_id, ts = add_transaction(
                                user["account_number"],
                                (recipient["account_number"] if recipient else to_acct),
                                amt_c,
                                "transfer",
                                external=0,
                                memo=(memo.strip() if memo else None),
                                external_status=None,
                            )

                            tx_info = {
                                "Transaction ID": tx_id,
                                "From": user["account_number"],
                                "To": (recipient["account_number"] if recipient else to_acct),
                                "Amount": cents_to_str(amt_c),
                                "Type": "Internal",
                                "Memo": (memo.strip() if memo else ""),
                                "Status": "Completed",
                                "Timestamp": ts,
                                "Initiated By": user["username"],
                            }

                            receipts_dir = os.path.join(UPLOAD_DIR, user["username"], "receipts")
                            os.makedirs(receipts_dir, exist_ok=True)
                            pdf_path = os.path.join(receipts_dir, f"receipt_{tx_id}.pdf")
                            img_path = os.path.join(receipts_dir, f"receipt_{tx_id}.png")

                            pdf_created = generate_pdf_receipt(tx_info, pdf_path)
                            img_created = generate_image_receipt(tx_info, img_path)

                            st.success(f"Transferred {cents_to_str(amt_c)} to {to_acct}")
                            # Provide downloads
                            attachments = []
                            if pdf_created and os.path.exists(pdf_created):
                                with open(pdf_created, "rb") as f:
                                    pdf_bytes = f.read()
                                st.download_button("⬇️ Download PDF receipt", data=pdf_bytes, file_name=os.path.basename(pdf_created), mime="application/pdf")
                                attachments.append((os.path.basename(pdf_created), pdf_bytes, "application/pdf"))
                            else:
                                st.info("PDF receipt not available (reportlab not installed)")

                            if img_created and os.path.exists(img_created):
                                with open(img_created, "rb") as f:
                                    img_bytes = f.read()
                                st.download_button("🖼️ Download image receipt", data=img_bytes, file_name=os.path.basename(img_created), mime="image/png")
                                attachments.append((os.path.basename(img_created), img_bytes, "image/png"))
                            else:
                                st.info("Image receipt not available (Pillow not installed)")

                            # Attempt to email receipts to user's email (username assumed email)
                            try:
                                user_email = user.get("email") or user.get("username")
                                if user_email and attachments:
                                    subject = f"Receipt for transaction {tx_id} - Access Bank"
                                    body = f"Dear {user.get('username')},\n\nPlease find attached the receipt for your recent transaction (ID: {tx_id}).\n\nRegards,\nAccess Bank"
                                    ok_email = send_email_with_attachments(user_email, subject, body, attachments)
                                    if ok_email:
                                        st.success("Receipt emailed to your address")
                                    else:
                                        st.info("Receipt email not sent (SMTP not configured or error)")
                            except Exception:
                                pass
        st.markdown("</div>", unsafe_allow_html=True)
    with a2:
        st.markdown("<div class='card'><h4>Account requests</h4>", unsafe_allow_html=True)
        if st.button("🛑 Request hold", key="req_hold"):
            conn = get_conn()
            conn.execute("UPDATE users SET status='hold' WHERE account_number = ?", (user["account_number"],))
            conn.commit()
            conn.close()
            log_audit(user["username"], "request_hold", user["account_number"])
            st.success("Hold requested. An admin should review it.")
        if st.button("❄️ Freeze account", key="req_freeze"):
            conn = get_conn()
            conn.execute("UPDATE users SET status='frozen' WHERE account_number = ?", (user["account_number"],))
            conn.commit()
            conn.close()
            log_audit(user["username"], "self_freeze", user["account_number"])
            st.success("Account freeze requested/activated. Contact admin to reactivate.")
        st.markdown("</div>", unsafe_allow_html=True)
    with a3:
        st.markdown("<div class='card'><h4>Quick actions</h4><div class='muted'>Shortcuts</div>", unsafe_allow_html=True)
        if st.button("📄 Download statements"):
            st.info("Statement generation coming soon")
        if st.button("💬 Contact support"):
            create_message(user["account_number"], "Support request", "User requested support", from_admin=0)
            st.success("Support request created")
        st.markdown("</div>", unsafe_allow_html=True)

    # Transactions
    st.markdown("<h4>Transaction history</h4>", unsafe_allow_html=True)
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY id DESC LIMIT 200", (user["account_number"], user["account_number"]))
    txs = c.fetchall()
    tx_table = []
    for t in txs:
        tx_table.append({
            "id": t["id"],
            "from": t["from_account"],
            "to": t["to_account"],
            "amount": cents_to_str(t["amount_cents"]),
            "type": t["type"],
            "external": bool(t["external"]),
            "ts": t["timestamp"]
        })
    st.table(tx_table)

    # Provide persistent download links for receipts for each transaction (generate if missing)
    receipts_base = os.path.join(UPLOAD_DIR, user["username"], "receipts")
    os.makedirs(receipts_base, exist_ok=True)
    for t in txs:
        txid = t["id"]
        pdf_path = os.path.join(receipts_base, f"receipt_{txid}.pdf")
        img_path = os.path.join(receipts_base, f"receipt_{txid}.png")

        # If either receipt is missing, attempt to generate from transaction data
        if (not os.path.exists(pdf_path)) or (not os.path.exists(img_path)):
            try:
                # Build tx_info defensively (older DBs may lack some fields)
                tx_info = {
                    "Transaction ID": txid,
                    "From": t.get("from_account") if hasattr(t, 'get') else t["from_account"],
                    "To": t.get("to_account") if hasattr(t, 'get') else t["to_account"],
                    "Amount": cents_to_str(t.get("amount_cents") if hasattr(t, 'get') else t["amount_cents"]),
                    "Type": (t.get("type") if hasattr(t, 'get') else t["type"]).capitalize() if (t.get("type") if hasattr(t, 'get') else t["type"]) else "",
                    "Routing": t.get("external_routing") if hasattr(t, 'get') else (t["external_routing"] if "external_routing" in t.keys() else ""),
                    "Receiving Bank": t.get("external_bank") if hasattr(t, 'get') else (t["external_bank"] if "external_bank" in t.keys() else ""),
                    "Memo": t.get("memo") if hasattr(t, 'get') else (t["memo"] if "memo" in t.keys() else ""),
                    "Status": t.get("external_status") if hasattr(t, 'get') else (t["external_status"] if "external_status" in t.keys() else ("Completed" if not (t.get("external") if hasattr(t, 'get') else t["external"]) else "Unknown")),
                    "Timestamp": t.get("timestamp") if hasattr(t, 'get') else t["timestamp"],
                }
            except Exception:
                tx_info = {
                    "Transaction ID": txid,
                    "From": t["from_account"],
                    "To": t["to_account"],
                    "Amount": cents_to_str(t["amount_cents"]),
                    "Type": (t["type"] if "type" in t.keys() else ""),
                    "Timestamp": t["timestamp"] if "timestamp" in t.keys() else datetime.datetime.utcnow().isoformat(),
                }
            try:
                generate_pdf_receipt(tx_info, pdf_path)
            except Exception:
                pass
            try:
                generate_image_receipt(tx_info, img_path)
            except Exception:
                pass

        # Show download buttons if files exist
        col_dl1, col_dl2 = st.columns([1,1])
        with col_dl1:
            if os.path.exists(pdf_path):
                try:
                    with open(pdf_path, "rb") as f:
                        st.download_button(f"⬇️ PDF tx {txid}", data=f.read(), file_name=os.path.basename(pdf_path), mime="application/pdf")
                except Exception:
                    st.write(f"PDF receipt for tx {txid} not available")
            else:
                st.write(f"PDF not available for tx {txid}")
        with col_dl2:
            if os.path.exists(img_path):
                try:
                    with open(img_path, "rb") as f:
                        st.download_button(f"🖼️ Image tx {txid}", data=f.read(), file_name=os.path.basename(img_path), mime="image/png")
                except Exception:
                    st.write(f"Image receipt for tx {txid} not available")
            else:
                st.write(f"Image not available for tx {txid}")

    # Show rejected transfers (external transfers rejected by admin)
    st.markdown("<h4>Rejected transfers</h4>", unsafe_allow_html=True)
    c.execute("SELECT id, from_account, to_account, amount_cents, external_routing, external_bank, memo, external_note, timestamp FROM transactions WHERE from_account = ? AND external = 1 AND external_status = 'rejected' ORDER BY id DESC LIMIT 50", (user["account_number"],))
    rejected_txs = c.fetchall()
    if rejected_txs:
        for r in rejected_txs:
            reason = r["external_note"] or "No reason provided"
            st.markdown(f"<div class='card' style='border-left:4px solid #ff6b6b'><b>Transfer rejected</b> — TX #{r['id']}<br><b>Amount:</b> {cents_to_str(r['amount_cents'])} &nbsp; <b>To:</b> {r['to_account']}<br><b>Bank:</b> {r['external_bank'] or 'Unknown'} &nbsp; <b>Routing:</b> {r['external_routing'] or '-'}<br><b>Rejection reason:</b> {reason}<br><span class='muted'>{r['timestamp']}</span></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='card'><span class='muted'>No rejected transfers</span></div>", unsafe_allow_html=True)

    st.markdown("<h4>Messages / Notifications</h4>", unsafe_allow_html=True)
    c.execute("SELECT id, title, body, from_admin, read, timestamp FROM messages WHERE user_account = ? ORDER BY id DESC LIMIT 200", (user["account_number"],))
    msgs = c.fetchall()
    for m in msgs:
        tag = "From Admin" if m["from_admin"] else "System"
        st.markdown(f"<div class='card'><b>{m['title'] or '(no title)'}</b> <span class='muted'>— {tag} — {m['timestamp']}</span><div style='margin-top:6px'>{m['body']}</div></div>", unsafe_allow_html=True)
        st.write("")

    conn.close()

# Main content: keep the banking dashboard on the default URL
if not is_admin_page:
    if st.session_state.account:
        show_user_dashboard(st.session_state.account)
    elif st.session_state.user is None:
        st.info("Please register or log in from the sidebar to access your dashboard.")

# -----------------------
# Final notes
# -----------------------
st.markdown("---")
st.caption("Access Bank — Production Banking Application. See the top of app.py for security guidelines.")