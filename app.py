import os
from flask import Flask, request, jsonify
import sqlite3
import uuid
from datetime import datetime, timedelta
import stripe
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# --- Paths / DB ---
DB_PATH = 'licenses.db'
print("📁 Using DB at:", os.path.abspath(DB_PATH))

# --- Live secrets from environment ---
STRIPE_SECRET_KEY     = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUBLISHABLE    = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
SERVER_SECRET         = os.environ.get('SERVER_SECRET', '')
MASTER_KEY            = os.environ.get('MASTER_KEY', 'spectre-master-7788')
APP_BASE_URL          = os.environ.get('APP_BASE_URL', 'https://spectrespoofer.com')

# Fail fast if not live key
if not STRIPE_SECRET_KEY.startswith('sk_live_'):
    print("❌ STRIPE_SECRET_KEY is missing or not a LIVE key.")
stripe.api_key = STRIPE_SECRET_KEY

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])


# ----------------- DB bootstrap -----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            credits INTEGER DEFAULT 5000,
            tier TEXT DEFAULT 'lite',
            issued_to TEXT,
            created_at TEXT,
            expires_at TEXT,
            hwid TEXT,
            usage_count INTEGER DEFAULT 0,
            last_reset TEXT
        )
    ''')
    conn.commit()
    conn.close()

def require_server_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("Authorization")
        if not SERVER_SECRET or provided != SERVER_SECRET:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def key_exists(key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM licenses WHERE key = ?', (key,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def reset_usage_if_needed(key, conn=None):
    own_conn = False
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        own_conn = True

    cursor = conn.cursor()
    cursor.execute('SELECT tier, usage_count, last_reset FROM licenses WHERE key = ?', (key,))
    row = cursor.fetchone()
    if not row:
        if own_conn:
            conn.close()
        return

    tier, usage_count, last_reset = row
    now = datetime.utcnow()

    should_reset = False
    if last_reset:
        last_reset_date = datetime.fromisoformat(last_reset)
        if tier in ['lite', 'premium'] and (now - last_reset_date).days >= 30:
            should_reset = True
        elif tier == 'trial' and (now - last_reset_date).days >= 1:
            should_reset = True
    else:
        should_reset = True

    if should_reset:
        cursor.execute('UPDATE licenses SET usage_count = 0, last_reset = ? WHERE key = ?', (now.isoformat(), key))
        conn.commit()

    if own_conn:
        conn.close()


# ----------------- Routes -----------------
@app.route('/')
def index():
    return jsonify({"status": "Spectre License API running."})


@app.route('/verify', methods=['POST'])
def verify_key():
    data = request.json or {}
    telegram_id = data.get('telegram_id', '').strip()
    user_key = data.get('key', '').strip()
    hwid = str(data.get('hwid')).strip() if data.get('hwid') else None

    print("🚨 /verify POST received")
    print("➡️ Key:", user_key)
    print("➡️ HWID:", hwid)
    print("➡️ Telegram ID:", telegram_id)

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not hwid:
        return jsonify({'valid': False, 'reason': 'Missing HWID'}), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Step 1: Direct license key
    cursor.execute('SELECT tier, credits, expires_at, hwid, issued_to FROM licenses WHERE key = ?', (user_key,))
    result = cursor.fetchone()

    if result:
        tier, credits, expires_at, stored_hwid, issued_to = result
        stored_hwid = stored_hwid or None

        if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
            print("❌ Rejected: License expired")
            conn.close()
            return jsonify({'valid': False, 'reason': 'License expired'}), 403

        # Telegram binding for trial/fam
        if tier in ['trial', 'fam']:
            if not issued_to or issued_to.endswith('@gmail.com'):
                cursor.execute('UPDATE licenses SET issued_to = ? WHERE key = ?', (telegram_id, user_key))
                conn.commit()
                issued_to = telegram_id
            elif issued_to != telegram_id:
                print("❌ Rejected: Telegram ID mismatch (expected:", issued_to, ")")
                conn.close()
                return jsonify({'valid': False, 'reason': 'Key bound to a different Telegram user'}), 403

        # HWID binding/mismatch checks (except master)
        if not stored_hwid and tier != 'master':
            cursor.execute('UPDATE licenses SET hwid = ? WHERE key = ?', (hwid, user_key))
            conn.commit()
            stored_hwid = hwid

        if stored_hwid and hwid != stored_hwid and tier != 'master':
            print(f"❌ Rejected: HWID mismatch (stored: {stored_hwid}, sent: {hwid})")
            conn.close()
            return jsonify({'valid': False, 'reason': 'HWID mismatch'}), 403

        conn.close()
        return jsonify({'valid': True, 'tier': tier, 'credits': credits})

    # Step 2: VA key path
    cursor.execute('SELECT parent_key FROM va_keys WHERE va_key = ?', (user_key,))
    va_row = cursor.fetchone()
    if va_row:
        parent_key = va_row[0]
        cursor.execute('SELECT tier, credits, expires_at FROM licenses WHERE key = ?', (parent_key,))
        parent_result = cursor.fetchone()

        if parent_result:
            tier, credits, expires_at = parent_result
            if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
                conn.close()
                return jsonify({'valid': False, 'reason': 'Parent license expired'}), 403

            conn.close()
            return jsonify({'valid': True, 'tier': f'VA-{tier}', 'credits': credits})

    # Step 3: Trial abuse detection
    cursor.execute(
        "SELECT 1 FROM licenses WHERE tier='trial' AND (hwid=? OR issued_to=? OR ? IN (SELECT issued_to FROM licenses))",
        (hwid, hwid, ip)
    )
    if cursor.fetchone():
        conn.close()
        return jsonify({'valid': False, 'reason': 'Trial already used on this machine or IP'}), 403

    conn.close()
    return jsonify({'valid': False, 'reason': 'Key not found'}), 403


@app.route('/generate_key', methods=['GET', 'POST'])
@require_server_auth
@limiter.limit("5 per minute")
def generate_key():
    data = request.get_json(force=True)
    tier = (data.get('tier') or '').lower()
    credits = data.get('credits')
    issued_to = data.get('issued_to')

    if not tier or credits is None or not issued_to:
        return jsonify({'error': 'Missing tier, credits, or issued_to'}), 400

    new_key = str(uuid.uuid4()).replace('-', '') + str(uuid.uuid4()).split('-')[0]
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO licenses (key, tier, credits, issued_to, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (new_key, tier, int(credits), issued_to, created_at, expires_at))
    conn.commit()
    conn.close()

    return jsonify({'generated_key': new_key})


@app.route('/edit_key', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def edit_key():
    data = request.get_json() or {}
    key = data.get('key')
    new_tier = data.get('tier')
    new_credits = data.get('credits')
    new_issued_to = data.get('issued_to')
    new_expires_at = data.get('expires_at')

    if not key:
        return jsonify({"error": "Missing 'key' field"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    updates, params = [], []

    if new_tier:
        updates.append("tier = ?")
        params.append(new_tier)
    if new_credits is not None:
        updates.append("credits = ?")
        params.append(new_credits)
    if new_issued_to:
        updates.append("issued_to = ?")
        params.append(new_issued_to)
    if new_expires_at:
        updates.append("expires_at = ?")
        params.append(new_expires_at)

    if not updates:
        conn.close()
        return jsonify({"error": "No fields to update"}), 400

    params.append(key)
    query = f"UPDATE licenses SET {', '.join(updates)} WHERE key = ?"
    cursor.execute(query, params)
    conn.commit()
    conn.close()

    return jsonify({"message": "Key updated successfully"})


@app.route('/view_keys', methods=['GET'])
@require_server_auth
@limiter.limit("5 per minute")
def view_keys():
    tier_filter = request.args.get('tier')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if tier_filter:
        cursor.execute('SELECT key, tier, credits, issued_to, created_at, expires_at FROM licenses WHERE tier = ?', (tier_filter,))
        rows = cursor.fetchall()
        keys = [{
            'key': row[0], 'tier': row[1], 'credits': row[2],
            'issued_to': row[3], 'created_at': row[4], 'expires_at': row[5]
        } for row in rows]
    else:
        cursor.execute('SELECT key, tier, credits, issued_to, created_at, expires_at, hwid FROM licenses')
        rows = cursor.fetchall()
        keys = [{
            'key': row[0], 'tier': row[1], 'credits': row[2], 'issued_to': row[3],
            'created_at': row[4], 'expires_at': row[5], 'hwid': row[6]
        } for row in rows]

    conn.close()
    return jsonify({'keys': keys})


@app.route('/delete_key', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def delete_key():
    data = request.get_json() or {}
    license_key = data.get('key')
    if not license_key:
        return jsonify({'error': 'Missing license key'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM licenses WHERE key = ?', (license_key,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Key deleted successfully'})


@app.route('/extend_key', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def extend_key():
    data = request.get_json() or {}
    key = data.get('key')
    new_tier = data.get('new_tier')
    additional_credits = data.get('additional_credits', 0)

    if not key or not new_tier:
        return jsonify({"error": "Missing 'key' or 'new_tier'"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT tier, credits FROM licenses WHERE key = ?', (key,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "Key not found"}), 404

    current_credits = result[1]
    updated_credits = current_credits + int(additional_credits)
    new_expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()

    cursor.execute('''
        UPDATE licenses
        SET tier = ?, credits = ?, expires_at = ?
        WHERE key = ?
    ''', (new_tier, updated_credits, new_expiry, key))
    conn.commit()
    conn.close()

    return jsonify({"message": "Key extended successfully"})


@app.route('/check_expired_keys', methods=['GET'])
def check_expired_keys():
    now = datetime.utcnow()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT key, tier, credits, issued_to, created_at, expires_at
        FROM licenses
        WHERE expires_at IS NOT NULL
    ''')
    rows = cursor.fetchall()
    conn.close()

    expired = []
    for row in rows:
        try:
            exp_date = datetime.fromisoformat(row[5])
            if exp_date < now:
                expired.append({
                    'key': row[0], 'tier': row[1], 'credits': row[2],
                    'issued_to': row[3], 'created_at': row[4], 'expires_at': row[5]
                })
        except Exception:
            continue

    return jsonify({'expired_keys': expired})


@app.route('/key_stats', methods=['POST'])
def key_stats():
    data = request.get_json() or {}
    key = data.get('key')
    if not key:
        return jsonify({'error': 'Missing key'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key, tier, credits, issued_to, created_at, expires_at FROM licenses WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Key not found'}), 404

    created = datetime.fromisoformat(row[4])
    days_active = (datetime.utcnow() - created).days

    return jsonify({
        'key': row[0], 'tier': row[1], 'credits': row[2], 'issued_to': row[3],
        'created_at': row[4], 'expires_at': row[5], 'days_since_created': days_active
    })


@app.route('/reset_hwid', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def reset_hwid():
    data = request.get_json() or {}
    key = data.get('key')
    admin_password = data.get('admin_password')

    if not key or not admin_password:
        return jsonify({'error': 'Missing key or admin password'}), 400

    if admin_password != MASTER_KEY:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM licenses WHERE key = ?', (key,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Key not found'}), 404

    cursor.execute('UPDATE licenses SET hwid = NULL WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'HWID reset successfully'})


@app.route('/consume_credits', methods=['POST'])
def consume_credits():
    data = request.get_json() or {}
    key = data.get('key')
    amount = data.get('amount', 1)

    if not key:
        return jsonify({'error': 'Missing key'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT credits FROM licenses WHERE key = ?', (key,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({'error': 'Key not found'}), 404

    current_credits = result[0]
    if current_credits < amount:
        conn.close()
        return jsonify({'error': 'Insufficient credits'}), 403

    updated_credits = current_credits - amount
    cursor.execute('UPDATE licenses SET credits = ? WHERE key = ?', (updated_credits, key))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Credits consumed', 'remaining_credits': updated_credits})


@app.route('/spoof', methods=['POST'])
def spoof():
    data = request.get_json() or {}
    key = data.get('key')
    hwid = data.get('hwid')

    if not key or not hwid:
        return jsonify({'error': 'Missing key or HWID'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VA key?
    cursor.execute('SELECT parent_key FROM va_keys WHERE va_key = ?', (key,))
    va_row = cursor.fetchone()

    if va_row:
        parent_key = va_row[0]
        cursor.execute('SELECT tier, usage_count, expires_at FROM licenses WHERE key = ?', (parent_key,))
        parent_result = cursor.fetchone()

        if not parent_result:
            conn.close()
            return jsonify({'error': 'Parent license not found'}), 404

        tier, usage_count, expires_at = parent_result

        if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
            conn.close()
            return jsonify({'error': 'Parent license expired'}), 403

        limits = {'trial': 5, 'lite': 5000, 'premium': 25000, 'custom': float('inf'), 'master': float('inf')}
        limit = limits.get(tier, 0)

        if usage_count >= limit:
            conn.close()
            return jsonify({'error': f'{tier.capitalize()} usage limit reached'}), 403

        cursor.execute('UPDATE licenses SET usage_count = usage_count + 1 WHERE key = ?', (parent_key,))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'tier': f'VA-{tier}', 'remaining_spoofs': int(limit - usage_count - 1)})

    # Regular license
    reset_usage_if_needed(key, conn)
    cursor.execute('SELECT tier, usage_count, hwid, expires_at FROM licenses WHERE key = ?', (key,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Key not found'}), 404

    tier, usage_count, stored_hwid, expires_at = row

    if tier == 'master':
        conn.close()
        return jsonify({'success': True, 'tier': 'master', 'remaining_spoofs': '∞'})

    if stored_hwid and stored_hwid != hwid:
        conn.close()
        return jsonify({'error': 'HWID mismatch'}), 403

    if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
        conn.close()
        return jsonify({'error': 'License expired'}), 403

    limits = {'trial': 5, 'lite': 5000, 'premium': 25000, 'custom': float('inf'), 'master': float('inf')}
    limit = limits.get(tier, 0)

    if usage_count >= limit:
        conn.close()
        return jsonify({'error': f'{tier.capitalize()} usage limit reached'}), 403

    if not stored_hwid:
        cursor.execute('UPDATE licenses SET hwid = ? WHERE key = ?', (hwid, key))

    cursor.execute('UPDATE licenses SET usage_count = usage_count + 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'tier': tier, 'remaining_spoofs': int(limit - usage_count - 1)})


@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature', '')
    endpoint_secret = STRIPE_WEBHOOK_SECRET

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError as e:
        print("❌ Invalid payload:", e)
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        print("❌ Signature verification failed:", e)
        return 'Invalid signature', 400

    print(f"✅ Webhook received: {event['type']}")

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')
        telegram_username = session.get('metadata', {}).get('telegram')
        customer_email = session.get('customer_email') or session.get('customer_details', {}).get('email')
        plan = session.get('metadata', {}).get('plan', 'lite')

        issued_to = telegram_username or customer_email
        print(f"📧 Email: {customer_email}")
        print(f"📦 Plan: {plan}")
        print(f"✅ Issuing license to: {issued_to}")
        generate_license_for_user(issued_to, plan, email=customer_email)

    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        new_price_id = subscription['items']['data'][0]['price']['id']
        customer_id = subscription['customer']

        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer.get('email')
        if not customer_email:
            print("❌ Cannot update license – email not found.")
            return '', 400

        if "premium" in new_price_id:
            new_tier = "premium"; new_credits = 25000
        elif "lite" in new_price_id:
            new_tier = "lite"; new_credits = 5000
        else:
            new_tier = "custom"; new_credits = 999999

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE licenses SET tier = ?, credits = ? WHERE issued_to = ?', (new_tier, new_credits, customer_email))
        conn.commit()
        conn.close()

        print(f"🔁 Updated {customer_email} to {new_tier}")

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')
        current_period_end = subscription.get('current_period_end')

        try:
            customer = stripe.Customer.retrieve(customer_id)
            customer_email = customer.get('email')
        except Exception as e:
            print("⚠️ Could not retrieve customer email on cancel:", e)
            return 'Error retrieving customer', 500

        if not customer_email:
            print("❌ No email found for subscription cancel.")
            return 'Missing email', 400

        new_expiry = datetime.utcfromtimestamp(current_period_end).isoformat()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE licenses SET tier = ?, credits = ?, expires_at = ?
            WHERE issued_to = ?
        ''', ('trial', 5, new_expiry, customer_email))
        conn.commit()
        conn.close()

        print(f"📉 Downgraded {customer_email} to trial (expires {new_expiry})")

    return '', 200


def generate_license_for_user(issued_to, plan, email=None):
    print(f"🧪 Generating license for {issued_to} with plan: {plan}")
    new_key = str(uuid.uuid4()).replace('-', '')
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()

    if plan.lower() == 'lite':
        credits = 5000; tier = 'lite'
    elif plan.lower() == 'premium':
        credits = 25000; tier = 'premium'
    else:
        credits = 999999; tier = 'custom'

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO licenses (key, tier, credits, issued_to, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (new_key, tier, credits, issued_to, created_at, expires_at))
    conn.commit()
    conn.close()

    # Send email (optional: move SMTP creds to env)
    send_email(
        to_email=(email or issued_to),
        subject="🎟️ Your Spectre Spoofer License",
        body=f"""Thanks for your purchase!

🔑 License Key: {new_key}
📦 Plan: {tier.capitalize()}
📅 Expires: {expires_at}

To install and activate:
1) Download: https://spectrespoofer.com/download
2) Enter the license key when prompted.

— Team Spectre
"""
    )


def cancel_user_license(email):
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE licenses SET expires_at = ? WHERE issued_to = ?', (expires_at, email))
    conn.commit()
    conn.close()


@app.route('/buy/<plan>', methods=['GET'])
def buy(plan):
    """
    Live one-time checkout using product IDs you created in Stripe (LIVE).
    Adjust unit_amounts as needed.
    """
    plan = plan.lower()
    if plan not in ['lite', 'premium']:
        return jsonify({'error': 'Invalid plan'}), 400

    tg_username = request.args.get("tg", "").strip()
    if not tg_username:
        return jsonify({'error': 'Missing Telegram username. Use ?tg=your_username'}), 400

    # Map plan -> product id + amount (USD cents)
    if plan == 'lite':
        product_id = 'prod_SWu7ab0IXlIwGK'
        unit_amount = 3000
    else:
        product_id = 'prod_SWu8FgZZV11Hmm'
        unit_amount = 10000

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': unit_amount,
                    'product': product_id
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f"{APP_BASE_URL}/success",
            cancel_url=f"{APP_BASE_URL}/cancel",
            metadata={'plan': plan, 'telegram': tg_username}
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/billing_portal', methods=['GET'])
def billing_portal():
    """
    Live billing portal – finds/creates the customer by email.
    """
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "Missing ?email="}), 400

    try:
        customers = stripe.Customer.list(email=email, limit=1).data
        if customers:
            customer_id = customers[0].id
        else:
            customer = stripe.Customer.create(email=email, metadata={"source": "spectre-spoofer"})
            customer_id = customer.id

        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{APP_BASE_URL}"
        )
        return jsonify({'portal_url': session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/va_keys', methods=['GET'])
@require_server_auth
def view_va_keys():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT parent_key, va_key, created_at FROM va_keys')
    rows = cursor.fetchall()
    conn.close()

    return jsonify({'va_keys': [
        {'parent_key': r[0], 'va_key': r[1], 'created_at': r[2]} for r in rows
    ]})


@app.route('/send_email', methods=['POST'])
def send_email_route():
    data = request.get_json() or {}
    to_email = data.get("to")
    subject = data.get("subject", "Test Email")
    body = data.get("body", "This is a test email from Spectre Spoofer.")

    if not to_email:
        return jsonify({"error": "Missing 'to' field"}), 400

    send_email(to_email, subject, body)
    return jsonify({"message": f"Email sent to {to_email}"}), 200


@app.route('/generate_va_key', methods=['POST'])
@require_server_auth
@limiter.limit("10 per minute")
def generate_va_key():
    data = request.get_json() or {}
    parent_key = data.get('parent_key')
    if not parent_key:
        return jsonify({'error': 'Missing parent_key'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT tier FROM licenses WHERE key = ?', (parent_key,))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Parent key not found'}), 404

    tier = (result[0] or '').lower().strip()
    cursor.execute('SELECT COUNT(*) FROM va_keys WHERE parent_key = ?', (parent_key,))
    count = cursor.fetchone()[0]

    if tier == 'premium' and count >= 2:
        conn.close()
        return jsonify({'error': 'Premium keys are limited to 2 VA keys'}), 403
    elif tier not in ['premium', 'custom']:
        conn.close()
        return jsonify({'error': 'Only premium or custom tiers can generate VA keys'}), 403

    va_key = str(uuid.uuid4()).replace('-', '')
    created_at = datetime.utcnow().isoformat()

    cursor.execute('''
        INSERT INTO va_keys (parent_key, va_key, created_at)
        VALUES (?, ?, ?)
    ''', (parent_key, va_key, created_at))

    conn.commit()
    conn.close()
    return jsonify({'va_key': va_key})


@app.route('/generate_fam_key', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def generate_fam_key():
    data = request.get_json(force=True)
    issued_to = data.get('issued_to')
    if not issued_to:
        return jsonify({'error': 'Missing issued_to'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM licenses WHERE tier = ? AND issued_to = ?', ('fam', issued_to))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User already has a fam key'}), 403

    new_key = str(uuid.uuid4()).replace('-', '')
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(days=9999)).isoformat()

    cursor.execute('''
        INSERT INTO licenses (key, tier, credits, issued_to, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (new_key, 'fam', 99999999, issued_to, created_at, expires_at))

    conn.commit()
    conn.close()
    return jsonify({'generated_key': new_key})


def send_email(to_email, subject, body):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_server = "smtppro.zoho.com"
    smtp_port = 465
    from_email = "team@spectrespoofer.com"
    app_password = os.environ.get("SMTP_APP_PASSWORD")
    if not app_password:
        print("❌ SMTP_APP_PASSWORD missing; cannot send email.")
        return

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(from_email, app_password)
            server.sendmail(from_email, to_email, msg.as_string())
            print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {to_email}: {e}")


def init_va_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS va_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_key TEXT NOT NULL,
            va_key TEXT NOT NULL UNIQUE,
            created_at TEXT,
            FOREIGN KEY(parent_key) REFERENCES licenses(key)
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/admin_delete_key', methods=['POST'])
def admin_delete_key():
    auth = request.headers.get("Authorization")
    if auth != SERVER_SECRET:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json() or {}
    key_to_delete = data.get("key")
    if not key_to_delete:
        return jsonify({"error": "No key provided"}), 400

    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key = ?", (key_to_delete,))
    conn.commit()
    conn.close()

    return jsonify({"status": "deleted", "key": key_to_delete})


if __name__ == '__main__':
    init_db()
    init_va_db()
    port = int(os.environ.get('PORT', 5000))
    # Do NOT enable debug in production
    app.run(host='0.0.0.0', port=port, debug=False)
