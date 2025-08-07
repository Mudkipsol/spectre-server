import os
from flask import Flask, request, jsonify
import sqlite3
import uuid
from datetime import datetime, timedelta
import stripe
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
DB_PATH = 'licenses.db'  # Define this first
print("📁 Using DB at:", os.path.abspath(DB_PATH))  # Now you can print it
stripe.api_key = 'sk_test_51RUAN1L88MM2LpTSb6XS2g4JlYUAvjz50knRbDJMIlmPywpoXTAICnDBUyXRpaSv7GnSxfRnwSd8v91L1ShI8ZFo00KIVcoajr'

app = Flask(__name__)

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
SERVER_SECRET = "RichOffSoftware22!"  # change this to your real server password

DB_PATH = 'licenses.db'
MASTER_KEY = 'spectre-master-7788'

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
        auth = request.headers.get("Authorization")
        if auth != SERVER_SECRET:
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

@app.route('/')
def index():
    return jsonify({"status": "Spectre License API running."})

@app.route('/verify', methods=['POST'])
def verify_key():
    data = request.json
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

    # Step 1: Check if it’s a direct license key
    cursor.execute('SELECT tier, credits, expires_at, hwid, issued_to FROM licenses WHERE key = ?', (user_key,))
    result = cursor.fetchone()

    if result:
        tier, credits, expires_at, stored_hwid, issued_to = result
        stored_hwid = stored_hwid or None

        # Step 1.1: Check expiration
        if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
            print("❌ Rejected: License expired")
            conn.close()
            return jsonify({'valid': False, 'reason': 'License expired'}), 403
        
        # Step 1.1.5: Telegram binding (only for trial and fam)
        if tier in ['trial', 'fam']:
            if not issued_to:
                cursor.execute('UPDATE licenses SET issued_to = ? WHERE key = ?', (telegram_id, user_key))
                conn.commit()
                issued_to = telegram_id
            elif issued_to != telegram_id and tier in ['trial', 'fam']:
                print("❌ Rejected: Telegram ID mismatch")
                conn.close()
                return jsonify({'valid': False, 'reason': 'Key bound to a different Telegram user'}), 403
    
        # Step 1.2: HWID binding (allowed for all tiers except master if not yet set)
        if not stored_hwid and tier != 'master':
            cursor.execute('UPDATE licenses SET hwid = ? WHERE key = ?', (hwid, user_key))
            conn.commit()
            stored_hwid = hwid  # Continue to next step with bound HWID

        # Step 1.3: HWID mismatch (skip if master)
        if stored_hwid and hwid != stored_hwid and tier != 'master':
            print(f"❌ Rejected: HWID mismatch (stored: {stored_hwid}, sent: {hwid})")
            conn.close()
            return jsonify({'valid': False, 'reason': 'HWID mismatch'}), 403

        # Step 1.4: All good
        conn.close()
        return jsonify({'valid': True, 'tier': tier, 'credits': credits})
    
        # Final fallback — key not found or failed all conditions
        print("❌ Rejected: Final fallback (key not accepted by any condition)")
        conn.close()
        return jsonify({'valid': False, 'reason': 'Key not found'}), 403

    # Step 2: Check if it's a VA key
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

    # Final fallback
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

    if not tier or not credits or not issued_to:
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
    data = request.get_json()
    key = data.get('key')
    new_tier = data.get('tier')
    new_credits = data.get('credits')
    new_issued_to = data.get('issued_to')
    new_expires_at = data.get('expires_at')

    if not key:
        return jsonify({"error": "Missing 'key' field"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    updates = []
    params = []

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
    else:
        cursor.execute('SELECT key, tier, credits, issued_to, created_at, expires_at, hwid FROM licenses')

    rows = cursor.fetchall()
    conn.close()

    keys = [{
        'key': row[0],
        'tier': row[1],
        'credits': row[2],
        'issued_to': row[3],
        'created_at': row[4],
        'expires_at': row[5],
        'hwid': row[6]
    } for row in rows]

    return jsonify({'keys': keys})

@app.route('/delete_key', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def delete_key():
    data = request.get_json()
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
    data = request.get_json()
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
                    'key': row[0],
                    'tier': row[1],
                    'credits': row[2],
                    'issued_to': row[3],
                    'created_at': row[4],
                    'expires_at': row[5]
                })
        except Exception:
            continue

    return jsonify({'expired_keys': expired})

@app.route('/key_stats', methods=['POST'])
def key_stats():
    data = request.get_json()
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
        'key': row[0],
        'tier': row[1],
        'credits': row[2],
        'issued_to': row[3],
        'created_at': row[4],
        'expires_at': row[5],
        'days_since_created': days_active
    })

@app.route('/reset_hwid', methods=['POST'])
@require_server_auth
@limiter.limit("5 per minute")
def reset_hwid():
    data = request.get_json()
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
    data = request.get_json()
    key = data.get('key')
    amount = data.get('amount', 1)  # default to 1 credit per use

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
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')

    if not key or not hwid:
        return jsonify({'error': 'Missing key or HWID'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Step 1: Check if it's a VA key
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

        # Tier usage limits
        limits = {
            'trial': 5,
            'lite': 5000,
            'premium': 25000,
            'custom': float('inf'),
            'master': float('inf')
        }
        limit = limits.get(tier, 0)

        if usage_count >= limit:
            conn.close()
            return jsonify({'error': f'{tier.capitalize()} usage limit reached'}), 403

        # Increment usage on parent license
        cursor.execute('UPDATE licenses SET usage_count = usage_count + 1 WHERE key = ?', (parent_key,))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'tier': f'VA-{tier}',
            'remaining_spoofs': int(limit - usage_count - 1)
        })

    # Step 2: Not a VA key — regular license path
    reset_usage_if_needed(key, conn)
    cursor.execute('SELECT tier, usage_count, hwid, expires_at FROM licenses WHERE key = ?', (key,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Key not found'}), 404

    tier, usage_count, stored_hwid, expires_at = row

    # 🔓 Master key: skip all restrictions
    if tier == 'master':
        conn.close()
        return jsonify({
            'success': True,
            'tier': 'master',
            'remaining_spoofs': '∞'
        })

    # HWID check
    if stored_hwid and stored_hwid != hwid:
        conn.close()
        return jsonify({'error': 'HWID mismatch'}), 403

    if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
        conn.close()
        return jsonify({'error': 'License expired'}), 403

    # Tier usage limits
    limits = {
        'trial': 5,
        'lite': 5000,
        'premium': 25000,
        'custom': float('inf'),
        'master': float('inf')  # still required for completeness
    }
    limit = limits.get(tier, 0)

    if usage_count >= limit:
        conn.close()
        return jsonify({'error': f'{tier.capitalize()} usage limit reached'}), 403

    # Bind HWID on first spoof
    if not stored_hwid:
        cursor.execute('UPDATE licenses SET hwid = ? WHERE key = ?', (hwid, key))

    # Increment usage
    cursor.execute('UPDATE licenses SET usage_count = usage_count + 1 WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'tier': tier,
        'remaining_spoofs': int(limit - usage_count - 1)
    })

@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    import json
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature', '')
    endpoint_secret = 'whsec_0c7daf7d2686db1e3f7eafdcb0653475747f145f76a44a3365e9da3387a7f5e4'

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

        # Fetch customer email
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer.get('email')

        if not customer_email:
            print("❌ Cannot update license – email not found.")
            return '', 400

        # Determine new plan
        if "premium" in new_price_id:
            new_tier = "premium"
            new_credits = 25000
        elif "lite" in new_price_id:
            new_tier = "lite"
            new_credits = 5000
        else:
            new_tier = "custom"
            new_credits = 999999

        # Update in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE licenses SET tier = ?, credits = ? WHERE issued_to = ?', (new_tier, new_credits, customer_email))
        conn.commit()
        conn.close()

        print(f"🔁 Updated {customer_email} to {new_tier}")

    elif event['type'] == 'customer.subscription.deleted':  # ← this line needs to be indented
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

    # Plan logic (safe)
    if plan.lower() == 'lite':
        credits = 5000
        tier = 'lite'
    elif plan.lower() == 'premium':
        credits = 25000
        tier = 'premium'
    else:
        credits = 999999
        tier = 'custom'

    # ✅ Insert into database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO licenses (key, tier, credits, issued_to, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (new_key, tier, credits, issued_to, created_at, expires_at))
    conn.commit()
    conn.close()

    # ✅ Send email
    target_email = email or issued_to
    send_email(
        to_email=target_email,
        subject="🎟️ Your Spectre Spoofer License",
        body=f"""
Thanks for your purchase!

🔑 License Key: {new_key}
📦 Plan: {tier.capitalize()}
📅 Expires: {expires_at}

To install and activate:
1. Download the Installer: https://spectrespoofer.com/download
2. Enter the license key when prompted.
3. Enjoy!

Questions? Contact us anytime.
– Team Spectre
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
    if plan not in ['lite', 'premium']:
        return jsonify({'error': 'Invalid plan'}), 400

    tg_username = request.args.get("tg", "").strip()
    if not tg_username:
        return jsonify({'error': 'Missing Telegram username. Use ?tg=your_username'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': 3000 if plan == 'lite' else 10000,
                    'product_data': {
                        'name': f'{plan.capitalize()} License'
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f"https://spectrespoofer.com/success",  # optional: update later
            cancel_url='https://spectrespoofer.com/cancel',
            metadata={
                'plan': plan,
                'telegram': tg_username  # ✅ Binds to Telegram username instead of email
            }
        )
        return jsonify({'checkout_url': checkout_session.url})
    except Exception as e:
        return jsonify(error=str(e)), 500
    
@app.route('/billing_portal', methods=['GET'])
def billing_portal():
    # In production, replace this with the real customer ID from your DB
    test_customer_id = "cus_SmxLn1uCKzJxQx"  # ⚠️ Replace with actual customer ID in production

    try:
        session = stripe.billing_portal.Session.create(
            customer=test_customer_id,
            return_url="http://127.0.0.1:5000/license?email=test@example.com"
        )
        return jsonify({'portal_url': session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/license', methods=['GET'])
def license_lookup():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Missing email'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key, tier, credits, expires_at FROM licenses WHERE issued_to = ?', (email,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'No license found'}), 404

    return jsonify({
        'license_key': result[0],
        'tier': result[1],
        'credits': result[2],
        'expires_at': result[3]
    })

@app.route('/va_keys', methods=['GET'])
@require_server_auth
def view_va_keys():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT parent_key, va_key, created_at FROM va_keys')
    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        'va_keys': [{
            'parent_key': r[0],
            'va_key': r[1],
            'created_at': r[2]
        } for r in rows]
    })

@app.route('/send_email', methods=['POST'])
def send_email_route():
    data = request.get_json()
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
    data = request.get_json()
    parent_key = data.get('parent_key')

    if not parent_key:
        return jsonify({'error': 'Missing parent_key'}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get tier
    cursor.execute('SELECT tier FROM licenses WHERE key = ?', (parent_key,))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Parent key not found'}), 404

    tier = result[0].lower().strip()
    print(f"DEBUG: parent_key = {parent_key}, tier = {tier}")

    # VA limits
    cursor.execute('SELECT COUNT(*) FROM va_keys WHERE parent_key = ?', (parent_key,))
    count = cursor.fetchone()[0]

    if tier == 'premium' and count >= 2:
        conn.close()
        return jsonify({'error': 'Premium keys are limited to 2 VA keys'}), 403
    elif tier not in ['premium', 'custom']:
        conn.close()
        return jsonify({'error': 'Only premium or custom tiers can generate VA keys'}), 403

    # Generate VA key
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
    app_password = "1T4HMU4SmyRX"

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

if __name__ == '__main__':
    init_db()
    init_va_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
