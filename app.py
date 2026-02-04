from flask import Flask, request, jsonify
import stripe
import os
import json
import time

app = Flask(__name__)

# ---------- CONFIG ----------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")  # para tus apps

DATA_FILE = "memberships.json"

stripe.api_key = STRIPE_SECRET_KEY


# ---------- HELPERS ----------
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def now():
    return int(time.time())


def require_internal_key(req):
    auth = req.headers.get("Authorization", "")
    return auth == f"Bearer {INTERNAL_API_KEY}"


# ---------- STRIPE WEBHOOK ----------
@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        print("❌ Webhook error:", e)
        return "Invalid", 400

    etype = event["type"]
    obj = event["data"]["object"]

    data = load_data()

    def upsert(username, payload):
        data[username.lower()] = payload
        save_data(data)

    # --- CHECKOUT COMPLETED ---
    if etype == "checkout.session.completed":
        meta = obj.get("metadata", {})
        username = meta.get("username")
        if not username:
            return jsonify(ok=True)

        sub_id = obj.get("subscription")
        sub = stripe.Subscription.retrieve(sub_id)

        upsert(username, {
            "status": sub["status"],
            "subscription_id": sub_id,
            "customer_id": obj.get("customer"),
            "current_period_end": sub["current_period_end"],
            "updated_at": now()
        })

    # --- SUBSCRIPTION UPDATED ---
    elif etype == "customer.subscription.updated":
        meta = obj.get("metadata", {})
        username = meta.get("username")
        if not username:
            return jsonify(ok=True)

        upsert(username, {
            "status": obj["status"],
            "subscription_id": obj["id"],
            "customer_id": obj["customer"],
            "current_period_end": obj["current_period_end"],
            "updated_at": now()
        })

    # --- SUBSCRIPTION DELETED ---
    elif etype == "customer.subscription.deleted":
        meta = obj.get("metadata", {})
        username = meta.get("username")
        if not username:
            return jsonify(ok=True)

        upsert(username, {
            "status": "canceled",
            "subscription_id": obj["id"],
            "customer_id": obj["customer"],
            "current_period_end": 0,
            "updated_at": now()
        })

    return jsonify(ok=True)


# ---------- CONSULTA DE MEMBRESÍA ----------
@app.route("/membership/status")
def membership_status():
    if not require_internal_key(request):
        return jsonify(error="unauthorized"), 401

    username = request.args.get("username", "").lower().strip()
    if not username:
        return jsonify(error="missing username"), 400

    data = load_data()
    m = data.get(username)

    if not m:
        return jsonify(active=False, reason="not_found")

    status = m["status"]
    period_end = m.get("current_period_end", 0)

    active = False
    if status in ("active", "trialing"):
        active = True
    elif status == "canceled" and period_end > now():
        active = True

    return jsonify(
        active=active,
        status=status,
        current_period_end=period_end
    )


@app.route("/")
def health():
    return "Billing service running"
