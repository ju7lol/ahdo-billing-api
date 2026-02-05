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

if not STRIPE_SECRET_KEY:
    print("❌ Missing STRIPE_SECRET_KEY")
if not STRIPE_WEBHOOK_SECRET:
    print("❌ Missing STRIPE_WEBHOOK_SECRET")
if not INTERNAL_API_KEY:
    print("❌ Missing INTERNAL_API_KEY")


# ---------- HELPERS ----------
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def now():
    return int(time.time())


def require_internal_key(req):
    auth = req.headers.get("Authorization", "")
    if not INTERNAL_API_KEY:
        raise RuntimeError("Missing INTERNAL_API_KEY")
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

    def upsert(user_id, payload):
        data[str(user_id)] = payload
        save_data(data)


    # --- CHECKOUT COMPLETED ---
    if etype == "checkout.session.completed":
        meta = obj.get("metadata", {})
        user_id = meta.get("user_id")
        if not user_id:
            return jsonify(ok=True)

        sub_id = obj.get("subscription")
        sub = stripe.Subscription.retrieve(sub_id)

        customer_id = obj.get("customer")
        if customer_id:
            stripe.Customer.modify(customer_id, metadata={"user_id": str(user_id)})


        upsert(user_id, {
            "status": sub["status"],
            "subscription_id": sub_id,
            "customer_id": obj.get("customer"),
            "current_period_end": sub["current_period_end"],
            "updated_at": now()
        })


    # --- SUBSCRIPTION UPDATED ---
    elif etype == "customer.subscription.updated":
        user_id = (obj.get("metadata") or {}).get("user_id")
        if not user_id:
            customer_id = obj.get("customer")
            if customer_id:
                cust = stripe.Customer.retrieve(customer_id)
                user_id = (cust.get("metadata") or {}).get("user_id")
        if not user_id:
            return jsonify(ok=True)


        upsert(user_id, {
            "status": obj["status"],
            "subscription_id": obj["id"],
            "customer_id": obj["customer"],
            "current_period_end": obj["current_period_end"],
            "updated_at": now()
        })


    # --- SUBSCRIPTION DELETED ---
    elif etype == "customer.subscription.deleted":
        user_id = (obj.get("metadata") or {}).get("user_id")
        if not user_id:
            customer_id = obj.get("customer")
            if customer_id:
                cust = stripe.Customer.retrieve(customer_id)
                user_id = (cust.get("metadata") or {}).get("user_id")
        if not user_id:
            return jsonify(ok=True)

        upsert(user_id, {
            "status": "canceled",
            "subscription_id": obj["id"],
            "customer_id": obj["customer"],
            "current_period_end": 0,
            "updated_at": now()
        })




# ---------- CONSULTA DE MEMBRESÍA ----------
@app.route("/membership/status")
def membership_status():
    if not require_internal_key(request):
        return jsonify(error="unauthorized"), 401

    user_id = (request.args.get("user_id") or "").strip()
    if not user_id:
        return jsonify(error="missing user_id"), 400

    data = load_data()
    m = data.get(str(user_id))


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

# ---------- CHECKOUT ----------


@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    if not require_internal_key(request):
        return jsonify(error="unauthorized"), 401

    body = request.get_json(silent=True) or {}
    user_id = (body.get("user_id") or "").strip()
    if not user_id:
        return jsonify(error="missing user_id"), 400

    plan_key = (body.get("plan_key") or "ahdo_plus").strip()
    PRICE_ID = os.getenv("STRIPE_PRICE_AHDO_PLUS")
    BASE_SUCCESS = os.getenv("SUCCESS_REDIRECT_URL", "http://localhost:5000/ahdo-plus/success-local")
    BASE_CANCEL = os.getenv("CANCEL_REDIRECT_URL", "http://localhost:5000/ahdo-plus")

    if not PRICE_ID:
        return jsonify(error="missing STRIPE_PRICE_AHDO_PLUS"), 500

    cs = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": PRICE_ID, "quantity": 1}],
        success_url=f"{BASE_SUCCESS}?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=BASE_CANCEL,
        metadata={"user_id": user_id, "plan_key": plan_key},
        subscription_data={"metadata": {"user_id": user_id, "plan_key": plan_key}}
    )

    return jsonify(url=cs["url"])


@app.route("/")
def health():
    return "Billing service running"

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
