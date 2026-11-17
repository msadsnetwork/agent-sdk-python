"""MS Ads Agent Exchange server SDK (Python 3.8+, standard library only).

    from msads_agent import AgentExchange
    ax = AgentExchange(agent_id="agt_...", key=os.environ["MSADS_KEY"], secret=os.environ.get("MSADS_SIGNING_SECRET"))
    r = ax.get_offers({"unit": "msads_...", "test": True, "intent": {"task_type": "purchase", "category": "electronics.laptops"}})

Never ship the key or signing secret inside a mobile app or browser: call this from your bot backend.
"""
import hashlib, hmac, json, secrets, time, urllib.request, urllib.error

__version__ = "0.1.0"
DEFAULT_BASE = "https://msadsnetwork.com"


def sign(secret, timestamp, nonce, method, path, body):
    """v1=hex(HMAC_SHA256(secret, ts\\nnonce\\nMETHOD\\n/path\\nsha256_hex(body)))"""
    body = body if isinstance(body, bytes) else (body or "").encode()
    s = "\n".join([str(timestamp), nonce, method.upper(), "/" + path.lstrip("/"), hashlib.sha256(body).hexdigest()])
    return "v1=" + hmac.new(secret.encode(), s.encode(), hashlib.sha256).hexdigest()


class MsadsError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status, self.body = status, body


class AgentExchange:
    def __init__(self, agent_id, key, secret=None, base_url=DEFAULT_BASE, timeout=2.0):
        self.agent_id, self.key, self.secret = agent_id, key, secret
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def _post(self, path, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        h = {"Content-Type": "application/json", "Accept": "application/json", "X-MSADS-Key": self.key, "User-Agent": "msads-agent-python/" + __version__}
        if self.secret:
            ts, nonce = str(int(time.time())), secrets.token_hex(12)
            h.update({"X-MSADS-Agent": self.agent_id, "X-MSADS-Timestamp": ts, "X-MSADS-Nonce": nonce,
                      "X-MSADS-Signature": sign(self.secret, ts, nonce, "POST", path, raw)})
        req = urllib.request.Request(self.base + path, data=raw, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                txt = r.read().decode() or "{}"
                return json.loads(txt)
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                body = json.loads(body)
            except ValueError:
                pass
            raise MsadsError(e.code, body)

    def get_offers(self, request):
        """POST /api/v1/agent-exchange/offers. Send only an intent summary: no raw chat text, no personal data."""
        return self._post("/api/v1/agent-exchange/offers", request)

    def send_event(self, offer_ref, event, idempotency_key, proof_hash=None):
        e = {"offer_ref": offer_ref, "event": event, "idempotency_key": idempotency_key}
        if proof_hash:
            e["proof_hash"] = proof_hash
        return self._post("/api/v1/agent-exchange/events", e)

    def send_events(self, events):
        return self._post("/api/v1/agent-exchange/events", {"events": events[:100]})

    @staticmethod
    def proof_hash(order_reference):
        """sha256 hex of the merchant order / booking reference (required for task_completed)."""
        return hashlib.sha256(order_reference.encode()).hexdigest()

    @staticmethod
    def sponsored_text(offer):
        """Plain-text rendering for WhatsApp / Telegram / SMS that keeps the mandatory Sponsored label."""
        label = (offer.get("disclosure") or {}).get("label", "Sponsored")
        m = offer.get("merchant") or {}
        p = offer.get("price") or {}
        price = f"{p.get('currency', '')} {p.get('amount', '')}".strip()
        return f"[{label}] {offer.get('title', '')} - {m.get('name', '')}\n{price}\n{(offer.get('checkout') or {}).get('url', '')}"
