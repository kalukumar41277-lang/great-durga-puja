import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import string
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("GREAT_DURGA_DATABASE", BASE_DIR / "orders.sqlite3"))
HOST = os.environ.get("GREAT_DURGA_HOST", "127.0.0.1")
PORT = int(os.environ.get("GREAT_DURGA_PORT", os.environ.get("PORT", "8000")))
PRICE_PER_TICKET = 50
MAX_TICKETS = 20
SALE_CLOSE = datetime.fromisoformat("2026-10-22T00:00:00+05:30")
SESSION_SECONDS = 8 * 60 * 60
PASSWORD_ITERATIONS = 310_000
MAX_BODY_BYTES = 16_384

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
SESSIONS = {}
LOGIN_FAILURES = {}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                access_hash TEXT NOT NULL,
                purchaser_name TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 20),
                amount INTEGER NOT NULL CHECK (amount > 0),
                status TEXT NOT NULL CHECK (
                    status IN ('awaiting_payment', 'pending_review', 'approved', 'rejected')
                ),
                payment_reference TEXT UNIQUE,
                ticket_codes TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ticket_sequence (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_number INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO ticket_sequence (singleton, next_number) VALUES (1, 1);
            """
        )


def make_password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt, derived


def request_token(handler):
    authorization = handler.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        raise ApiError(401, "Order access token is required.")
    return token


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class GreatDurgaHandler(BaseHTTPRequestHandler):
    server_version = "GreatDurgaPuja/1.0"

    def log_message(self, message, *args):
        logging.info("%s - %s", self.address_string(), message % args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def send_bytes(self, body, content_type, status=200, cache_control="no-store"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length_header = self.headers.get("Content-Length")
        if not length_header:
            raise ApiError(400, "A JSON request body is required.")
        try:
            length = int(length_header)
        except ValueError as error:
            raise ApiError(400, "Invalid request length.") from error
        if length < 1 or length > MAX_BODY_BYTES:
            raise ApiError(413, "Request body is empty or too large.")
        if "application/json" not in self.headers.get("Content-Type", "").lower():
            raise ApiError(415, "Content-Type must be application/json.")
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApiError(400, "Request body must contain valid JSON.") from error
        if not isinstance(data, dict):
            raise ApiError(400, "Request body must be a JSON object.")
        return data

    def ensure_same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            raise ApiError(403, "A same-origin request is required.")
        parsed = urlsplit(origin)
        if parsed.netloc.lower() != self.headers.get("Host", "").lower():
            raise ApiError(403, "Cross-origin requests are not allowed.")

    def send_api_error(self, error):
        self.send_json({"error": error.message}, error.status)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        try:
            if path == "/healthz":
                with connect_db() as connection:
                    connection.execute("SELECT 1").fetchone()
                self.send_json({"status": "ok"})
                return
            if path.startswith("/api/"):
                self.handle_api_get(path)
                return
            files = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/index.html": ("index.html", "text/html; charset=utf-8"),
                "/admin": ("admin.html", "text/html; charset=utf-8"),
                "/admin.html": ("admin.html", "text/html; charset=utf-8"),
                "/WhatsApp Image 2026-10-10 at 21.24.06 (2).jpeg": (
                    "WhatsApp Image 2026-10-10 at 21.24.06 (2).jpeg",
                    "image/jpeg",
                ),
            }
            if path not in files:
                raise ApiError(404, "Page not found.")
            filename, content_type = files[path]
            body = (BASE_DIR / filename).read_bytes()
            cache = "public, max-age=3600" if content_type == "image/jpeg" else "no-store"
            self.send_bytes(body, content_type, cache_control=cache)
        except ApiError as error:
            if path.startswith("/api/"):
                self.send_api_error(error)
            else:
                self.send_error(error.status, error.message)
        except OSError:
            logging.exception("Could not serve requested file")
            if path.startswith("/api/"):
                self.send_json({"error": "The requested resource could not be read."}, 500)
            else:
                self.send_error(500, "The requested page could not be read.")

    def handle_api_get(self, path):
        if path.startswith("/api/orders/"):
            order_id = path.removeprefix("/api/orders/")
            if not order_id or "/" in order_id:
                raise ApiError(404, "Order not found.")
            token = request_token(self)
            with connect_db() as connection:
                order = connection.execute(
                    "SELECT * FROM orders WHERE order_id = ?", (order_id,)
                ).fetchone()
            if not order or not hmac.compare_digest(order["access_hash"], token_hash(token)):
                raise ApiError(404, "Order not found.")
            self.send_json(
                {
                    "orderId": order["order_id"],
                    "quantity": order["quantity"],
                    "amount": order["amount"],
                    "status": order["status"],
                    "ticketCodes": json.loads(order["ticket_codes"]),
                    "createdAt": order["created_at"],
                }
            )
            return

        if path == "/api/admin/orders":
            self.require_admin()
            with connect_db() as connection:
                orders = connection.execute(
                    """
                    SELECT order_id, purchaser_name, quantity, amount, status,
                           payment_reference, ticket_codes, created_at, updated_at
                    FROM orders
                    ORDER BY
                        CASE status WHEN 'pending_review' THEN 0
                                    WHEN 'awaiting_payment' THEN 1 ELSE 2 END,
                        created_at DESC
                    LIMIT 200
                    """
                ).fetchall()
            self.send_json(
                {
                    "orders": [
                        {
                            "orderId": order["order_id"],
                            "name": order["purchaser_name"],
                            "quantity": order["quantity"],
                            "amount": order["amount"],
                            "status": order["status"],
                            "paymentReference": order["payment_reference"],
                            "ticketCodes": json.loads(order["ticket_codes"]),
                            "createdAt": order["created_at"],
                        }
                        for order in orders
                    ]
                }
            )
            return
        raise ApiError(404, "API endpoint not found.")

    def do_POST(self):
        path = unquote(urlsplit(self.path).path)
        try:
            self.ensure_same_origin()
            if path == "/api/orders":
                self.create_order()
            elif path.startswith("/api/orders/") and path.endswith("/payment-reference"):
                order_id = path.removeprefix("/api/orders/").removesuffix("/payment-reference")
                if not order_id or "/" in order_id:
                    raise ApiError(404, "Order not found.")
                self.submit_payment_reference(order_id)
            elif path == "/api/admin/login":
                self.admin_login()
            elif path == "/api/admin/logout":
                self.admin_logout()
            elif path.startswith("/api/admin/orders/"):
                self.admin_review(path.removeprefix("/api/admin/orders/"))
            else:
                raise ApiError(404, "API endpoint not found.")
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.IntegrityError:
            self.send_json(
                {"error": "That payment reference is already recorded. Check it and contact the organizer."},
                409,
            )
        except sqlite3.Error:
            logging.exception("Database operation failed")
            self.send_json({"error": "The order could not be saved. Please try again."}, 500)

    def create_order(self):
        data = self.read_json()
        name = data.get("name")
        quantity = data.get("quantity")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
            raise ApiError(400, "Enter a name (up to 80 characters).")
        if isinstance(quantity, bool) or not isinstance(quantity, int):
            raise ApiError(400, "Ticket quantity must be a whole number.")
        if quantity < 1 or quantity > MAX_TICKETS:
            raise ApiError(400, f"Choose between 1 and {MAX_TICKETS} tickets.")
        if datetime.now(timezone.utc).timestamp() >= SALE_CLOSE.timestamp():
            raise ApiError(410, "Ticket requests are closed.")

        order_id = secrets.token_hex(6).upper()
        access_token = secrets.token_urlsafe(32)
        now = utc_now()
        with connect_db() as connection:
            connection.execute(
                """
                INSERT INTO orders (
                    order_id, access_hash, purchaser_name, quantity, amount,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'awaiting_payment', ?, ?)
                """,
                (
                    order_id,
                    token_hash(access_token),
                    name.strip(),
                    quantity,
                    quantity * PRICE_PER_TICKET,
                    now,
                    now,
                ),
            )
        self.send_json(
            {
                "orderId": order_id,
                "accessToken": access_token,
                "quantity": quantity,
                "amount": quantity * PRICE_PER_TICKET,
                "status": "awaiting_payment",
                "ticketCodes": [],
            },
            201,
        )

    def submit_payment_reference(self, order_id):
        token = request_token(self)
        data = self.read_json()
        reference = data.get("paymentReference")
        if not isinstance(reference, str):
            raise ApiError(400, "Enter the UPI transaction reference.")
        reference = reference.strip()
        if not 6 <= len(reference) <= 80 or any(ord(char) < 32 for char in reference):
            raise ApiError(400, "Enter a transaction reference between 6 and 80 characters.")

        with connect_db() as connection:
            order = connection.execute(
                "SELECT access_hash, status FROM orders WHERE order_id = ?", (order_id,)
            ).fetchone()
            if not order or not hmac.compare_digest(order["access_hash"], token_hash(token)):
                raise ApiError(404, "Order not found.")
            if order["status"] != "awaiting_payment":
                raise ApiError(409, "A payment reference has already been submitted or the order is closed.")
            connection.execute(
                """
                UPDATE orders SET payment_reference = ?, status = 'pending_review', updated_at = ?
                WHERE order_id = ?
                """,
                (reference, utc_now(), order_id),
            )
        self.send_json({"orderId": order_id, "status": "pending_review"})

    def admin_login(self):
        client = self.client_address[0]
        now = time.time()
        failures = [stamp for stamp in LOGIN_FAILURES.get(client, []) if now - stamp < 600]
        if len(failures) >= 10:
            raise ApiError(429, "Too many failed sign-in attempts. Wait ten minutes and try again.")
        data = self.read_json()
        password = data.get("password")
        if not isinstance(password, str) or len(password) > 256:
            password = ""
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), ADMIN_SALT, PASSWORD_ITERATIONS
        )
        if not hmac.compare_digest(candidate, ADMIN_HASH):
            failures.append(now)
            LOGIN_FAILURES[client] = failures
            raise ApiError(401, "Incorrect admin password.")
        LOGIN_FAILURES.pop(client, None)

        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        SESSIONS[hashlib.sha256(session_id.encode()).hexdigest()] = {
            "csrf": csrf_token,
            "expires": now + SESSION_SECONDS,
        }
        cookie = (
            f"gdp_admin={session_id}; HttpOnly; SameSite=Strict; Path=/; "
            f"Max-Age={SESSION_SECONDS}"
        )
        if os.environ.get("GREAT_DURGA_COOKIE_SECURE") == "1":
            cookie += "; Secure"
        self.send_json(
            {"csrfToken": csrf_token},
            headers={"Set-Cookie": cookie},
        )

    def get_admin_session(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            raise ApiError(401, "Admin sign-in is required.")
        morsel = cookies.get("gdp_admin")
        if not morsel:
            raise ApiError(401, "Admin sign-in is required.")
        key = hashlib.sha256(morsel.value.encode()).hexdigest()
        session = SESSIONS.get(key)
        if not session or session["expires"] < time.time():
            SESSIONS.pop(key, None)
            raise ApiError(401, "Admin session expired. Sign in again.")
        return key, session

    def require_admin(self):
        _, session = self.get_admin_session()
        supplied_csrf = self.headers.get("X-CSRF-Token", "")
        if not supplied_csrf or not hmac.compare_digest(supplied_csrf, session["csrf"]):
            raise ApiError(403, "Admin request could not be verified. Sign in again.")

    def admin_logout(self):
        self.require_admin()
        key, _ = self.get_admin_session()
        SESSIONS.pop(key, None)
        self.send_json(
            {"ok": True},
            headers={
                "Set-Cookie": "gdp_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            },
        )

    def admin_review(self, action_path):
        self.require_admin()
        parts = action_path.split("/")
        if len(parts) != 2 or parts[1] not in ("approve", "reject"):
            raise ApiError(404, "Admin action not found.")
        order_id, action = parts
        if not order_id:
            raise ApiError(404, "Order not found.")
        data = self.read_json()
        admin_reference = data.get("paymentReference")
        if admin_reference is not None:
            if not isinstance(admin_reference, str):
                raise ApiError(400, "The payment reference must be text.")
            admin_reference = admin_reference.strip()
            if not 6 <= len(admin_reference) <= 80 or any(
                ord(char) < 32 for char in admin_reference
            ):
                raise ApiError(
                    400, "Enter a verified transaction reference between 6 and 80 characters."
                )
        with connect_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            order = connection.execute(
                "SELECT quantity, status, payment_reference FROM orders WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            if not order:
                raise ApiError(404, "Order not found.")
            allowed_statuses = ("pending_review", "awaiting_payment")
            if order["status"] not in allowed_statuses:
                raise ApiError(409, "Only orders awaiting payment review can be approved or rejected.")

            if action == "approve":
                payment_reference = order["payment_reference"] or admin_reference
                first_number = connection.execute(
                    "SELECT next_number FROM ticket_sequence WHERE singleton = 1"
                ).fetchone()["next_number"]
                quantity = order["quantity"]
                ticket_codes = [
                    f"GDP26-{number:06d}"
                    for number in range(first_number, first_number + quantity)
                ]
                connection.execute(
                    "UPDATE ticket_sequence SET next_number = ? WHERE singleton = 1",
                    (first_number + quantity,),
                )
                connection.execute(
                    """
                    UPDATE orders SET status = 'approved', payment_reference = ?,
                                      ticket_codes = ?, updated_at = ?
                    WHERE order_id = ?
                    """,
                    (payment_reference, json.dumps(ticket_codes), utc_now(), order_id),
                )
            else:
                ticket_codes = []
                connection.execute(
                    "UPDATE orders SET status = 'rejected', updated_at = ? WHERE order_id = ?",
                    (utc_now(), order_id),
                )
        self.send_json({"orderId": order_id, "status": "approved" if action == "approve" else "rejected", "ticketCodes": ticket_codes})


def main():
    global ADMIN_SALT, ADMIN_HASH

    password = os.environ.get("GREAT_DURGA_ADMIN_PASSWORD")
    if password and len(password) < 16:
        raise SystemExit("GREAT_DURGA_ADMIN_PASSWORD must be at least 16 characters.")
    if not password:
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for _ in range(24))
        print(f"Generated one-time admin password: {password}", flush=True)
        print("Set GREAT_DURGA_ADMIN_PASSWORD before restarting to keep a stable password.", flush=True)
    ADMIN_SALT, ADMIN_HASH = make_password_hash(password)
    initialize_database()

    server = ThreadingHTTPServer((HOST, PORT), GreatDurgaHandler)
    server.daemon_threads = True
    print(f"Great Durga Puja is running at http://{HOST}:{PORT}/", flush=True)
    print(f"Admin approval page: http://{HOST}:{PORT}/admin", flush=True)
    print(f"Orders are stored in: {DATABASE}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Great Durga Puja server.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
