from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from database import engine
from auth import hash_password, verify_password, make_token, current_user
from datetime import datetime
import random

app = FastAPI(title="ConcurrentSea")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Request
from fastapi.responses import JSONResponse

ERROR_CODES = {
    400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN",
    404: "NOT_FOUND", 409: "CONFLICT", 410: "GONE",
}

@app.exception_handler(HTTPException)
def http_error(request: Request, exc: HTTPException):
    code = ERROR_CODES.get(exc.status_code, "ERROR")
    if exc.status_code == 409 and "seat" in str(exc.detail).lower():
        code = "SEAT_TAKEN"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": code, "message": exc.detail},
    )

def release_expired_holds(conn) -> int:
    conn.execute(text("""
        UPDATE bookings b
        SET status = 'EXPIRED'
        FROM seats s
        WHERE b.seat_id = s.id
          AND b.status = 'PENDING'
          AND s.status = 'HELD'
          AND s.held_until < now()
    """))

    result = conn.execute(text("""
        UPDATE seats
        SET status = 'AVAILABLE', held_by = NULL, held_until = NULL
        WHERE status = 'HELD' AND held_until < now()
    """))
    return result.rowcount

def log_attempt(user_id, seat_id, result, message=None):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO booking_attempts (user_id, seat_id, result, message)
            VALUES (:uid, :sid, :res, :msg)
        """), {"uid": user_id, "sid": seat_id, "res": result, "msg": message})

# request models

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    fullName: str
    phone: str | None = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class HoldIn(BaseModel):
    seatId: int


class PayIn(BaseModel):
    method: str


class ScheduleIn(BaseModel):
    origin: str
    destination: str
    departureTime: str
    arrivalTime: str
    vesselName: str
    price: float
    totalSeats: int


class SchedulePatch(BaseModel):
    origin: str | None = None
    destination: str | None = None
    departureTime: str | None = None
    arrivalTime: str | None = None
    vesselName: str | None = None
    price: float | None = None
    status: str | None = None


class UserPatch(BaseModel):
    isActive: bool | None = None
    role: str | None = None


# schedules 

@app.get("/api/schedules")
def list_schedules(origin: str | None = None, destination: str | None = None,
                   date: str | None = None, minSeats: int | None = None):
    sql = """
        SELECT s.id,
               s.origin,
               s.destination,
               s.departure_time AS "departureTime",
               s.arrival_time   AS "arrivalTime",
               s.vessel_name    AS "vesselName",
               s.price,
               s.total_seats    AS "totalSeats",
               s.status,
               (SELECT count(*) FROM seats
                 WHERE schedule_id = s.id AND status = 'AVAILABLE') AS "availableSeats"
        FROM schedules s
        WHERE s.status = 'SCHEDULED'
    """
    params = {}
    if origin:
        sql += " AND s.origin ILIKE :origin"
        params["origin"] = f"%{origin}%"
    if destination:
        sql += " AND s.destination ILIKE :dest"
        params["dest"] = f"%{destination}%"
    if date:
        sql += " AND s.departure_time::date = :date"
        params["date"] = date
    if minSeats:
        sql += """ AND (SELECT count(*) FROM seats
                         WHERE schedule_id = s.id AND status = 'AVAILABLE') >= :minSeats"""
        params["minSeats"] = minSeats
    sql += " ORDER BY s.departure_time"

    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    return [dict(r) for r in rows]


@app.get("/api/schedules/{schedule_id}/seats")
def seat_map(schedule_id: int):
    with engine.begin() as conn:
        release_expired_holds(conn)

        exists = conn.execute(
            text("SELECT 1 FROM schedules WHERE id = :id"),
            {"id": schedule_id},
        ).first()
        if not exists:
            raise HTTPException(404, "Schedule not found")

        rows = conn.execute(text("""
            SELECT id AS "seatId", seat_number AS "seatNumber", status
            FROM seats
            WHERE schedule_id = :id
            ORDER BY id
        """), {"id": schedule_id}).mappings().all()

    return {"scheduleId": schedule_id, "seats": [dict(r) for r in rows]}


@app.get("/api/schedules/{schedule_id}")
def get_schedule(schedule_id: int):
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT s.id,
                   s.origin,
                   s.destination,
                   s.departure_time AS "departureTime",
                   s.arrival_time   AS "arrivalTime",
                   s.vessel_name    AS "vesselName",
                   s.price,
                   s.total_seats    AS "totalSeats",
                   s.status,
                   (SELECT count(*) FROM seats
                     WHERE schedule_id = s.id AND status = 'AVAILABLE') AS "availableSeats"
            FROM schedules s
            WHERE s.id = :id
        """), {"id": schedule_id}).mappings().first()

    if not row:
        raise HTTPException(404, "Schedule not found")
    return dict(row)

# auth

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterIn):
    sql = text("""
        INSERT INTO users (email, password_hash, full_name, phone)
        VALUES (:email, :pw, :name, :phone)
        RETURNING id, email, full_name AS "fullName", role
    """)
    try:
        with engine.begin() as conn:
            row = conn.execute(sql, {
                "email": body.email,
                "pw": hash_password(body.password),
                "name": body.fullName,
                "phone": body.phone,
            }).mappings().first()
    except IntegrityError:
        raise HTTPException(409, "Email already registered")
    return dict(row)


@app.post("/api/auth/login")
def login(body: LoginIn):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, password_hash, full_name, role, is_active "
                 "FROM users WHERE email = :email"),
            {"email": body.email},
        ).mappings().first()

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if not row["is_active"]:
        raise HTTPException(401, "Account deactivated")

    return {
        "token": make_token(row["id"], row["role"]),
        "user": {"id": row["id"], "fullName": row["full_name"], "role": row["role"]},
    }


@app.get("/api/auth/me")
def me(user = Depends(current_user)):
    return {"id": user["id"], "email": user["email"],
            "fullName": user["full_name"], "role": user["role"]}


#  admin 


def require_admin(user = Depends(current_user)):
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Admin access required")
    return user


@app.post("/api/admin/release-holds")
def force_release(admin = Depends(require_admin)):
    with engine.begin() as conn:
        return {"released": release_expired_holds(conn)}


@app.post("/api/admin/schedules", status_code=201)
def create_schedule(body: ScheduleIn, admin = Depends(require_admin)):
    if body.totalSeats < 1 or body.totalSeats > 500:
        raise HTTPException(400, "totalSeats must be between 1 and 500")

    with engine.begin() as conn:
        sched = conn.execute(text("""
            INSERT INTO schedules (origin, destination, departure_time,
                                   arrival_time, vessel_name, price, total_seats)
            VALUES (:o, :d, :dep, :arr, :v, :p, :n)
            RETURNING id
        """), {"o": body.origin, "d": body.destination,
               "dep": body.departureTime, "arr": body.arrivalTime,
               "v": body.vesselName, "p": body.price,
               "n": body.totalSeats}).mappings().first()

        conn.execute(text("""
            INSERT INTO seats (schedule_id, seat_number)
            SELECT :sid, 'A' || g FROM generate_series(1, :n) AS g
        """), {"sid": sched["id"], "n": body.totalSeats})

    return {"id": sched["id"], "origin": body.origin,
            "destination": body.destination, "vesselName": body.vesselName,
            "totalSeats": body.totalSeats, "seatCount": body.totalSeats,
            "status": "SCHEDULED"}    


COLUMN_MAP = {
    "origin": "origin", "destination": "destination",
    "departureTime": "departure_time", "arrivalTime": "arrival_time",
    "vesselName": "vessel_name", "price": "price", "status": "status",
}


@app.patch("/api/admin/schedules/{schedule_id}")
def patch_schedule(schedule_id: int, body: SchedulePatch,
                   admin = Depends(require_admin)):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(400, "No fields to update")

    sets, params = [], {"id": schedule_id}
    for key, value in changes.items():
        column = COLUMN_MAP[key]
        sets.append(f"{column} = :{key}")
        params[key] = value

    sql = f"UPDATE schedules SET {', '.join(sets)} WHERE id = :id RETURNING id, status"

    with engine.begin() as conn:
        row = conn.execute(text(sql), params).mappings().first()
    if not row:
        raise HTTPException(404, "Schedule not found")
    return {"id": row["id"], "status": row["status"]}


@app.get("/api/admin/users")
def list_users(admin = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, email, full_name AS "fullName", phone, role,
                   is_active AS "isActive", created_at AS "createdAt"
            FROM users ORDER BY id
        """)).mappings().all()
    return [dict(r) for r in rows]


@app.patch("/api/admin/users/{user_id}")
def patch_user(user_id: int, body: UserPatch, admin = Depends(require_admin)):
    if body.role and body.role not in ("CUSTOMER", "ADMIN"):
        raise HTTPException(400, "Invalid role")

    with engine.begin() as conn:
        row = conn.execute(text("""
            UPDATE users
            SET is_active = COALESCE(:active, is_active),
                role      = COALESCE(:role, role)
            WHERE id = :id
            RETURNING id, email, role, is_active AS "isActive"
        """), {"active": body.isActive, "role": body.role,
               "id": user_id}).mappings().first()
    if not row:
        raise HTTPException(404, "User not found")
    return dict(row)


@app.get("/api/admin/bookings")
def admin_bookings(scheduleId: int | None = None, status: str | None = None,
                   admin = Depends(require_admin)):
    sql = """
        SELECT b.id AS "bookingId", b.booking_reference AS "bookingReference",
               b.status, b.created_at AS "createdAt",
               u.id AS "userId", u.full_name AS "fullName", u.email,
               s.id AS "seatId", s.seat_number AS "seatNumber",
               sc.id AS "scheduleId", sc.origin, sc.destination,
               p.status AS "paymentStatus", p.method
        FROM bookings b
        JOIN users u      ON u.id = b.user_id
        JOIN seats s      ON s.id = b.seat_id
        JOIN schedules sc ON sc.id = s.schedule_id
        LEFT JOIN payments p ON p.booking_id = b.id
        WHERE 1=1
    """
    params = {}
    if scheduleId:
        sql += " AND sc.id = :sid"; params["sid"] = scheduleId
    if status:
        sql += " AND b.status = :st"; params["st"] = status
    sql += " ORDER BY b.created_at DESC"

    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    return [dict(r) for r in rows]


@app.get("/api/admin/attempts")
def list_attempts(seatId: int | None = None, limit: int = 50,
                  admin = Depends(require_admin)):
    sql = """
        SELECT ba.user_id AS "userId", u.full_name AS "fullName",
               ba.seat_id AS "seatId", s.seat_number AS "seatNumber",
               ba.result, ba.message,
               ba.attempted_at AS "attemptedAt"
        FROM booking_attempts ba
        LEFT JOIN users u ON u.id = ba.user_id
        LEFT JOIN seats s ON s.id = ba.seat_id
        WHERE 1=1
    """
    params = {"limit": limit}
    if seatId:
        sql += " AND ba.seat_id = :sid"; params["sid"] = seatId
    sql += " ORDER BY ba.attempted_at DESC LIMIT :limit"

    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    return [dict(r) for r in rows]


# booking

@app.post("/api/bookings/hold", status_code=201)
def hold_seat(body: HoldIn, user = Depends(current_user)):
    seat_id = body.seatId
    user_id = user["id"]

    with engine.begin() as conn:
        release_expired_holds(conn)

        info = conn.execute(text("""
            SELECT s.seat_number, sc.id AS schedule_id,
                   sc.status AS schedule_status, sc.price
            FROM seats s
            JOIN schedules sc ON sc.id = s.schedule_id
            WHERE s.id = :sid
        """), {"sid": seat_id}).mappings().first()

        if not info:
            raise HTTPException(404, "Seat not found")
        if info["schedule_status"] != "SCHEDULED":
            raise HTTPException(410, "This trip is no longer open for booking")

        # the claim
        claimed = conn.execute(text("""
            UPDATE seats
            SET status     = 'HELD',
                held_by    = :uid,
                held_until = now() + INTERVAL '5 minutes',
                version    = version + 1
            WHERE id = :sid AND status = 'AVAILABLE'
            RETURNING held_until
        """), {"uid": user_id, "sid": seat_id}).mappings().first()

        if claimed is not None:
            booking = conn.execute(text("""
                INSERT INTO bookings (user_id, seat_id, status)
                VALUES (:uid, :sid, 'PENDING')
                RETURNING id
            """), {"uid": user_id, "sid": seat_id}).mappings().first()

            ref = f"BK-{datetime.now().year}-{booking['id']:06d}"
            conn.execute(
                text("UPDATE bookings SET booking_reference = :ref WHERE id = :id"),
                {"ref": ref, "id": booking["id"]},
            )

    if claimed is None:
        log_attempt(user_id, seat_id, "SEAT_TAKEN", "Lost the race")
        raise HTTPException(409, "That seat was just booked by someone else.")

    log_attempt(user_id, seat_id, "SUCCESS")

    return {
        "bookingId": booking["id"],
        "bookingReference": ref,
        "seatId": seat_id,
        "seatNumber": info["seat_number"],
        "status": "PENDING",
        "amount": float(info["price"]),
        "holdExpiresAt": claimed["held_until"].isoformat(),
    }

# booking history

@app.get("/api/bookings/me")
def my_bookings(status: str | None = None, user = Depends(current_user)):
    sql = """
        SELECT b.id, b.booking_reference, b.status, b.created_at,
               s.seat_number, sc.origin, sc.destination,
               sc.departure_time, sc.price
        FROM bookings b
        JOIN seats s      ON s.id = b.seat_id
        JOIN schedules sc ON sc.id = s.schedule_id
        WHERE b.user_id = :uid
    """
    params = {"uid": user["id"]}
    if status:
        sql += " AND b.status = :status"
        params["status"] = status
    sql += " ORDER BY b.created_at DESC"

    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    return [{
        "bookingId": r["id"],
        "bookingReference": r["booking_reference"],
        "status": r["status"],
        "seatNumber": r["seat_number"],
        "amount": float(r["price"]),
        "createdAt": r["created_at"].isoformat(),
        "schedule": {"origin": r["origin"], "destination": r["destination"],
                     "departureTime": r["departure_time"].isoformat()},
    } for r in rows]

# return single booking

@app.get("/api/bookings/{booking_id}")
def get_booking(booking_id: int, user = Depends(current_user)):
    with engine.connect() as conn:
        r = conn.execute(text("""
            SELECT b.id, b.booking_reference, b.status, b.created_at,
                   b.confirmed_at, b.cancelled_at, b.user_id,
                   s.id AS seat_id, s.seat_number,
                   sc.id AS schedule_id, sc.origin, sc.destination,
                   sc.departure_time, sc.vessel_name,
                   p.status AS pay_status, p.method, p.amount
            FROM bookings b
            JOIN seats s      ON s.id = b.seat_id
            JOIN schedules sc ON sc.id = s.schedule_id
            LEFT JOIN payments p ON p.booking_id = b.id
            WHERE b.id = :bid
        """), {"bid": booking_id}).mappings().first()

    if not r:
        raise HTTPException(404, "Booking not found")
    if r["user_id"] != user["id"] and user["role"] != "ADMIN":
        raise HTTPException(403, "Not your booking")

    return {
        "bookingId": r["id"],
        "bookingReference": r["booking_reference"],
        "status": r["status"],
        "createdAt": r["created_at"].isoformat(),
        "confirmedAt": r["confirmed_at"].isoformat() if r["confirmed_at"] else None,
        "cancelledAt": r["cancelled_at"].isoformat() if r["cancelled_at"] else None,
        "seat": {"seatId": r["seat_id"], "seatNumber": r["seat_number"]},
        "schedule": {
            "id": r["schedule_id"], "origin": r["origin"],
            "destination": r["destination"],
            "departureTime": r["departure_time"].isoformat(),
            "vesselName": r["vessel_name"],
        },
        "payment": None if r["pay_status"] is None else {
            "status": r["pay_status"], "method": r["method"],
            "amount": float(r["amount"]),
        },
    }


# pay

@app.post("/api/bookings/{booking_id}/pay")
def pay(booking_id: int, body: PayIn, user = Depends(current_user)):
    if body.method not in ("GCASH", "MAYA", "CARD", "COUNTER"):
        raise HTTPException(400, "Invalid payment method")

    with engine.begin() as conn:
        release_expired_holds(conn)

        info = conn.execute(text("""
            SELECT b.user_id, b.booking_reference, b.seat_id,
                   s.seat_number, sc.price
            FROM bookings b
            JOIN seats s      ON s.id = b.seat_id
            JOIN schedules sc ON sc.id = s.schedule_id
            WHERE b.id = :bid
        """), {"bid": booking_id}).mappings().first()

        if not info:
            raise HTTPException(404, "Booking not found")
        if info["user_id"] != user["id"]:
            raise HTTPException(403, "Not your booking")

        confirmed = conn.execute(text("""
            UPDATE bookings
            SET status = 'CONFIRMED', confirmed_at = now()
            WHERE id = :bid AND status = 'PENDING'
            RETURNING confirmed_at
        """), {"bid": booking_id}).mappings().first()

        if confirmed is None:
            raise HTTPException(409, "Hold expired or booking is no longer pending")

        conn.execute(text("""
            UPDATE seats SET status = 'BOOKED', held_by = NULL, held_until = NULL
            WHERE id = :sid
        """), {"sid": info["seat_id"]})

        txn_ref = f"{body.method[:2]}-{random.randint(10000, 99999)}"
        conn.execute(text("""
            INSERT INTO payments (booking_id, amount, method, status,
                                  transaction_ref, paid_at)
            VALUES (:bid, :amt, :method, 'PAID', :ref, now())
        """), {"bid": booking_id, "amt": info["price"],
               "method": body.method, "ref": txn_ref})

    return {
        "bookingId": booking_id,
        "bookingReference": info["booking_reference"],
        "status": "CONFIRMED",
        "confirmedAt": confirmed["confirmed_at"].isoformat(),
        "payment": {"status": "PAID", "method": body.method,
                    "amount": float(info["price"]), "transactionRef": txn_ref},
    }

# cancel

@app.post("/api/bookings/{booking_id}/cancel")
def cancel(booking_id: int, user = Depends(current_user)):
    with engine.begin() as conn:
        info = conn.execute(text("""
            SELECT user_id, seat_id FROM bookings WHERE id = :bid
        """), {"bid": booking_id}).mappings().first()

        if not info:
            raise HTTPException(404, "Booking not found")
        if info["user_id"] != user["id"] and user["role"] != "ADMIN":
            raise HTTPException(403, "Not your booking")

        cancelled = conn.execute(text("""
            UPDATE bookings
            SET status = 'CANCELLED', cancelled_at = now()
            WHERE id = :bid AND status IN ('PENDING', 'CONFIRMED')
            RETURNING cancelled_at
        """), {"bid": booking_id}).mappings().first()

        if cancelled is None:
            raise HTTPException(409, "Booking is already cancelled or expired")

        conn.execute(text("""
            UPDATE seats SET status = 'AVAILABLE', held_by = NULL, held_until = NULL
            WHERE id = :sid
        """), {"sid": info["seat_id"]})

        conn.execute(text("""
            UPDATE payments SET status = 'REFUNDED'
            WHERE booking_id = :bid AND status = 'PAID'
        """), {"bid": booking_id})

    return {"bookingId": booking_id, "status": "CANCELLED",
            "cancelledAt": cancelled["cancelled_at"].isoformat()}


# reset database

@app.post("/api/admin/reset-demo")
def reset_demo(admin = Depends(require_admin)):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM booking_attempts"))
        conn.execute(text("DELETE FROM payments"))
        conn.execute(text("DELETE FROM bookings"))
        result = conn.execute(text("""
            UPDATE seats
            SET status='AVAILABLE', held_by=NULL, held_until=NULL, version=0
        """))
    return {"reset": True, "seatsReleased": result.rowcount}


# ... every @app route above ...

import os
from fastapi.staticfiles import StaticFiles

if os.path.isdir("dev-ui"):
    app.mount("/dev-ui", StaticFiles(directory="dev-ui", html=True), name="dev-ui")

if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
