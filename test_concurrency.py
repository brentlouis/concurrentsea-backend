import threading, requests, time

API = "http://localhost:8000"
N = 5

USERS = [
    ("maria@test.com", "Maria Santos"),
    ("jose@test.com",  "Jose Rizal"),
    ("ana@test.com",   "Ana Cruz"),
    ("pedro@test.com", "Pedro Reyes"),
    ("luis@test.com",  "Luis Garcia"),
]
PASSWORD = "test1234"


def setup_users():
    tokens = []
    for email, name in USERS:
        requests.post(f"{API}/api/auth/register", json={
            "email": email, "password": PASSWORD, "fullName": name,
        })  # 409 if already registered — fine
        r = requests.post(f"{API}/api/auth/login",
                          json={"email": email, "password": PASSWORD})
        tokens.append((name, r.json()["token"]))
    return tokens


def first_available_seat(schedule_id=1):
    seats = requests.get(f"{API}/api/schedules/{schedule_id}/seats").json()["seats"]
    for s in seats:
        if s["status"] == "AVAILABLE":
            return s["seatId"], s["seatNumber"]
    raise SystemExit("No available seats — reset the database")


results = []
barrier = threading.Barrier(N)


def attempt(name, token, seat_id):
    headers = {"Authorization": f"Bearer {token}"}
    barrier.wait()                      # everyone waits here
    sent = time.perf_counter()          # then all fire together
    r = requests.post(f"{API}/api/bookings/hold",
                      json={"seatId": seat_id}, headers=headers)
    results.append((name, r.status_code, sent, r.json()))


if __name__ == "__main__":
    tokens = setup_users()
    seat_id, seat_number = first_available_seat()
    print(f"\n{N} users racing for seat {seat_number} (id {seat_id})\n")

    threads = [threading.Thread(target=attempt, args=(n, t, seat_id))
               for n, t in tokens]

    for t in threads: t.start()
    for t in threads: t.join()

    results.sort(key=lambda r: r[2])
    t0 = results[0][2]
    for name, status, sent, body in results:
        offset = (sent - t0) * 1000
        verdict = "WON " if status == 201 else "lost"
        detail = body.get("bookingReference") or body.get("detail", "")
        print(f"  +{offset:6.2f} ms  {name:14} {status}  {verdict}  {detail}")

    won = sum(1 for r in results if r[1] == 201)
    print(f"\n  {won} booking created, {N - won} rejected with 409")
    print("  PASS\n" if won == 1 else "\n  FAIL — expected exactly 1\n")