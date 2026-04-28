import csv
import os
import datetime

STALE_DAYS = 90



def load_users(filepath=None):
    if filepath is None:
        filepath = os.path.join(os.path.dirname(__file__), "user_access.csv")
    users = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users.append(dict(row))
    return users



def review_users(users):
    today = datetime.date.today()
    for u in users:
        reasons = []
        last_login = datetime.date.fromisoformat(u["last_login"])
        days_since = (today - last_login).days
        if days_since > STALE_DAYS:
            reasons.append(f"No login in {days_since} days")
            if u["access_level"] == "admin":
                reasons.append("Admin access — review required")
                if not u.get("manager"):
                    reasons.append("No manager assigned")
        u["flag"] = "REVIEW" if reasons else "OK"
        u["reasons"] = "; ".join(reasons)
    return users



def write_report(users, filepath=None):
    if filepath is None:
        today_str = datetime.date.today().strftime("%Y%m%d")
        filepath = os.path.join(
            os.path.dirname(__file__), f"access_review_report_{today_str}.csv"
        )
    fieldnames = [
        "username", "full_name", "department", "role",
        "access_level", "last_login", "manager", "flag", "reasons"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)
    return filepath

if __name__ == "__main__":
    users = load_users()
    print(f"Loaded {len(    users)} users\n")
    reviewed = review_users(users)
    out = write_report(reviewed)
    print(f"Flagged: {sum(1 for u in reviewed if u['flag'] == 'REVIEW')}")
    print(f"Report written to: {out}")
