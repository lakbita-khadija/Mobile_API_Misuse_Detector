import time
import json


def token_bucket_check(ip, limit, window, r):

    key = f"tb:{ip}"

    now = time.time()

    raw = r.get(key)

    data = json.loads(raw) if raw else None

    if data is None:
        data = {
            "tokens": limit,
            "last": now
        }

    elapsed = now - data["last"]

    refill = elapsed * (limit / window)

    data["tokens"] = min(limit, data["tokens"] + refill)

    data["last"] = now

    if data["tokens"] < 1:
        r.setex(key, window, json.dumps(data))
        return False, 0

    data["tokens"] -= 1

    r.setex(key, window, json.dumps(data))

    return True, int(data["tokens"])
