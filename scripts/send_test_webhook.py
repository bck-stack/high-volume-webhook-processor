"""
Send signed test webhooks to a running receiver.

    python scripts/send_test_webhook.py                      # one event
    python scripts/send_test_webhook.py --count 2000 -c 50   # quick load test
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000/webhook")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("-c", "--concurrency", type=int, default=20)
    parser.add_argument("--secret", default=os.getenv("WEBHOOK_SECRET", ""))
    args = parser.parse_args()

    sem = asyncio.Semaphore(args.concurrency)
    statuses: dict[int, int] = {}

    async with httpx.AsyncClient(timeout=10) as client:
        async def send(i: int) -> None:
            body = json.dumps({"order_id": i, "amount": round(10 + i * 0.5, 2)}).encode()
            headers = {
                "Content-Type": "application/json",
                "X-Event-Source": "load-test",
                "X-Event-Type": "order.created",
                "X-Delivery-Id": str(uuid.uuid4()),
            }
            if args.secret:
                headers["X-Hub-Signature-256"] = sign(args.secret, body)
            async with sem:
                try:
                    r = await client.post(args.url, content=body, headers=headers)
                    statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
                except httpx.HTTPError:
                    statuses[0] = statuses.get(0, 0) + 1

        t0 = time.perf_counter()
        await asyncio.gather(*(send(i) for i in range(args.count)))
        elapsed = time.perf_counter() - t0

    print(f"Sent {args.count} webhooks in {elapsed:.2f}s ({args.count / elapsed:.0f} req/s)")
    print("Status codes:", dict(sorted(statuses.items())), "(0 = connection error)")


if __name__ == "__main__":
    asyncio.run(main())
