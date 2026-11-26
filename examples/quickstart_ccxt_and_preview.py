#!/usr/bin/env python3
"""
Arena Exchange v4.9 — Client-Side Quickstart: AI Discovery, CCXT Adapter & Order Preview
(`examples/quickstart_ccxt_and_preview.py`)

100% client-side zero-dependency example using only the public `arena_sdk` connector.
Demonstrates:
  1. Machine-readable discovery (`GET /llms.txt` and `GET /openapi.json`)
  2. Self-service EIP-191 wallet onboarding (`EthWalletSigner` + `login_with_wallet`)
  3. Standard CCXT `camelCase` methods on `ArenaCcxtAdapter` (`fetchMarkets`,
     `fetchOrderBook`, `previewOrder`, `createLimitBuyOrder`, `cancelOrder`)
  4. Stateless `POST /order/preview` dry-run margin & fill simulation (zero WAL mutation)
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

SDK_DIR = Path(__file__).resolve().parent.parent / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from arena_sdk import (  # noqa: E402
    PUBLIC_TESTNET_URL,
    ArenaCcxtAdapter,
    ArenaHttpClient,
    EthWalletSigner,
)


def run_quickstart(arena_url: str, symbol: str, dry_run: bool = True) -> Dict[str, Any]:
    client = ArenaHttpClient(arena_url, timeout=5.0)
    try:
        llms_banner = client.llms_txt().splitlines()[0]
        openapi = client.openapi_spec()
        signer = EthWalletSigner()
        login = client.login_with_wallet(signer)
        if not login.get("ok"):
            raise RuntimeError(f"Wallet login failed: {login}")
        aid = int(login["account_id"])

        exchange = ArenaCcxtAdapter(client, account_id=aid)
        try:
            markets = exchange.fetchMarkets()
            ob = exchange.fetchOrderBook(symbol, limit=5)
            preview = exchange.previewOrder(
                symbol,
                "limit",
                "buy",
                "0.0100",
                "50000.00",
                {"postOnly": True},
            )
            result: Dict[str, Any] = {
                "ok": True,
                "llms_header": llms_banner,
                "openapi_version": openapi.get("openapi"),
                "account_id": aid,
                "eth_address": signer.address,
                "market_count": len(markets),
                "top_bid": ob["bids"][0] if ob.get("bids") else None,
                "top_ask": ob["asks"][0] if ob.get("asks") else None,
                "preview": preview,
            }
            if not dry_run and preview.get("wouldAccept"):
                placed = exchange.createLimitBuyOrder(
                    symbol, "0.0100", "50000.00", {"postOnly": True}
                )
                result["placed_order"] = placed
                if placed.get("status") == "open":
                    result["canceled_order"] = exchange.cancelOrder(placed["id"], symbol)
            return result
        finally:
            exchange.close()
    finally:
        client.close()


def _run_self_test() -> int:
    signer = EthWalletSigner()
    exchange = ArenaCcxtAdapter(
        {
            "url": "http://127.0.0.1:8080",
            "apiKey": "demo_key",
            "secret": "demo_secret",
            "accountId": 7,
            "timeout": 5000,
        }
    )
    try:
        assert signer.address.startswith("0x") and len(signer.address) == 42
        assert exchange.account_id == 7 and exchange.timeout == 5.0
        assert callable(exchange.previewOrder) and callable(exchange.createLimitBuyOrder)
        assert callable(exchange.fetchLeaderboard) and callable(exchange.setSandboxMode)
        tn_cli = ArenaHttpClient.testnet()
        tn_ex = ArenaCcxtAdapter({"sandbox": True})
        try:
            assert PUBLIC_TESTNET_URL == "https://testnet.feraterra.app"
            assert tn_cli.base_url == PUBLIC_TESTNET_URL and tn_ex.base_url == PUBLIC_TESTNET_URL
        finally:
            tn_cli.close()
            tn_ex.close()
    finally:
        exchange.close()
    print("[PASS] quickstart_ccxt_and_preview.py client self-test OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Arena Exchange Client-Side CCXT & Preview Quickstart")
    ap.add_argument(
        "--arena-url",
        "--url",
        dest="arena_url",
        default=os.environ.get("ARENA_URL", "http://127.0.0.1:8080"),
        help=f"Arena HTTP endpoint (or set ARENA_URL; public testnet: {PUBLIC_TESTNET_URL})",
    )
    ap.add_argument(
        "--testnet",
        action="store_true",
        help=f"Connect to live public Base Sepolia testnet ({PUBLIC_TESTNET_URL})",
    )
    ap.add_argument("--symbol", default="BTC/USD:USD")
    ap.add_argument("--execute", action="store_true", help="Submit + cancel live PostOnly order if preview accepts")
    ap.add_argument("--self-test", action="store_true", help="Run offline deterministic client self-test")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    eff_url = PUBLIC_TESTNET_URL if args.testnet else args.arena_url
    out = run_quickstart(eff_url, args.symbol, dry_run=(not args.execute))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
