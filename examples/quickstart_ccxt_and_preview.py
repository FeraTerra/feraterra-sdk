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
import http.server
import json
import os
from pathlib import Path
import sys
import threading
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


FUNDING_HINT_MSG = (
    "Account has $0 margin; re-run with --fund-faucet "
    "(or call request_testnet_faucet + deposit_onchain_margin) before --execute."
)


def _compute_preview_limit_buy_price(markets: List[Dict[str, Any]], symbol: str) -> str:
    sym_up = str(symbol or "").strip().upper()
    btc_perp: Optional[Dict[str, Any]] = None
    for m in markets:
        if not isinstance(m, dict):
            continue
        candidates = (
            str(m.get("symbol", "")).upper(),
            str(m.get("nativeSymbol", "")).upper(),
            str(m.get("id", "")).upper(),
        )
        if sym_up and sym_up in candidates:
            btc_perp = m
            break
    if btc_perp is None:
        for m in markets:
            if not isinstance(m, dict):
                continue
            if str(m.get("nativeSymbol", m.get("symbol", ""))).upper() in ("BTC-USD-PERP", "BTC/USD:USD"):
                btc_perp = m
                break
    info = btc_perp.get("info") if isinstance(btc_perp, dict) and isinstance(btc_perp.get("info"), dict) else {}
    mark_ticks = int(info.get("mark_price_ticks") or 0)
    if mark_ticks > 0:
        ticks_98 = max(1, (mark_ticks * 98) // 100)
        return f"{ticks_98 // 100}.{ticks_98 % 100:02d}"
    return "50000.00"


def run_quickstart(
    arena_url: str,
    symbol: str,
    dry_run: bool = True,
    fund_faucet: bool = False,
) -> Dict[str, Any]:
    client = ArenaHttpClient(arena_url, timeout=5.0)
    try:
        llms_raw = str(client.llms_txt() or "")
        llms_lines = [ln.strip() for ln in llms_raw.splitlines() if ln.strip()]
        if not llms_lines:
            raise RuntimeError("GET /llms.txt returned empty discovery document")
        llms_banner = llms_lines[0]
        openapi = client.openapi_spec()
        signer = EthWalletSigner()
        login = client.login_with_wallet(signer)
        if not login.get("ok"):
            raise RuntimeError(f"Wallet login failed: {login}")
        aid = int(login["account_id"])

        faucet_res: Optional[Dict[str, Any]] = None
        deposit_res: Optional[Dict[str, Any]] = None
        if fund_faucet:
            faucet_res = client.request_testnet_faucet(
                signer.address, amount="10000", asset="USD", drip_gas=True
            )
            if not faucet_res.get("ok", True):
                raise RuntimeError(f"Testnet faucet request failed: {faucet_res}")
            deposit_res = client.deposit_onchain_margin(
                signer, "10000", account_id=aid, wait_for_credit=True
            )

        exchange = ArenaCcxtAdapter(client, account_id=aid)
        try:
            markets = exchange.fetchMarkets()
            limit_buy_price = _compute_preview_limit_buy_price(markets, symbol)
            ob = exchange.fetchOrderBook(symbol, limit=5)
            preview = exchange.previewOrder(
                symbol,
                "limit",
                "buy",
                "0.0100",
                limit_buy_price,
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
            if faucet_res is not None:
                result["faucet"] = faucet_res
            if deposit_res is not None:
                result["deposit"] = deposit_res
            if not preview.get("wouldAccept") and "insufficient" in str(
                preview.get("rejectionReason", "")
            ).lower():
                result["funding_hint"] = FUNDING_HINT_MSG
            if not dry_run and preview.get("wouldAccept"):
                placed = exchange.createLimitBuyOrder(
                    symbol, "0.0100", limit_buy_price, {"postOnly": True}
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

    assert _compute_preview_limit_buy_price([], "BTC/USD:USD") == "50000.00"
    assert (
        _compute_preview_limit_buy_price(
            [{"symbol": "BTC/USD:USD", "nativeSymbol": "BTC-USD-PERP", "info": {"mark_price_ticks": 8_500_000}}],
            "BTC/USD:USD",
        )
        == "83300.00"
    )

    preview_calls: List[Dict[str, Any]] = []
    accept_preview = False

    class _QuickstartLoopback(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def _reply_json(self, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/llms.txt"):
                raw = b"Arena Exchange v4.9\n/order/preview\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif self.path.startswith("/openapi.json"):
                self._reply_json({"openapi": "3.1.0", "paths": {"/order/preview": {}}})
            elif self.path.startswith("/markets"):
                self._reply_json(
                    {
                        "ok": True,
                        "markets": [
                            {
                                "market_id": 4,
                                "symbol": "BTC-USD-PERP",
                                "kind": "perp",
                                "base_asset_id": 1,
                                "mark_price_ticks": 7_000_000,
                            }
                        ],
                    }
                )
            elif self.path.startswith("/book"):
                self._reply_json(
                    {
                        "ok": True,
                        "market_id": 4,
                        "bids": [[6_999_000, 10_000, 1]],
                        "asks": [[7_001_000, 10_000, 1]],
                    }
                )
            else:
                self._reply_json({"ok": True})

        def do_POST(self) -> None:
            clen = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(clen) if clen > 0 else b"{}"
            body = json.loads(raw_body.decode("utf-8"))
            if self.path.startswith("/auth/challenge"):
                self._reply_json({"ok": True, "nonce": "n3", "message": "Arena login n3"})
            elif self.path.startswith("/auth/wallet") or self.path.startswith("/auth/verify"):
                self._reply_json({"ok": True, "account_id": 99, "api_key": "k3", "api_secret": "s3"})
            elif self.path.startswith("/order/preview"):
                preview_calls.append(body)
                if accept_preview:
                    self._reply_json({"ok": True, "would_accept": True, "status": "ok"})
                else:
                    self._reply_json(
                        {"ok": True, "would_accept": False, "status": "reject_insufficient_funds_or_margin"}
                    )
            else:
                self._reply_json({"ok": True})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuickstartLoopback)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    try:
        base_u = f"http://127.0.0.1:{srv.server_port}"
        unfunded_out = run_quickstart(base_u, "BTC/USD:USD", dry_run=True, fund_faucet=False)
        assert unfunded_out.get("funding_hint") == FUNDING_HINT_MSG
        assert int(preview_calls[-1].get("price_ticks", 0)) == 6_860_000

        accept_preview = True
        funded_out = run_quickstart(base_u, "BTC/USD:USD", dry_run=True, fund_faucet=False)
        assert "funding_hint" not in funded_out
    finally:
        srv.shutdown()
        srv.server_close()

    # Verify empty /llms.txt guard and --fund-faucet with custom --arena-url (without --testnet)
    empty_llms = True
    faucet_hits = 0

    class _EdgeQuickstartLoopback(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def _reply_json(self, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/llms.txt"):
                raw = b"   \n\n" if empty_llms else b"\nArena Exchange v4.9\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif self.path.startswith("/openapi.json"):
                self._reply_json({"openapi": "3.1.0"})
            elif self.path.startswith("/markets"):
                self._reply_json(
                    {"ok": True, "markets": [{"market_id": 4, "symbol": "BTC-USD-PERP", "kind": "perp", "base_asset_id": 1, "mark_price_ticks": 1}]}
                )
            elif self.path.startswith("/book"):
                self._reply_json({"ok": True, "market_id": 4, "bids": [], "asks": []})
            else:
                self._reply_json({"ok": True})

        def do_POST(self) -> None:
            nonlocal faucet_hits
            clen = int(self.headers.get("Content-Length", "0"))
            if clen > 0:
                _ = self.rfile.read(clen)
            if self.path.startswith("/auth/challenge"):
                self._reply_json({"ok": True, "nonce": "n4", "message": "Arena login n4"})
            elif self.path.startswith("/auth/wallet") or self.path.startswith("/auth/verify"):
                self._reply_json({"ok": True, "account_id": 101, "api_key": "k4", "api_secret": "s4"})
            elif self.path.startswith("/faucet"):
                faucet_hits += 1
                self._reply_json({"ok": False, "error": "faucet_invoked_on_custom_url"})
            else:
                self._reply_json({"ok": True, "would_accept": True, "status": "ok"})

    assert (
        _compute_preview_limit_buy_price(
            [{"symbol": "BTC/USD:USD", "nativeSymbol": "BTC-USD-PERP", "info": {"mark_price_ticks": 1}}],
            "BTC/USD:USD",
        )
        == "0.01"
    )
    edge_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _EdgeQuickstartLoopback)
    edge_thr = threading.Thread(target=edge_srv.serve_forever, daemon=True)
    edge_thr.start()
    try:
        edge_u = f"http://127.0.0.1:{edge_srv.server_port}"
        caught_empty_llms = False
        try:
            _ = run_quickstart(edge_u, "BTC/USD:USD")
        except RuntimeError as llms_err:
            caught_empty_llms = "empty discovery" in str(llms_err)
        assert caught_empty_llms
        empty_llms = False
        caught_custom_faucet = False
        try:
            _ = main(["--arena-url", edge_u, "--fund-faucet"])
        except RuntimeError as cf_err:
            caught_custom_faucet = "faucet_invoked_on_custom_url" in str(cf_err)
        assert caught_custom_faucet and faucet_hits == 1
    finally:
        edge_srv.shutdown()
        edge_srv.server_close()

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
    ap.add_argument(
        "--fund-faucet",
        action="store_true",
        help="Drip 10,000 USD + gas via /faucet and deposit margin on-chain before preview/execute",
    )
    ap.add_argument("--execute", action="store_true", help="Submit + cancel live PostOnly order if preview accepts")
    ap.add_argument("--self-test", action="store_true", help="Run offline deterministic client self-test")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    eff_url = PUBLIC_TESTNET_URL if args.testnet else args.arena_url
    out = run_quickstart(
        eff_url,
        args.symbol,
        dry_run=(not args.execute),
        fund_faucet=bool(args.fund_faucet),
    )
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
