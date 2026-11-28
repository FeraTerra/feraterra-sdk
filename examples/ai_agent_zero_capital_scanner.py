#!/usr/bin/env python3
"""
Arena Exchange v4.9 — Client-Side Autonomous Zero-Capital AI Agent Scanner
(`examples/ai_agent_zero_capital_scanner.py`)

External client-side SDK example demonstrating how an autonomous AI agent with $0
pre-existing margin can onboard via EIP-191 wallet auth, discover capabilities from
`GET /llms.txt`, and scan for:
  1. Zero-Pre-Margin Atomic Flash Arbitrage (`POST /flash_arb`) on Bonding-Curve
     Spot or `BoundedClaim` markets when L3 BBO diverges from primary mint/redeem parity
  2. Zero-Capital Autonomous Liquidation Bounties (`POST /auto_liquidate` with
     `flash_offload_to_book=True`)
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
    ArenaHttpClient,
    EthWalletSigner,
    usd_to_micro,
)


def _bonding_curve_reserve_micro(
    base_price_ticks: int,
    slope_ticks_per_unit: int,
    supply_lots: int,
    max_price_ticks: int = 1 << 46,
) -> Optional[int]:
    if base_price_ticks <= 0 or slope_ticks_per_unit < 0 or max_price_ticks <= 0 or supply_lots < 0:
        return None
    if supply_lots == 0:
        return 0
    if base_price_ticks >= max_price_ticks:
        return max_price_ticks * supply_lots
    s_ramp = supply_lots
    s_flat = 0
    if slope_ticks_per_unit > 0:
        s_cap = ((max_price_ticks - base_price_ticks) * 10_000) // slope_ticks_per_unit
        if supply_lots > s_cap:
            s_ramp = s_cap
            s_flat = supply_lots - s_cap
    lin = base_price_ticks * s_ramp
    quad = ((slope_ticks_per_unit * s_ramp * s_ramp) // 20_000) if (slope_ticks_per_unit > 0 and s_ramp > 0) else 0
    flat = max_price_ticks * s_flat if s_flat > 0 else 0
    return lin + quad + flat


def evaluate_claim_flash_arb_opportunity(
    best_bid_ticks: int,
    best_ask_ticks: int,
    cap_ticks: int,
    qty_lots: int,
    *,
    resolved: bool = False,
    payout_ticks: int = 0,
) -> Optional[Dict[str, Any]]:
    _ = (best_ask_ticks, payout_ticks)
    if resolved or cap_ticks <= 0 or qty_lots <= 0:
        return None
    if best_bid_ticks > 0 and best_bid_ticks > cap_ticks:
        gross_micro = (best_bid_ticks - cap_ticks) * qty_lots
        return {"side": "bid", "qty_lots": qty_lots, "estimated_gross_profit_micro": gross_micro}
    return None


def evaluate_bonding_curve_flash_arb_opportunity(
    best_bid_ticks: int,
    best_bid_lots: int,
    best_ask_ticks: int,
    best_ask_lots: int,
    base_price_ticks: int,
    slope_ticks_per_unit: int = 0,
    supply_lots: int = 0,
    max_supply_lots: int = 0,
    max_price_ticks: int = 1 << 46,
    max_clip_lots: int = 100,
) -> Optional[Dict[str, Any]]:
    r_cur = _bonding_curve_reserve_micro(
        base_price_ticks, slope_ticks_per_unit, supply_lots, max_price_ticks
    )
    if r_cur is None:
        return None
    best_opp: Optional[Dict[str, Any]] = None

    if best_bid_ticks > 0 and best_bid_lots > 0:
        mint_cap = (max_supply_lots - supply_lots) if max_supply_lots > 0 else best_bid_lots
        q_bid = min(max_clip_lots, best_bid_lots, max(0, mint_cap))
        if q_bid > 0:
            r_nxt = _bonding_curve_reserve_micro(
                base_price_ticks, slope_ticks_per_unit, supply_lots + q_bid, max_price_ticks
            )
            if r_nxt is not None and r_nxt > r_cur:
                mint_cost = r_nxt - r_cur
                gross_bid = (best_bid_ticks * q_bid) - mint_cost
                if gross_bid > 0:
                    best_opp = {
                        "side": "bid",
                        "qty_lots": q_bid,
                        "estimated_gross_profit_micro": gross_bid,
                    }

    if best_ask_ticks > 0 and best_ask_lots > 0 and supply_lots > 0:
        q_ask = min(max_clip_lots, best_ask_lots, supply_lots)
        if q_ask > 0:
            r_prev = _bonding_curve_reserve_micro(
                base_price_ticks, slope_ticks_per_unit, supply_lots - q_ask, max_price_ticks
            )
            if r_prev is not None and r_cur >= r_prev:
                burn_payout = r_cur - r_prev
                gross_ask = burn_payout - (best_ask_ticks * q_ask)
                if gross_ask > 0 and (
                    best_opp is None or gross_ask > int(best_opp["estimated_gross_profit_micro"])
                ):
                    best_opp = {
                        "side": "ask",
                        "qty_lots": q_ask,
                        "estimated_gross_profit_micro": gross_ask,
                    }

    return best_opp


def scan_once(
    arena_url: str,
    wallet_privkey: str = "",
    min_profit_usd: str = "0.05",
    dry_run: bool = True,
) -> Dict[str, Any]:
    min_profit_micro = usd_to_micro(min_profit_usd, allow_zero=True)
    signer = EthWalletSigner(wallet_privkey) if wallet_privkey else EthWalletSigner()
    http = ArenaHttpClient(arena_url, timeout=5.0)
    try:
        spec_txt = http.llms_txt()
        login = http.login_with_wallet(signer)
        if not login.get("ok"):
            raise RuntimeError(f"Wallet login failed: {login}")
        aid = int(login["account_id"])
        mkts_resp = http.markets()
        if not isinstance(mkts_resp, dict) or not mkts_resp.get("ok"):
            raise RuntimeError(f"GET /markets failed: {mkts_resp}")
        candidates: List[Dict[str, Any]] = []
        executions: List[Dict[str, Any]] = []

        for m in list(mkts_resp.get("markets", [])):
            if str(m.get("trading_status", "live")).strip().lower() != "live":
                continue
            kind = str(m.get("kind", "")).strip().lower()
            mid = int(m["market_id"])
            bb_t = int(m.get("best_bid_ticks", 0))
            ba_t = int(m.get("best_ask_ticks", 0))
            bb_q = int(m.get("best_bid_lots", 0))
            ba_q = int(m.get("best_ask_lots", 0))
            opp: Optional[Dict[str, Any]] = None

            if kind in ("bounded_claim", "claim"):
                is_res = bool(m.get("claim_resolved", m.get("resolved", False)))
                if is_res or bb_t <= 0:
                    continue
                avail_q = bb_q
                if avail_q <= 0:
                    continue
                cap_t = int(m.get("claim_cap_ticks") or m.get("max_price_ticks") or 10_000)
                pay_t = int(m.get("claim_payout_ticks", m.get("resolved_payout_ticks", 0)))
                opp = evaluate_claim_flash_arb_opportunity(
                    bb_t,
                    ba_t,
                    cap_t,
                    min(100, avail_q),
                    resolved=is_res,
                    payout_ticks=pay_t,
                )
            elif kind == "spot" and bool(m.get("bonding_curve", False)):
                opp = evaluate_bonding_curve_flash_arb_opportunity(
                    best_bid_ticks=bb_t,
                    best_bid_lots=bb_q,
                    best_ask_ticks=ba_t,
                    best_ask_lots=ba_q,
                    base_price_ticks=int(m.get("curve_base_price_ticks", 0)),
                    slope_ticks_per_unit=int(m.get("curve_slope_ticks_per_unit", 0)),
                    supply_lots=int(m.get("synthetic_supply_lots", 0)),
                    max_supply_lots=int(m.get("max_supply_lots", 0)),
                    max_price_ticks=int(m.get("max_price_ticks") or (1 << 46)),
                )

            if opp is not None and int(opp["estimated_gross_profit_micro"]) >= min_profit_micro:
                opp["market_id"] = mid
                opp["symbol"] = m.get("symbol")
                candidates.append(opp)
                if not dry_run:
                    executions.append(
                        http.flash_arbitrage(
                            account_id=aid,
                            market_id=mid,
                            side=str(opp["side"]),
                            qty_lots=int(opp["qty_lots"]),
                            min_profit_micro=min_profit_micro,
                            is_market=True,
                        )
                    )

        if not dry_run:
            executions.append(
                http.auto_liquidate(
                    liquidator_account_id=aid,
                    market_id=0,
                    min_bounty_micro=min_profit_micro,
                    flash_offload_to_book=True,
                )
            )

        return {
            "ok": True,
            "dry_run": dry_run,
            "account_id": aid,
            "eth_address": signer.address,
            "llms_discovered": "/order/preview" in spec_txt,
            "flash_arb_candidates": candidates,
            "executions": executions,
        }
    finally:
        http.close()


def _run_self_test() -> int:
    none_opp = evaluate_claim_flash_arb_opportunity(9_999, 10_000, 10_000, 50)
    hit_opp = evaluate_claim_flash_arb_opportunity(10_050, 0, 10_000, 20)
    res_opp = evaluate_claim_flash_arb_opportunity(0, 9_800, 10_000, 10, resolved=True, payout_ticks=10_000)
    res_bid_opp = evaluate_claim_flash_arb_opportunity(10_500, 0, 10_000, 10, resolved=True, payout_ticks=10_000)
    bc_bid_opp = evaluate_bonding_curve_flash_arb_opportunity(10_150, 50, 0, 0, base_price_ticks=10_000, slope_ticks_per_unit=0, supply_lots=500)
    bc_ask_opp = evaluate_bonding_curve_flash_arb_opportunity(0, 0, 9_800, 40, base_price_ticks=10_000, slope_ticks_per_unit=0, supply_lots=500)
    assert none_opp is None
    assert hit_opp is not None and hit_opp["side"] == "bid" and hit_opp["estimated_gross_profit_micro"] == 1_000
    assert res_opp is None and res_bid_opp is None
    assert bc_bid_opp is not None and bc_bid_opp["side"] == "bid" and bc_bid_opp["estimated_gross_profit_micro"] == 7_500
    assert bc_ask_opp is not None and bc_ask_opp["side"] == "ask" and bc_ask_opp["estimated_gross_profit_micro"] == 8_000

    class _LoopbackHandler(http.server.BaseHTTPRequestHandler):
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
                raw = b"Arena Exchange /order/preview\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif self.path.startswith("/markets"):
                self._reply_json(
                    {
                        "ok": True,
                        "markets": [
                            {
                                "market_id": 101,
                                "symbol": "BTC-100K-YES",
                                "kind": "bounded_claim",
                                "claim_cap_ticks": 10_000,
                                "claim_resolved": False,
                                "best_bid_ticks": 10_500,
                                "best_ask_ticks": 0,
                                "best_bid_lots": 100,
                                "best_ask_lots": 0,
                            },
                            {
                                "market_id": 102,
                                "symbol": "AETHER-CURVE-SPOT",
                                "kind": "spot",
                                "bonding_curve": True,
                                "curve_base_price_ticks": 10_000,
                                "curve_slope_ticks_per_unit": 0,
                                "synthetic_supply_lots": 1_000,
                                "best_bid_ticks": 0,
                                "best_ask_ticks": 9_400,
                                "best_bid_lots": 0,
                                "best_ask_lots": 100,
                            },
                            {
                                "market_id": 103,
                                "symbol": "RESOLVED-CLAIM",
                                "kind": "bounded_claim",
                                "claim_cap_ticks": 10_000,
                                "claim_resolved": True,
                                "claim_payout_ticks": 10_000,
                                "best_bid_ticks": 10_500,
                                "best_ask_ticks": 9_400,
                                "best_bid_lots": 100,
                                "best_ask_lots": 100,
                            },
                            {
                                "market_id": 104,
                                "symbol": "ZERO-LOT-CLAIM",
                                "kind": "bounded_claim",
                                "claim_cap_ticks": 10_000,
                                "claim_resolved": False,
                                "best_bid_ticks": 10_500,
                                "best_ask_ticks": 0,
                                "best_bid_lots": 0,
                                "best_ask_lots": 0,
                            },
                        ],
                    }
                )
            else:
                self._reply_json({"ok": True})

        def do_POST(self) -> None:
            clen = int(self.headers.get("Content-Length", "0"))
            if clen > 0:
                _ = self.rfile.read(clen)
            if self.path.startswith("/auth/challenge"):
                self._reply_json({"ok": True, "nonce": "n1", "message": "Arena login n1"})
            else:
                self._reply_json({"ok": True, "account_id": 42, "api_key": "k1", "api_secret": "s1"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    try:
        scan_out = scan_once(f"http://127.0.0.1:{srv.server_port}", min_profit_usd="0.05", dry_run=True)
    finally:
        srv.shutdown()
        srv.server_close()
    assert scan_out["ok"] is True and len(scan_out["flash_arb_candidates"]) == 2
    assert {c["market_id"] for c in scan_out["flash_arb_candidates"]} == {101, 102}
    print("[PASS] ai_agent_zero_capital_scanner.py client self-test OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Arena Exchange Zero-Capital AI Agent Scanner")
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
    ap.add_argument("--wallet-privkey", default="")
    ap.add_argument("--min-profit-usd", default="0.05")
    ap.add_argument("--live", action="store_true", help="Execute flash_arbitrage and auto_liquidate sweeps")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    out = scan_once(
        arena_url=(PUBLIC_TESTNET_URL if args.testnet else args.arena_url),
        wallet_privkey=args.wallet_privkey,
        min_profit_usd=args.min_profit_usd,
        dry_run=(not args.live),
    )
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
