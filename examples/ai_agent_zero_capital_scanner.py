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
    ArenaHttpClient,
    EthWalletSigner,
    usd_to_micro,
)


def evaluate_claim_flash_arb_opportunity(
    best_bid_ticks: int,
    best_ask_ticks: int,
    cap_ticks: int,
    qty_lots: int,
    *,
    resolved: bool = False,
    payout_ticks: int = 0,
) -> Optional[Dict[str, Any]]:
    if cap_ticks <= 0 or qty_lots <= 0:
        return None
    if best_bid_ticks > cap_ticks:
        gross_micro = (best_bid_ticks - cap_ticks) * qty_lots
        return {"side": "bid", "qty_lots": qty_lots, "estimated_gross_profit_micro": gross_micro}
    if resolved and payout_ticks > 0 and 0 < best_ask_ticks < payout_ticks:
        gross_micro = (payout_ticks - best_ask_ticks) * qty_lots
        return {"side": "ask", "qty_lots": qty_lots, "estimated_gross_profit_micro": gross_micro}
    return None


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
        candidates: List[Dict[str, Any]] = []
        executions: List[Dict[str, Any]] = []

        for m in list(mkts_resp.get("markets", [])):
            kind = str(m.get("kind", "")).lower()
            if kind != "bounded_claim":
                continue
            mid = int(m["market_id"])
            cap_t = int(m.get("claim_cap_ticks") or m.get("max_price_ticks") or 10_000)
            bb_t = int(m.get("best_bid_ticks", 0))
            ba_t = int(m.get("best_ask_ticks", 0))
            bb_q = int(m.get("best_bid_lots", 0))
            ba_q = int(m.get("best_ask_lots", 0))
            is_res = bool(m.get("resolved", False))
            pay_t = int(m.get("resolved_payout_ticks", 0))
            avail_q = ba_q if (is_res and pay_t > 0 and 0 < ba_t < pay_t) else bb_q
            opp = evaluate_claim_flash_arb_opportunity(
                bb_t,
                ba_t,
                cap_t,
                min(100, max(1, avail_q)),
                resolved=is_res,
                payout_ticks=pay_t,
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
    assert none_opp is None
    assert hit_opp is not None and hit_opp["side"] == "bid" and hit_opp["estimated_gross_profit_micro"] == 1_000
    assert res_opp is not None and res_opp["side"] == "ask" and res_opp["estimated_gross_profit_micro"] == 2_000
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
