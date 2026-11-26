#!/usr/bin/env python3
"""
Arena Exchange v4.9 — Client-Side Quantitative Two-Sided Market-Maker Starter
(`examples/algo_two_sided_quoter.py`)

External client-side SDK example (zero privileged endpoints; 100% neutral arena).
Demonstrates:
  1. Configuring Market-Maker Protection (`POST /account/mmp`) with automatic quote trip
  2. Computing fair-value midpoints and inventory-aware `auto_skew_ticks` quotes
  3. Atomic single-RTT two-sided quote replacement (`quote_replace` via HTTP or 64B TCP wire)
     preserving L3 FIFO queue priority when price/peg matches
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SDK_DIR = Path(__file__).resolve().parent.parent / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from arena_sdk import (  # noqa: E402
    PUBLIC_TESTNET_URL,
    ArenaHttpClient,
    EthWalletSigner,
    base_to_qty_lots,
    usd_to_price_ticks,
)


def compute_two_sided_ticks(
    mid_ticks: int,
    half_spread_ticks: int,
    net_pos_lots: int = 0,
    skew_ticks_per_10k_lots: int = 10,
) -> Tuple[int, int]:
    if mid_ticks <= 0 or half_spread_ticks <= 0:
        raise ValueError("mid_ticks and half_spread_ticks must be > 0")
    inv_shift = (int(net_pos_lots) * int(skew_ticks_per_10k_lots)) // 10_000
    center = int(mid_ticks) - inv_shift
    bid_px = max(1, center - int(half_spread_ticks))
    ask_px = max(bid_px + 1, center + int(half_spread_ticks))
    return bid_px, ask_px


def run_quoter(
    arena_url: str,
    market_id: int,
    wallet_privkey: str,
    quote_size_base: str = "0.0500",
    half_spread_usd: str = "2.50",
    cycles: int = 1,
    interval_sec: float = 1.0,
    dry_run: bool = True,
) -> List[Dict[str, Any]]:
    qty_lots = base_to_qty_lots(quote_size_base)
    half_spread_ticks = usd_to_price_ticks(half_spread_usd)
    signer = EthWalletSigner(wallet_privkey) if wallet_privkey else EthWalletSigner()
    http = ArenaHttpClient(arena_url, timeout=5.0)
    reports: List[Dict[str, Any]] = []
    try:
        login = http.login_with_wallet(signer)
        if not login.get("ok"):
            raise RuntimeError(f"Wallet login failed: {login}")
        aid = int(login["account_id"])
        if not dry_run:
            http.configure_mmp(
                account_id=aid,
                window_wal_seqs=100,
                max_fill_lots=qty_lots * 10,
                max_delta_lots=qty_lots * 6,
                cooldown_wal_seqs=50,
            )

        for step in range(max(1, int(cycles))):
            book = http.book(market_id, depth=1)
            acct = http.account(aid)
            mark_t = int(book.get("mark_price_ticks", 0))
            bb_t = int(book.get("best_bid_ticks", 0))
            ba_t = int(book.get("best_ask_ticks", 0))
            mid_t = ((bb_t + ba_t) // 2) if (bb_t > 0 and ba_t > bb_t) else max(10_000, mark_t)
            pos_lots = 0
            for pos in list(acct.get("perp_positions", [])):
                if int(pos.get("market_id", 0)) == market_id:
                    pos_lots = int(pos.get("position_lots", 0))
            bid_t, ask_t = compute_two_sided_ticks(mid_t, half_spread_ticks, pos_lots, 15)
            if dry_run:
                prev_b = http.preview_order(
                    account_id=aid,
                    market_id=market_id,
                    side="bid",
                    price_ticks=bid_t,
                    qty_lots=qty_lots,
                    tif="post_only",
                    post_only_slide=True,
                )
                reports.append(
                    {
                        "step": step,
                        "dry_run": True,
                        "account_id": aid,
                        "bid_ticks": bid_t,
                        "ask_ticks": ask_t,
                        "qty_lots": qty_lots,
                        "bid_preview": prev_b,
                    }
                )
            else:
                q_res = http.quote_replace(
                    account_id=aid,
                    market_id=market_id,
                    bid_price_ticks=bid_t,
                    bid_qty_lots=qty_lots,
                    ask_price_ticks=ask_t,
                    ask_qty_lots=qty_lots,
                    tif="post_only",
                    post_only_slide=True,
                    auto_skew_ticks=15,
                )
                reports.append(q_res)
            if step + 1 < cycles:
                time.sleep(max(0.05, float(interval_sec)))
        return reports
    finally:
        http.close()


def _run_self_test() -> int:
    b0, a0 = compute_two_sided_ticks(5_000_000, 250, net_pos_lots=0, skew_ticks_per_10k_lots=20)
    b_long, a_long = compute_two_sided_ticks(5_000_000, 250, net_pos_lots=10_000, skew_ticks_per_10k_lots=20)
    assert b0 == 4_999_750 and a0 == 5_000_250
    assert b_long == 4_999_730 and a_long == 5_000_230
    assert Decimal("0.0500") > 0 and base_to_qty_lots("0.0500") == 500
    print("[PASS] algo_two_sided_quoter.py client self-test OK")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Arena Exchange Client-Side Two-Sided Quoter Starter")
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
    ap.add_argument("--market-id", type=int, default=4)
    ap.add_argument("--wallet-privkey", default="")
    ap.add_argument("--quote-size-base", default="0.0500")
    ap.add_argument("--half-spread-usd", default="2.50")
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--interval-sec", type=float, default=1.0)
    ap.add_argument("--live", action="store_true", help="Send live quote_replace instead of preview dry-run")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    rep = run_quoter(
        arena_url=(PUBLIC_TESTNET_URL if args.testnet else args.arena_url),
        market_id=args.market_id,
        wallet_privkey=args.wallet_privkey,
        quote_size_base=args.quote_size_base,
        half_spread_usd=args.half_spread_usd,
        cycles=args.cycles,
        interval_sec=args.interval_sec,
        dry_run=(not args.live),
    )
    print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
