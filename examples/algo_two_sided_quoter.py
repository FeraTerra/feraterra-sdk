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
import contextlib
from decimal import Decimal
import http.server
import io
import json
import os
from pathlib import Path
import sys
import threading
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


_PEG_MODE_MAP: Dict[str, int] = {
    "0": 0,
    "none": 0,
    "1": 1,
    "primary": 1,
    "primary_peg": 1,
    "2": 2,
    "mid": 2,
    "mid_peg": 2,
    "midpoint": 2,
    "midpoint_peg": 2,
    "3": 3,
    "mark": 3,
    "mark_peg": 3,
    "4": 4,
    "trailing": 4,
    "trailing_peg": 4,
}

QUOTE_FUNDING_HINT = (
    "POST /quote rejected with reject_insufficient_funds_or_margin ($0 margin). "
    "Fund your wallet via POST /faucet "
    "(http.request_testnet_faucet(signer.address, amount='10000', asset='USD', drip_gas=True)) "
    "and http.deposit_onchain_margin(signer, '10000', account_id=aid, wait_for_credit=True), "
    "or run: python examples/quickstart_ccxt_and_preview.py --testnet --fund-faucet"
)


def parse_peg_mode(value: int | str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value <= 4:
            return value
        raise ValueError(f"peg_mode must be in 0..4, got {value}")
    key = str(value).strip().lower()
    if key in _PEG_MODE_MAP:
        return _PEG_MODE_MAP[key]
    raise ValueError(
        f"Unsupported peg_mode {value!r}; expected 0..4 or none|primary_peg|midpoint_peg|mark_peg|trailing_peg"
    )


def resolve_effective_peg_mode(
    testnet: bool,
    peg_mode_arg: Optional[int | str],
    auto_flip_ticks: int = 0,
) -> int:
    if peg_mode_arg is not None:
        return parse_peg_mode(peg_mode_arg)
    if testnet and int(auto_flip_ticks) <= 0:
        return 3  # mark_peg: track live oracle mark moves in C++ (0 ns)
    return 0


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
    peg_mode: int | str = 0,
    auto_flip_ticks: int = 0,
) -> List[Dict[str, Any]]:
    qty_lots = base_to_qty_lots(quote_size_base)
    half_spread_ticks = usd_to_price_ticks(half_spread_usd)
    eff_peg = parse_peg_mode(peg_mode)
    raw_flip = int(auto_flip_ticks)
    if not (0 <= raw_flip <= 500):
        raise ValueError(f"auto_flip_ticks must be in 0..500, got {raw_flip}")
    eff_flip = 0 if eff_peg > 0 else raw_flip
    eff_skew = 0 if (eff_peg > 0 or eff_flip > 0) else 15
    peg_off = max(1, min(500, half_spread_ticks)) if eff_peg > 0 else 0

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
            if not isinstance(book, dict) or not book.get("ok"):
                raise RuntimeError(f"GET /book failed for market_id={market_id}: {book}")
            acct = http.account(aid)
            if not isinstance(acct, dict) or not acct.get("ok"):
                raise RuntimeError(f"GET /account failed for account_id={aid}: {acct}")
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
                    price_ticks=(0 if eff_peg > 0 else bid_t),
                    qty_lots=qty_lots,
                    tif="post_only",
                    post_only_slide=True,
                    primary_peg=(eff_peg == 1),
                    midpoint_peg=(eff_peg == 2),
                    mark_peg=(eff_peg == 3),
                    trailing_peg=(eff_peg == 4),
                    peg_offset_ticks=(-peg_off if eff_peg > 0 else 0),
                    auto_flip_ticks=eff_flip,
                )
                step_rep: Dict[str, Any] = {
                    "step": step,
                    "dry_run": True,
                    "account_id": aid,
                    "bid_ticks": bid_t,
                    "ask_ticks": ask_t,
                    "qty_lots": qty_lots,
                    "peg_mode": eff_peg,
                    "auto_flip_ticks": eff_flip,
                    "bid_preview": prev_b,
                }
                if not prev_b.get("would_accept", True) and "insufficient" in str(
                    prev_b.get("status", "")
                ).lower():
                    step_rep["funding_hint"] = QUOTE_FUNDING_HINT
                reports.append(step_rep)
            else:
                try:
                    q_res = http.quote_replace(
                        account_id=aid,
                        market_id=market_id,
                        bid_price_ticks=(0 if eff_peg > 0 else bid_t),
                        bid_qty_lots=qty_lots,
                        ask_price_ticks=(0 if eff_peg > 0 else ask_t),
                        ask_qty_lots=qty_lots,
                        tif="post_only",
                        post_only_slide=True,
                        auto_skew_ticks=eff_skew,
                        auto_flip_ticks=eff_flip,
                        quote_peg_mode=eff_peg,
                        peg_offset_ticks=peg_off,
                    )
                except Exception as exc:
                    err_s = str(exc)
                    if (
                        "reject_insufficient_funds_or_margin" in err_s
                        or "unbonded_account" in err_s
                    ):
                        print(f"[HINT] {QUOTE_FUNDING_HINT}", file=sys.stderr)
                        reports.append(
                            {
                                "ok": False,
                                "status": "reject_insufficient_funds_or_margin",
                                "error": err_s,
                                "funding_hint": QUOTE_FUNDING_HINT,
                            }
                        )
                        break
                    raise
                q_status = str(q_res.get("status") or q_res.get("error") or "")
                if not q_res.get("ok", True) and (
                    "reject_insufficient_funds_or_margin" in q_status
                    or "unbonded_account" in q_status
                ):
                    q_out = dict(q_res)
                    q_out["funding_hint"] = QUOTE_FUNDING_HINT
                    print(f"[HINT] {QUOTE_FUNDING_HINT}", file=sys.stderr)
                    reports.append(q_out)
                    break
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
    assert resolve_effective_peg_mode(False, None, 0) == 0
    assert resolve_effective_peg_mode(True, None, 0) == 3
    assert resolve_effective_peg_mode(True, "0", 0) == 0
    assert resolve_effective_peg_mode(True, None, 20) == 0
    assert parse_peg_mode("mark_peg") == 3

    quote_payloads: List[Dict[str, Any]] = []
    reject_next_quote = False

    class _QuoterLoopback(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def _reply_json(self, code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/book"):
                self._reply_json(
                    200,
                    {
                        "ok": True,
                        "mark_price_ticks": 7_000_000,
                        "best_bid_ticks": 6_999_000,
                        "best_ask_ticks": 7_001_000,
                    },
                )
            elif self.path.startswith("/account"):
                self._reply_json(200, {"ok": True, "perp_positions": []})
            else:
                self._reply_json(200, {"ok": True})

        def do_POST(self) -> None:
            clen = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(clen) if clen > 0 else b"{}"
            body = json.loads(raw_body.decode("utf-8"))
            if self.path.startswith("/auth/challenge"):
                self._reply_json(200, {"ok": True, "nonce": "n2", "message": "Arena login n2"})
            elif self.path.startswith("/auth/wallet") or self.path.startswith("/auth/verify"):
                self._reply_json(200, {"ok": True, "account_id": 77, "api_key": "k2", "api_secret": "s2"})
            elif self.path.startswith("/quote"):
                quote_payloads.append(body)
                if reject_next_quote:
                    self._reply_json(400, {"ok": False, "status": "reject_insufficient_funds_or_margin"})
                else:
                    self._reply_json(200, {"ok": True, "status": "ok"})
            else:
                self._reply_json(200, {"ok": True})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuoterLoopback)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    try:
        base_u = f"http://127.0.0.1:{srv.server_port}"
        rep_def = run_quoter(base_u, 4, "", dry_run=False)
        assert rep_def[0]["ok"] is True
        assert int(quote_payloads[-1].get("quote_peg_mode", 0)) == 0
        assert int(quote_payloads[-1].get("auto_skew_ticks", 0)) == 15
        assert int(quote_payloads[-1].get("auto_flip_ticks", 0)) == 0

        rep_peg = run_quoter(base_u, 4, "", dry_run=False, peg_mode=3)
        assert rep_peg[0]["ok"] is True
        assert int(quote_payloads[-1].get("quote_peg_mode", 0)) == 3
        assert int(quote_payloads[-1].get("peg_offset_ticks", 0)) == 250
        assert int(quote_payloads[-1].get("bid_price_ticks", 0)) == 0
        assert int(quote_payloads[-1].get("ask_price_ticks", 0)) == 0
        assert int(quote_payloads[-1].get("auto_skew_ticks", 0)) == 0

        rep_flip = run_quoter(base_u, 4, "", dry_run=False, peg_mode=0, auto_flip_ticks=20)
        assert rep_flip[0]["ok"] is True
        assert int(quote_payloads[-1].get("quote_peg_mode", 0)) == 0
        assert int(quote_payloads[-1].get("auto_flip_ticks", 0)) == 20
        assert int(quote_payloads[-1].get("auto_skew_ticks", 0)) == 0

        reject_next_quote = True
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rep_rej = run_quoter(base_u, 4, "", cycles=3, dry_run=False, peg_mode=3)
        assert len(rep_rej) == 1
        assert "/faucet" in rep_rej[0].get("funding_hint", "")
        assert "deposit_onchain_margin" in rep_rej[0].get("funding_hint", "")
        assert "/faucet" in err_buf.getvalue() and "deposit_onchain_margin" in err_buf.getvalue()
    finally:
        srv.shutdown()
        srv.server_close()

    # Verify failed book / account responses raise RuntimeError instead of quoting $100 fallback mid
    fail_book = True

    class _FailBookAcctLoopback(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def _reply_json(self, code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/book"):
                if fail_book:
                    self._reply_json(200, {"ok": False, "error": "invalid_market"})
                else:
                    self._reply_json(200, {"ok": True, "mark_price_ticks": 7_000_000})
            elif self.path.startswith("/account"):
                self._reply_json(200, {"ok": False, "error": "unauthorized"})
            else:
                self._reply_json(200, {"ok": True})

        def do_POST(self) -> None:
            clen = int(self.headers.get("Content-Length", "0"))
            if clen > 0:
                _ = self.rfile.read(clen)
            if self.path.startswith("/auth/challenge"):
                self._reply_json(200, {"ok": True, "nonce": "n9", "message": "Arena login n9"})
            else:
                self._reply_json(200, {"ok": True, "account_id": 77, "api_key": "k9", "api_secret": "s9"})

    fail_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FailBookAcctLoopback)
    fail_thr = threading.Thread(target=fail_srv.serve_forever, daemon=True)
    fail_thr.start()
    try:
        fail_u = f"http://127.0.0.1:{fail_srv.server_port}"
        caught_book_err = False
        try:
            _ = run_quoter(fail_u, 999, "", dry_run=True)
        except RuntimeError as b_err:
            caught_book_err = "GET /book failed" in str(b_err)
        assert caught_book_err
        fail_book = False
        caught_acct_err = False
        try:
            _ = run_quoter(fail_u, 4, "", dry_run=True)
        except RuntimeError as a_err:
            caught_acct_err = "GET /account failed" in str(a_err)
        assert caught_acct_err
    finally:
        fail_srv.shutdown()
        fail_srv.server_close()

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
    ap.add_argument(
        "--peg-mode",
        default=None,
        help="Quote peg mode: 0=none (local default), 1=primary_peg, 2=midpoint_peg, 3=mark_peg (--testnet default), 4=trailing_peg",
    )
    ap.add_argument(
        "--auto-flip-ticks",
        type=int,
        default=0,
        help="Optional 0 ns ping-pong auto-replenish offset in ticks (e.g. 20; used when peg_mode=0)",
    )
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--interval-sec", type=float, default=1.0)
    ap.add_argument("--live", action="store_true", help="Send live quote_replace instead of preview dry-run")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    eff_peg_mode = resolve_effective_peg_mode(
        testnet=bool(args.testnet),
        peg_mode_arg=args.peg_mode,
        auto_flip_ticks=args.auto_flip_ticks,
    )
    rep = run_quoter(
        arena_url=(PUBLIC_TESTNET_URL if args.testnet else args.arena_url),
        market_id=args.market_id,
        wallet_privkey=args.wallet_privkey,
        quote_size_base=args.quote_size_base,
        half_spread_usd=args.half_spread_usd,
        cycles=args.cycles,
        interval_sec=args.interval_sec,
        dry_run=(not args.live),
        peg_mode=eff_peg_mode,
        auto_flip_ticks=args.auto_flip_ticks,
    )
    print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
