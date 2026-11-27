"""
Arena Exchange v4.9 — Official Headless HFT, Algo & Autonomous AI Python SDK (`sdk/python/arena_sdk.py`)

Provides zero-dependency clients for:
  1. Ultra-low-latency 64-byte binary `ArenaWireFrame` TCP (`TCP_NODELAY`,
     including deadlock-free pipelined `send_batch`), UDP, `SetCancelOnDisconnect`
     (`0xB`), atomic `TwoSidedQuoteReplace` (`0xC`), 2..4-leg `AtomicSpread` /
     `AtomicBasket` (`0xD`), auto-skewing inventory quotes (`auto_skew_ticks`),
     dark-midpoint zero-impact orders (`dark_midpoint`), OCO bracket orders
     (`oco_linked`), signed offset pegs (`peg_offset_ticks`), one-way ratchet
     trailing pegs (`trailing_peg`), native pegged quotes (`quote_peg_mode`),
     Prime-Brokerage sub-account linking, internal transfers & Cross-Sub-Account
     Analytic Jacobian Portfolio Delta-Netting (`link_sub_account`,
     `prime_internal_transfer`), autonomous cross-market arb sweeps
     (`auto_cross_arb`), Autonomous Zero-Capital Liquidation & Backstop Sweeper
     (`auto_liquidate`), Volume-Participation Dynamic Iceberg Auto-Reload
     (`display_qty_lots > 0 and jit_elastic_mult >= 2`), Deterministic `Keccak-256`
     Binary State Snapshots (`save_wal_snapshot`, `get_wal_snapshot`), Good-Til-Sequence
     auto-expiry (`max_lifetime_wal_seqs`), opt-in portfolio drawdown kill-switch
     (`set_account_drawdown_stop`), and collateral-bonded admission
     (`WireStatusCode.REJECT_UNBONDED = 0x0E`).
  2. Binary 64-byte `ArenaITCH` (`v1` wire format, v4.9 capability set) tick-by-tick
     L3 market-data feed client (`ArenaItchClient`) with 16-byte `"AIRQ"`
     snapshot/gap-replay subscription, deterministic L3/L2 FIFO book reconstructor
     (`ItchOrderBookReconstructor`), and rolling 256-bit `Keccak-256`
     `LEDGER_CHECKPOINT` (`0x09`) tracking.
  3. Ethereum `Keccak-256`, EIP-55, EIP-191 `personal_sign`, Yellow-Paper RLP,
     EIP-155 / EIP-1559 raw transaction signing, SEC2 `secp256k1` signing &
     `ecrecover` (`EthWalletSigner`), zero-dependency ERC-20 & `Clearinghouse`
     on-chain margin deposit / withdrawal-voucher claim helpers, Sovereign
     Execution Ledger tip verification (`compute_ledger_tip_digest`,
     `verify_ledger_tip`), and `HMAC-SHA256`.
  4. Headless HTTP/1.1 JSON REST (`GET /`, `GET /llms.txt`, `GET /openapi.json`,
     `POST /order/preview`, `POST /faucet`, `GET /ledger/tip`, `POST /spread`,
     `POST /basket`, `POST /claim/resolve`, `POST /quote`, Auth, On-Chain Deposit
     Indexing, Withdrawal Vouchers, Settlement Batch & Market-Data API), CCXT
     drop-in adapter (`ArenaCcxtAdapter` with `camelCase` & `snake_case` parity),
     and Real-Time RFC-6455 WebSocket Streaming (`ArenaWebSocketClient` /
     `ArenaWsClient`: `{"op":"order_preview"}`, `{"op":"quote"}`, `{"op":"spread"}`,
     `{"op":"basket"}`, `{"op":"resolve_claim"}`).
"""
from __future__ import annotations

import base64
from collections import deque
import contextlib
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import math
import os
import secrets
import select
import selectors
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import weakref
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from pathlib import Path
from typing import Any, Deque, Dict, Iterator, List, Optional, Sequence

__version__ = "4.9.4"
TICK_SIZE = 4
ARENA_WIRE_BYTES = 64
MASK50 = (1 << 50) - 1
MASK64 = 0xFFFF_FFFF_FFFF_FFFF
MIN_WIRE_PRICE_TICKS_48 = -140_737_488_355_328
MAX_WIRE_PRICE_TICKS_48 = 140_737_488_355_327
PRICE_TICKS_PER_USD = Decimal("100")
LOTS_PER_BASE_UNIT = Decimal("10000")
MICRO_USD_PER_DOLLAR = Decimal("1000000")
DEFAULT_KEY_LO64 = 0x0123_4567_89AB_CDEF
DEFAULT_KEY_HI64 = 0xCAFE_BABE_DEAD_BEEF
DEFAULT_SEQ_HI50 = 1

DEFAULT_LOCAL_HTTP_URL = "http://127.0.0.1:8080"
DEFAULT_LOCAL_WS_URL = "ws://127.0.0.1:8080/ws"
PUBLIC_DOMAIN = "feraterra.app"
PUBLIC_TESTNET_URL = "https://testnet.feraterra.app"
PUBLIC_TESTNET_WS_URL = "wss://testnet.feraterra.app/ws"
PUBLIC_MAINNET_URL = "https://api.feraterra.app"
PUBLIC_MAINNET_WS_URL = "wss://api.feraterra.app/ws"
PUBLIC_TESTNET_CHAIN_ID = 84532


def http_url_to_ws_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(str(url or DEFAULT_LOCAL_HTTP_URL).strip())
    scheme_map = {"https": "wss", "http": "ws", "wss": "wss", "ws": "ws"}
    ws_scheme = scheme_map.get(parsed.scheme.lower(), "ws")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/ws"
    elif not path.endswith("/ws"):
        path = f"{path}/ws"
    return urllib.parse.urlunsplit((ws_scheme, parsed.netloc, path, parsed.query, ""))


def _validate_price_ticks_48(price_ticks: int, field_name: str = "price_ticks") -> int:
    px = int(price_ticks)
    if not (MIN_WIRE_PRICE_TICKS_48 <= px <= MAX_WIRE_PRICE_TICKS_48):
        raise ValueError(
            f"{field_name} {px} out of signed 48-bit range "
            f"[{MIN_WIRE_PRICE_TICKS_48}, {MAX_WIRE_PRICE_TICKS_48}]"
        )
    return px


class BaseOp(IntEnum):
    NEW_ORDER = 0x0
    CANCEL = 0x1
    MODIFY_IN_PLACE = 0x2
    CANCEL_ALL_ACCOUNT = 0x3
    DEPOSIT_COLLATERAL = 0x4
    WITHDRAW_COLLATERAL = 0x5
    QUERY_BOOK_BBO = 0x6
    QUERY_ACCOUNT = 0x7
    UPDATE_MARK_FUNDING = 0x8
    LIQUIDATE_ACCOUNT = 0x9
    REGISTER_SESSION_KEY = 0xA
    SET_CANCEL_ON_DISCONNECT = 0xB
    TWO_SIDED_QUOTE_REPLACE = 0xC
    ATOMIC_SPREAD = 0xD
    MINT_REDEEM_SET = 0xE
    HEARTBEAT = 0xF


class OrderSide(IntEnum):
    BID = 0
    ASK = 1


class TimeInForce(IntEnum):
    GTC = 0
    IOC = 1
    FOK = 2
    POST_ONLY = 3


class StpMode(IntEnum):
    CANCEL_RESTING = 0
    CANCEL_INCOMING = 1
    CANCEL_BOTH = 2
    NONE = 3


class WireStatusCode(IntEnum):
    OK = 0x00
    REJECT_INVALID_MAC = 0x01
    REJECT_REPLAY_OR_STALE = 0x02
    REJECT_SESSION_CAP = 0x03
    REJECT_INVALID_OP = 0x04
    REJECT_INVALID_MARKET = 0x05
    REJECT_INVALID_PARAMS = 0x06
    REJECT_INSUFFICIENT = 0x07
    REJECT_ORDER_NOT_FOUND = 0x08
    REJECT_UNAUTHORIZED = 0x09
    REJECT_POST_ONLY_CROSS = 0x0A
    REJECT_FOK_UNFILLABLE = 0x0B
    REJECT_NOT_LIQUIDATABLE = 0x0C
    REJECT_WAL_IO_ERROR = 0x0D
    REJECT_UNBONDED = 0x0E
    REJECT_RISK_LIMIT = 0x0F


class WireOrderStatus(IntEnum):
    NONE = 0x00
    RESTING = 0x01
    PARTIALLY_FILLED = 0x02
    FILLED = 0x03
    CANCELED = 0x04
    MODIFIED = 0x05
    REJECTED = 0x06


LIQ_AUX1_FLAG_SET_KNOCKOUT = 1 << 0
LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE = 1 << 1
LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT = 1 << 2
LIQ_AUX1_FLAG_AUTO_CROSS_ARB = 1 << 3
LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP = 1 << 4
LIQ_AUX1_FLAG_NO_OFFLOAD = 1 << 62
MODIFY_AUX_FLAG_KEEP_PRIORITY = 1 << 0
CANCEL_ALL_FLAG_BID_ONLY = 1 << 62
CANCEL_ALL_FLAG_ASK_ONLY = 1 << 63
CANCEL_ALL_TAG_MASK = 0x3FFF_FFFF_FFFF_FFFF
WIRE_EXT51_FLAG_LADDER_BY_TAG = 0x01
WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL = 0x02
WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP = 0x04
MAX_PRIORITY_FEE_PPM = 50_000
MAX_EXPRESS_SURPLUS_BID_BPS = 5_000
MAX_LIQ_BOUNTY_REBATE_BID_BPS = 10_000
MAX_EXPRESS_PORT_LEASE_EPOCHS = 1_051_200
MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO = 1_000
MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO = 10_000_000_000
HEARTBEAT_AUX0_SYNC_SEQ = 0x5359_4E43_5F53_4551
MARK_AUX1_FLAG_DISTRIBUTE_YIELD = 1 << 0
MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT = 1 << 1
MARK_AUX1_FLAG_LINK_SUB_ACCOUNT = 1 << 2
MARK_AUX1_FLAG_SUB_TRANSFER = 1 << 3
MARK_AUX1_FLAG_SAVE_SNAPSHOT = 1 << 4
MARK_AUX1_FLAG_SWEEP_INSURANCE = 1 << 5
MARK_AUX1_FLAG_HARVEST_FLOAT_YIELD = 1 << 6
MARK_AUX1_FLAG_HARVEST_SPOT_REPO = 1 << 7
MARK_AUX1_FLAG_HARVEST_USD_REPO = 1 << 8
MARK_AUX1_FLAG_BIND_BUILDER = 1 << 9
MARK_AUX1_FLAG_CONFIG_MMP = 1 << 10
MARK_AUX1_FLAG_CONFIG_PAYOUT = 1 << 11
MARK_AUX1_FLAG_BASE_YIELD = 1 << 12
MARK_AUX1_FLAG_CONFIG_AUTO_REPO = 1 << 13
MARK_AUX1_FLAG_FUND_MARKET_VAULT = 1 << 14
MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES = 1 << 15
MARK_AUX1_FLAG_DEFAULT_INCENTIVES = 1 << 16
MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT = 1 << 17
INCENTIVE_PILLAR_SUPERCHARGE = 0x01
INCENTIVE_PILLAR_AUTO_YIELD_DRIP = 0x02
INCENTIVE_PILLAR_AUTO_REPO = 0x04
INCENTIVE_PILLAR_NOTIONAL_BBO = 0x08
INCENTIVE_PILLAR_TWO_SIDED_BONUS = 0x10
INCENTIVE_PILLAR_CLAIM_COLLATERAL = 0x20
INCENTIVE_PILLAR_ITCH_PRIVACY = 0x40
INCENTIVE_PILLAR_MACRO_AND_BASIS = 0x80
INCENTIVE_PILLARS_ALL_ON = 0xFF
PAYOUT_FLAG_AUTO_REPAY_BORROW = 0x01
PAYOUT_FLAG_COMPOUND_BONDING_CURVE = 0x02
PAYOUT_FLAG_AUTO_COMPOUND_QUOTES = 0x04
MINT_AUX1_FLAG_FLASH_ARB = 1 << 0
MINT_AUX1_FLAG_FLASH_MARKET = 1 << 1


MAX_WIRE_HEADER_QTY_LOTS = 0xFF_FFFF_FFFF
MAX_WIRE_EXT_QTY_LOTS = 0x0003_FFFF_FFFF_FFFF
MAX_WIRE_BASKET_LEG24_QTY_LOTS = 0x00FF_FFFF
MIN_WIRE_BASKET_LEG34_PRICE_TICKS = -2_147_483_648
MAX_WIRE_BASKET_LEG34_PRICE_TICKS = 2_147_483_647


def anonymize_itch_account_id(
    account_id: int,
    key_lo64: int = 0,
    key_hi64: int = 0,
    epoch_salt_nonce: int = 0,
) -> int:
    aid = int(account_id) & 0xFFFF_FFFF
    if aid == 0:
        return 0
    k_lo = int(key_lo64) & MASK64
    k_hi = int(key_hi64) & MASK64
    salt = int(epoch_salt_nonce) & MASK64
    if salt != 0:
        k_lo = (k_lo ^ ((salt * 0x9E37_79B9_7F4A_7C15) & MASK64)) & MASK64
        k_hi = (k_hi ^ ((salt * 0xBF58_476D_1CE4_E5B9) & MASK64)) & MASK64
    if k_lo == 0 and k_hi == 0:
        z = (aid + 0x9E37_79B9_7F4A_7C15) & MASK64
        z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
        return ((z ^ (z >> 31)) | (1 << 63)) & MASK64
    m = ((4 << 56) | aid) & MASK64
    v0 = (k_lo ^ 0x736F6D6570736575) & MASK64
    v1 = (k_hi ^ 0x646F72616E646F6D) & MASK64
    v2 = (k_lo ^ 0x6C7967656E657261) & MASK64
    v3 = (k_hi ^ 0x7465646279746573 ^ m) & MASK64
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= m
    v2 ^= 0xFF
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    return ((v0 ^ v1 ^ v2 ^ v3) | (1 << 63)) & MASK64


ORDER_AUX_FLAG_REDUCE_ONLY = 1 << 0
ORDER_AUX_FLAG_MARKET = 1 << 1
ORDER_FLAG_MARKET = ORDER_AUX_FLAG_MARKET
ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT = 1 << 2
ORDER_AUX_FLAG_POST_ONLY_SLIDE = 1 << 3
ORDER_AUX_FLAG_PRIMARY_PEG = 1 << 4
ORDER_AUX_FLAG_MIDPOINT_PEG = 1 << 5
ORDER_AUX_FLAG_MARK_PEG_COMBO = ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG
ORDER_AUX_FLAG_MARGIN_SPOT = 1 << 6
ORDER_AUX_FLAG_ICEBERG = 1 << 7
ORDER_AUX_AUTO_SKEW_SHIFT = 8
ORDER_AUX_AUTO_SKEW_MASK = 0x03FF
ORDER_AUX_AUTO_FLIP_BIT = 0x0200
ORDER_AUX_AUTO_FLIP_MASK = 0x01FF
ORDER_AUX_PEG_OFFSET_MASK = 0x03FF
ORDER_AUX_FLAG_OCO_LINKED = 1 << 18
ORDER_AUX_FLAG_TRAILING_PEG = ORDER_AUX_FLAG_MARK_PEG_COMBO | ORDER_AUX_FLAG_ICEBERG
ORDER_AUX_FLAG_GTS_EXPIRY = 1 << 19
ORDER_AUX_JIT_MULT_SHIFT = 20
ORDER_AUX_JIT_MULT_MASK = 0x0F
ORDER_AUX_MIN_QTY_SHIFT = 24
ORDER_AUX_MIN_QTY_MASK = 0xFF_FFFF_FFFF
ORDER_AUX_MIN_QTY_GTS_MASK = 0x00_00FF_FFFF
ORDER_AUX_GTS_SHIFT = 48
ORDER_AUX_GTS_MASK = 0xFFFF
QUOTE_AUX_QTY_MASK = 0x07_FFFF_FFFF
QUOTE_AUX_HI16_SHIFT = 35
QUOTE_AUX_QTY_50_MASK = 0x0003_FFFF_FFFF_FFFF
QUOTE_EXT_QTY_MAX = QUOTE_AUX_QTY_50_MASK
QUOTE_AUX_FLAG_PEG_ACTIVE = 1 << 35
QUOTE_AUX_PEG_MODE_SHIFT = 62
QUOTE_AUX_PEG_MODE_MASK = 0x03
QUOTE_AUX_JIT_MULT_SHIFT = 36
QUOTE_AUX_JIT_MULT_MASK = 0x0F
QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT = 1 << 40
QUOTE_AUX_FLAG_POST_ONLY_SLIDE = 1 << 41
QUOTE_AUX_FLAG_MARGIN_SPOT = 1 << 42
QUOTE_AUX_FLAG_OCO_LINKED = 1 << 43
QUOTE_AUX_GTS_LO_SHIFT = 44
QUOTE_AUX_AUTO_SKEW_SHIFT = 48
QUOTE_AUX_AUTO_SKEW_MASK = 0x03FF
QUOTE_AUX_AUTO_FLIP_BIT = 0x0200
QUOTE_AUX_AUTO_FLIP_MASK = 0x01FF
QUOTE_AUX_PEG_OFFSET_MASK = 0x03FF
QUOTE_AUX_GTS_HI_SHIFT = 58


def _pack_jit_elastic_mult_nibble(jit_elastic_mult: int) -> int:
    m = int(jit_elastic_mult)
    if m <= 1:
        return 0
    if m <= 10:
        return m
    if m <= 17:
        return 11
    if m <= 22:
        return 12
    if m <= 30:
        return 13
    if m <= 42:
        return 14
    return 15


def _unpack_jit_elastic_mult_nibble(raw: int) -> int:
    r = int(raw) & 0x0F
    if r <= 1:
        return 0
    if r <= 10:
        return r
    return {11: 15, 12: 20, 13: 25, 14: 35, 15: 50}[r]


def pack_order_aux1(
    reduce_only: bool = False,
    is_market: bool = False,
    cancel_on_disconnect: bool = False,
    post_only_slide: bool = False,
    min_qty_lots: int = 0,
    primary_peg: bool = False,
    midpoint_peg: bool = False,
    margin_spot: bool = False,
    display_qty_lots: int = 0,
    dark_midpoint: bool = False,
    auto_skew_ticks: int = 0,
    peg_offset_ticks: int = 0,
    oco_linked: bool = False,
    max_lifetime_wal_seqs: int = 0,
    jit_elastic_mult: int = 0,
    mark_peg: bool = False,
    auto_flip_ticks: int = 0,
    trailing_peg: bool = False,
) -> int:
    if not (0 <= min_qty_lots <= ORDER_AUX_MIN_QTY_MASK):
        raise ValueError("min_qty_lots out of 40-bit range")
    if not (0 <= display_qty_lots <= ORDER_AUX_MIN_QTY_MASK):
        raise ValueError("display_qty_lots out of 40-bit range")
    eff_trailing_peg = trailing_peg and not dark_midpoint
    eff_mark_peg = mark_peg and not eff_trailing_peg and not dark_midpoint
    eff_primary = primary_peg or ((mark_peg or eff_trailing_peg) and not dark_midpoint)
    eff_midpoint = midpoint_peg or dark_midpoint or ((mark_peg or eff_trailing_peg) and not dark_midpoint)
    use_iceberg = (display_qty_lots > 0) or dark_midpoint or eff_trailing_peg
    qty_payload = 0 if (dark_midpoint or eff_trailing_peg) else (display_qty_lots if use_iceberg else min_qty_lots)
    if (eff_primary or eff_midpoint) and not dark_midpoint:
        clamped_off = min(max(int(peg_offset_ticks), -500), 500)
        skew_or_peg = clamped_off & ORDER_AUX_PEG_OFFSET_MASK
    elif auto_flip_ticks > 0:
        skew_or_peg = ORDER_AUX_AUTO_FLIP_BIT | (min(max(int(auto_flip_ticks), 0), 500) & ORDER_AUX_AUTO_FLIP_MASK)
    elif auto_skew_ticks > 0:
        skew_or_peg = min(max(int(auto_skew_ticks), 0), 500) & ORDER_AUX_AUTO_FLIP_MASK
    else:
        skew_or_peg = 0
    has_gts = int(max_lifetime_wal_seqs) > 0
    qty_mask = ORDER_AUX_MIN_QTY_GTS_MASK if has_gts else ORDER_AUX_MIN_QTY_MASK
    if has_gts and not (dark_midpoint or eff_trailing_peg) and qty_payload > ORDER_AUX_MIN_QTY_GTS_MASK:
        raise ValueError(
            "min_qty_lots / display_qty_lots out of 24-bit range when max_lifetime_wal_seqs > 0"
        )
    gts_bits = (
        ORDER_AUX_FLAG_GTS_EXPIRY
        | ((min(max(int(max_lifetime_wal_seqs), 0), ORDER_AUX_GTS_MASK) & ORDER_AUX_GTS_MASK) << ORDER_AUX_GTS_SHIFT)
    ) if has_gts else 0
    jit4 = _pack_jit_elastic_mult_nibble(jit_elastic_mult) & ORDER_AUX_JIT_MULT_MASK
    aux1 = (
        ((qty_payload & qty_mask) << ORDER_AUX_MIN_QTY_SHIFT)
        | (skew_or_peg << ORDER_AUX_AUTO_SKEW_SHIFT)
        | (jit4 << ORDER_AUX_JIT_MULT_SHIFT)
        | gts_bits
    )
    if reduce_only:
        aux1 |= ORDER_AUX_FLAG_REDUCE_ONLY
    if is_market:
        aux1 |= ORDER_AUX_FLAG_MARKET
    if cancel_on_disconnect:
        aux1 |= ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT
    if post_only_slide:
        aux1 |= ORDER_AUX_FLAG_POST_ONLY_SLIDE
    if eff_primary:
        aux1 |= ORDER_AUX_FLAG_PRIMARY_PEG
    if eff_midpoint:
        aux1 |= ORDER_AUX_FLAG_MIDPOINT_PEG
    if margin_spot:
        aux1 |= ORDER_AUX_FLAG_MARGIN_SPOT
    if use_iceberg:
        aux1 |= ORDER_AUX_FLAG_ICEBERG
    if oco_linked:
        aux1 |= ORDER_AUX_FLAG_OCO_LINKED
    return aux1 & MASK64


def unpack_order_min_qty_lots(aux1: int) -> int:
    if aux1 & ORDER_AUX_FLAG_ICEBERG:
        return 0
    mask = ORDER_AUX_MIN_QTY_GTS_MASK if (aux1 & ORDER_AUX_FLAG_GTS_EXPIRY) else ORDER_AUX_MIN_QTY_MASK
    return (aux1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask


def unpack_order_display_qty_lots(aux1: int) -> int:
    if not (aux1 & ORDER_AUX_FLAG_ICEBERG):
        return 0
    mask = ORDER_AUX_MIN_QTY_GTS_MASK if (aux1 & ORDER_AUX_FLAG_GTS_EXPIRY) else ORDER_AUX_MIN_QTY_MASK
    return (aux1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask


def unpack_order_dark_midpoint(aux1: int) -> bool:
    mask = ORDER_AUX_MIN_QTY_GTS_MASK if (aux1 & ORDER_AUX_FLAG_GTS_EXPIRY) else ORDER_AUX_MIN_QTY_MASK
    return (
        bool(aux1 & ORDER_AUX_FLAG_MIDPOINT_PEG)
        and not bool(aux1 & ORDER_AUX_FLAG_PRIMARY_PEG)
        and bool(aux1 & ORDER_AUX_FLAG_ICEBERG)
        and (((aux1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0)
    )


def unpack_order_trailing_peg(aux1: int, client_tag: int = 0) -> bool:
    _ = client_tag
    mask = ORDER_AUX_MIN_QTY_GTS_MASK if (aux1 & ORDER_AUX_FLAG_GTS_EXPIRY) else ORDER_AUX_MIN_QTY_MASK
    return (
        ((aux1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO)
        and bool(aux1 & ORDER_AUX_FLAG_ICEBERG)
        and (((aux1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0)
    )


def unpack_order_mark_peg(aux1: int) -> bool:
    return (
        ((aux1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO)
        and not unpack_order_trailing_peg(aux1)
        and not unpack_order_dark_midpoint(aux1)
    )


def unpack_order_primary_peg(aux1: int) -> bool:
    return (
        bool(aux1 & ORDER_AUX_FLAG_PRIMARY_PEG)
        and not unpack_order_mark_peg(aux1)
        and not unpack_order_trailing_peg(aux1)
    )


def unpack_order_midpoint_peg(aux1: int) -> bool:
    return (
        bool(aux1 & ORDER_AUX_FLAG_MIDPOINT_PEG)
        and not unpack_order_mark_peg(aux1)
        and not unpack_order_trailing_peg(aux1)
        and not unpack_order_dark_midpoint(aux1)
    )


def unpack_order_oco_linked(aux1: int, client_tag: int = 1) -> bool:
    _ = client_tag
    return bool(aux1 & ORDER_AUX_FLAG_OCO_LINKED)


def unpack_order_auto_skew_ticks(aux1: int, client_tag: int = 1) -> int:
    _ = client_tag
    if aux1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG):
        return 0
    raw10 = (aux1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK
    if raw10 & ORDER_AUX_AUTO_FLIP_BIT:
        return 0
    return min(raw10 & ORDER_AUX_AUTO_FLIP_MASK, 500)


def unpack_order_auto_flip_ticks(aux1: int, client_tag: int = 1) -> int:
    _ = client_tag
    if aux1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG):
        return 0
    raw10 = (aux1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK
    if not (raw10 & ORDER_AUX_AUTO_FLIP_BIT):
        return 0
    return min(raw10 & ORDER_AUX_AUTO_FLIP_MASK, 500)


def unpack_order_peg_offset_ticks(aux1: int, client_tag: int = 1) -> int:
    _ = client_tag
    has_peg = bool(aux1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG))
    if not has_peg or unpack_order_dark_midpoint(aux1):
        return 0
    raw10 = (aux1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_PEG_OFFSET_MASK
    s10 = (raw10 - 1024) if (raw10 & 0x0200) else raw10
    return min(max(s10, -500), 500)


def unpack_order_max_lifetime_wal_seqs(aux1: int) -> int:
    if not (aux1 & ORDER_AUX_FLAG_GTS_EXPIRY):
        return 0
    return (aux1 >> ORDER_AUX_GTS_SHIFT) & ORDER_AUX_GTS_MASK


def unpack_order_jit_elastic_mult(aux1: int) -> int:
    m = (aux1 >> ORDER_AUX_JIT_MULT_SHIFT) & ORDER_AUX_JIT_MULT_MASK
    return _unpack_jit_elastic_mult_nibble(m)


def is_canonical_ext_qty_hi16(ask_qty_hi16: int) -> bool:
    return 0 <= int(ask_qty_hi16) <= 0x7FFF


def pack_quote_ask_qty_hi16(ask_qty_lots: int) -> int:
    return (int(ask_qty_lots) >> QUOTE_AUX_HI16_SHIFT) & 0x7FFF


def unpack_quote_ask_qty(aux1: int, ask_qty_hi16: int = 0) -> int:
    return ((int(aux1) & QUOTE_AUX_QTY_MASK) | ((int(ask_qty_hi16) & 0x7FFF) << QUOTE_AUX_HI16_SHIFT)) & QUOTE_AUX_QTY_50_MASK


def pack_quote_aux1(
    ask_qty_lots: int,
    cancel_on_disconnect: bool = False,
    post_only_slide: bool = False,
    margin_spot: bool = False,
    auto_skew_ticks: int = 0,
    oco_linked: bool = False,
    max_lifetime_wal_seqs: int = 0,
    jit_elastic_mult: int = 0,
    auto_flip_ticks: int = 0,
    quote_peg_mode: int = 0,
    peg_offset_ticks: int = 0,
) -> int:
    if not (0 <= int(ask_qty_lots) <= QUOTE_AUX_QTY_50_MASK):
        raise ValueError("ask_qty_lots out of 50-bit wire range")
    eff_peg = int(quote_peg_mode) if (1 <= int(quote_peg_mode) <= 4) else 0
    if eff_peg != 0:
        clamped_off = min(max(int(peg_offset_ticks), -500), 500)
        skew_flip_or_peg10 = clamped_off & QUOTE_AUX_PEG_OFFSET_MASK
    elif auto_flip_ticks > 0:
        skew_flip_or_peg10 = QUOTE_AUX_AUTO_FLIP_BIT | (
            min(max(int(auto_flip_ticks), 0), 500) & QUOTE_AUX_AUTO_FLIP_MASK
        )
    else:
        skew_flip_or_peg10 = min(max(int(auto_skew_ticks), 0), 500) & QUOTE_AUX_AUTO_FLIP_MASK
    gts_cap = 255 if (eff_peg != 0) else 1023
    gts_val = min(max(int(max_lifetime_wal_seqs), 0), gts_cap)
    gts_lo = (gts_val & 0x0F) << QUOTE_AUX_GTS_LO_SHIFT
    gts_hi_mask = 0x0F if (eff_peg != 0) else 0x3F
    gts_hi = ((gts_val >> 4) & gts_hi_mask) << QUOTE_AUX_GTS_HI_SHIFT
    jit4 = _pack_jit_elastic_mult_nibble(jit_elastic_mult) & QUOTE_AUX_JIT_MULT_MASK
    peg_bits = (
        QUOTE_AUX_FLAG_PEG_ACTIVE
        | (((eff_peg - 1) & QUOTE_AUX_PEG_MODE_MASK) << QUOTE_AUX_PEG_MODE_SHIFT)
    ) if (eff_peg != 0) else 0
    return (
        (ask_qty_lots & QUOTE_AUX_QTY_MASK)
        | peg_bits
        | (QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT if cancel_on_disconnect else 0)
        | (QUOTE_AUX_FLAG_POST_ONLY_SLIDE if post_only_slide else 0)
        | (QUOTE_AUX_FLAG_MARGIN_SPOT if margin_spot else 0)
        | (QUOTE_AUX_FLAG_OCO_LINKED if oco_linked else 0)
        | gts_lo
        | (skew_flip_or_peg10 << QUOTE_AUX_AUTO_SKEW_SHIFT)
        | gts_hi
        | (jit4 << QUOTE_AUX_JIT_MULT_SHIFT)
    ) & MASK64


def unpack_quote_peg_mode(aux1: int) -> int:
    if not (aux1 & QUOTE_AUX_FLAG_PEG_ACTIVE):
        return 0
    raw2 = (aux1 >> QUOTE_AUX_PEG_MODE_SHIFT) & QUOTE_AUX_PEG_MODE_MASK
    return raw2 + 1


def unpack_quote_peg_offset_ticks(aux1: int) -> int:
    if unpack_quote_peg_mode(aux1) == 0:
        return 0
    raw10 = (aux1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_PEG_OFFSET_MASK
    s10 = (raw10 - 1024) if (raw10 & 0x0200) else raw10
    return min(max(s10, -500), 500)


def unpack_quote_auto_skew_ticks(aux1: int) -> int:
    if unpack_quote_peg_mode(aux1) != 0:
        return 0
    raw10 = (aux1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK
    if raw10 & QUOTE_AUX_AUTO_FLIP_BIT:
        return 0
    return min(raw10 & QUOTE_AUX_AUTO_FLIP_MASK, 500)


def unpack_quote_auto_flip_ticks(aux1: int) -> int:
    if unpack_quote_peg_mode(aux1) != 0:
        return 0
    raw10 = (aux1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK
    if not (raw10 & QUOTE_AUX_AUTO_FLIP_BIT):
        return 0
    return min(raw10 & QUOTE_AUX_AUTO_FLIP_MASK, 500)


def unpack_quote_oco_linked(aux1: int) -> bool:
    return bool(aux1 & QUOTE_AUX_FLAG_OCO_LINKED)


def unpack_quote_max_lifetime_wal_seqs(aux1: int) -> int:
    lo4 = (aux1 >> QUOTE_AUX_GTS_LO_SHIFT) & 0x0F
    hi_mask = 0x0F if (aux1 & QUOTE_AUX_FLAG_PEG_ACTIVE) else 0x3F
    hi = (aux1 >> QUOTE_AUX_GTS_HI_SHIFT) & hi_mask
    return (hi << 4) | lo4


def unpack_quote_jit_elastic_mult(aux1: int) -> int:
    m = (aux1 >> QUOTE_AUX_JIT_MULT_SHIFT) & QUOTE_AUX_JIT_MULT_MASK
    return _unpack_jit_elastic_mult_nibble(m)


SPREAD_AUX1_FLAG_LEG2_ASK = 1 << 40
SPREAD_AUX1_FLAG_LEG1_MARKET = 1 << 41
SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY = 1 << 42
SPREAD_AUX1_FLAG_LEG2_MARKET = 1 << 43
SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY = 1 << 44
SPREAD_AUX1_FLAG_MARGIN_SPOT = 1 << 45
SPREAD_AUX1_FLAG_MULTI_LEG_BASKET = 1 << 46
SPREAD_AUX1_FLAG_BASKET_4_LEGS = 1 << 47
SPREAD_AUX1_LEG4_MKT_SHIFT = 48
SPREAD_AUX1_FLAG_LEG3_ASK = 1 << 56
SPREAD_AUX1_FLAG_LEG3_MARKET = 1 << 57
SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY = 1 << 58
SPREAD_AUX1_FLAG_LEG4_ASK = 1 << 59
SPREAD_AUX1_FLAG_LEG4_MARKET = 1 << 60
SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY = 1 << 61
SPREAD_AUX1_FLAG_BASKET_2_LEGS = 1 << 62
SPREAD_AUX1_FLAG_BASKET_EXT_MKT16 = 1 << 63
SPREAD_AUX1_LEG3_MKT_HI8_SHIFT = 24
SPREAD_AUX1_LEG4_MKT_HI8_SHIFT = 32


@dataclass
class WireBasketLeg:
    market_id: int = 0
    side: OrderSide = OrderSide.BID
    price_ticks: int = 0
    qty_lots: int = 0
    is_market: bool = False
    reduce_only: bool = False
    margin_spot: bool = False


def pack_atomic_spread_aux(
    leg2_market_id: int,
    leg2_side: OrderSide,
    leg2_price_ticks: int,
    leg2_qty_lots: int,
    leg1_is_market: bool = False,
    leg1_reduce_only: bool = False,
    leg2_is_market: bool = False,
    leg2_reduce_only: bool = False,
    margin_spot: bool = False,
) -> tuple[int, int]:
    if not (0 <= leg2_market_id <= 0xFFFF):
        raise ValueError("leg2_market_id out of 16-bit range")
    if not (-(1 << 47) <= leg2_price_ticks < (1 << 47)):
        raise ValueError("leg2_price_ticks out of signed 48-bit range")
    if not (0 <= leg2_qty_lots <= QUOTE_AUX_QTY_50_MASK):
        raise ValueError("leg2_qty_lots out of 50-bit range")
    p48 = leg2_price_ticks & 0xFFFF_FFFF_FFFF
    aux0 = ((leg2_market_id << 48) | p48) & MASK64
    aux1 = leg2_qty_lots & QUOTE_AUX_QTY_MASK
    if leg2_side == OrderSide.ASK:
        aux1 |= SPREAD_AUX1_FLAG_LEG2_ASK
    if leg1_is_market:
        aux1 |= SPREAD_AUX1_FLAG_LEG1_MARKET
    if leg1_reduce_only:
        aux1 |= SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY
    if leg2_is_market:
        aux1 |= SPREAD_AUX1_FLAG_LEG2_MARKET
    if leg2_reduce_only:
        aux1 |= SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY
    if margin_spot:
        aux1 |= SPREAD_AUX1_FLAG_MARGIN_SPOT
    return aux0, aux1 & MASK64


def unpack_atomic_spread_aux(
    aux0: int, aux1: int, leg2_qty_hi16: int = 0
) -> tuple[int, OrderSide, int, int, bool, bool, bool, bool]:
    leg2_market_id = (aux0 >> 48) & 0xFFFF
    p48 = aux0 & 0xFFFF_FFFF_FFFF
    if p48 & (1 << 47):
        leg2_price_ticks = p48 - (1 << 48)
    else:
        leg2_price_ticks = p48
    if (aux1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) and not (aux1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS):
        if aux1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16:
            leg2_qty_lots = aux1 & 0xFFFFFF
        else:
            leg2_qty_lots = aux1 & QUOTE_AUX_QTY_MASK
    else:
        leg2_qty_lots = unpack_quote_ask_qty(aux1, leg2_qty_hi16)
    leg2_side = OrderSide.ASK if (aux1 & SPREAD_AUX1_FLAG_LEG2_ASK) else OrderSide.BID
    leg1_is_market = bool(aux1 & SPREAD_AUX1_FLAG_LEG1_MARKET)
    leg1_reduce_only = bool(aux1 & SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY)
    leg2_is_market = bool(aux1 & SPREAD_AUX1_FLAG_LEG2_MARKET)
    leg2_reduce_only = bool(aux1 & SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY)
    return (
        leg2_market_id,
        leg2_side,
        leg2_price_ticks,
        leg2_qty_lots,
        leg1_is_market,
        leg1_reduce_only,
        leg2_is_market,
        leg2_reduce_only,
    )


def _rotl64(x: int, b: int) -> int:
    x &= MASK64
    return ((x << b) | (x >> (64 - b))) & MASK64


def _sip_round(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    v0 = (v0 + v1) & MASK64
    v1 = _rotl64(v1, 13) ^ v0
    v0 = _rotl64(v0, 32)
    v2 = (v2 + v3) & MASK64
    v3 = _rotl64(v3, 16) ^ v2
    v0 = (v0 + v3) & MASK64
    v3 = _rotl64(v3, 21) ^ v0
    v2 = (v2 + v1) & MASK64
    v1 = _rotl64(v1, 17) ^ v2
    v2 = _rotl64(v2, 32)
    return v0, v1, v2, v3


@dataclass
class ArenaHeader:
    op: BaseOp = BaseOp.NEW_ORDER
    tif: TimeInForce = TimeInForce.GTC
    stp: StpMode = StpMode.CANCEL_RESTING
    market_id: int = 0
    account_id: int = 0
    side: OrderSide = OrderSide.BID
    seq_lo: int = 0
    price_ticks: int = 0
    qty_lots: int = 0

    def pack_flags4(self) -> int:
        return (((int(self.stp) & 0x3) << 2) | (int(self.tif) & 0x3)) & 0xF

    def pack_words(self) -> tuple[int, int, int]:
        mkt_int = int(self.market_id)
        if mkt_int < 0 or mkt_int > 0xFFFF:
            raise ValueError(
                f"market_id {self.market_id} out of 16-bit wire range [0, 65535]"
            )
        acct_int = int(self.account_id)
        if acct_int < 0 or acct_int > 0xFFFFFF:
            raise ValueError(
                f"account_id {self.account_id} out of 24-bit wire range [0, 16777215]"
            )
        qty_int = int(self.qty_lots)
        if qty_int < 0 or qty_int > MAX_WIRE_HEADER_QTY_LOTS:
            raise ValueError(
                f"qty_lots {self.qty_lots} out of 40-bit wire range [0, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        px = _validate_price_ticks_48(self.price_ticks, "price_ticks")
        op_fl = ((int(self.op) & 0xF) << 4) | self.pack_flags4()
        mkt = mkt_int & 0xFFFF
        acct = acct_int & 0xFFFFFF
        sd_seq = ((int(self.side) & 0x3) << 14) | (self.seq_lo & 0x3FFF)
        m0 = (op_fl << 56) | (mkt << 40) | (acct << 16) | sd_seq

        p48 = px & 0xFFFF_FFFF_FFFF
        q40 = qty_int & 0xFF_FFFF_FFFF
        m1 = (p48 << 16) | (q40 >> 24)
        hi24 = q40 & 0xFFFFFF
        return m0, m1, hi24


def calc_pre_siphash40(
    hdr: ArenaHeader,
    seq_hi50: int = DEFAULT_SEQ_HI50,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
) -> int:
    m0, m1, hi24 = hdr.pack_words()
    m2 = ((hi24 << 40) | (seq_hi50 & 0xFF_FFFF_FFFF)) & MASK64
    seq_top10 = (seq_hi50 >> 40) & 0x3FF

    v0 = (key_lo64 ^ 0x736F6D6570736575 ^ seq_top10) & MASK64
    v1 = (key_hi64 ^ 0x646F72616E646F6D) & MASK64
    v2 = (key_lo64 ^ 0x6C7967656E657261) & MASK64
    v3 = (key_hi64 ^ 0x7465646279746573 ^ m0) & MASK64

    # SipHash-2-4 across (m0, m1, m2) with 4 finalization rounds
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= m0

    v3 ^= m1
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= m1

    v3 ^= m2
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= m2

    v2 ^= 0xFF
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    digest = (v0 ^ v1 ^ v2 ^ v3) & MASK64
    return (digest ^ (digest >> 24)) & 0xFF_FFFF_FFFF


def calc_tail_siphash48(
    frame_bytes: bytes | bytearray,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    seq_hi50: int = DEFAULT_SEQ_HI50,
) -> int:
    eff_hi50 = int(seq_hi50) & 0x0003_FFFF_FFFF_FFFF
    w0, w1, w2, w3, w4, w5, w6 = struct.unpack_from(">7Q", frame_bytes, 0)
    w7 = eff_hi50 | (0x2A54 << 50)
    w8 = (64 << 56) | 0x4152454E4154

    v0 = (key_lo64 ^ 0x736F6D6570736575 ^ 0x5441494C5F563231) & MASK64
    v1 = (key_hi64 ^ 0x646F72616E646F6D) & MASK64
    v2 = (key_lo64 ^ 0x6C7967656E657261) & MASK64
    v3 = (key_hi64 ^ 0x7465646279746573) & MASK64

    for m in (w0, w1, w2, w3, w4, w5, w6, w7, w8):
        v3 ^= m
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)

    h = (v0 ^ v1 ^ v2 ^ v3) & MASK64
    return (h ^ (h >> 16)) & 0xFFFF_FFFF_FFFF


def pack_wire_frame(
    hdr: ArenaHeader,
    aux_param0: int = 0,
    aux_param1: int = 0,
    seq_hi50: int = DEFAULT_SEQ_HI50,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    ext_qty_hi16: int = 0,
) -> bytes:
    if not is_canonical_ext_qty_hi16(ext_qty_hi16):
        raise ValueError(f"ext_qty_hi16 {ext_qty_hi16} out of 15-bit canonical range [0, 32767]")
    buf = bytearray(ARENA_WIRE_BYTES)
    m0, m1, hi24 = hdr.pack_words()
    struct.pack_into(">QQ", buf, 0, m0, m1)
    buf[16] = (hi24 >> 16) & 0xFF
    buf[17] = (hi24 >> 8) & 0xFF
    buf[18] = hi24 & 0xFF

    mac40 = calc_pre_siphash40(hdr, seq_hi50, key_lo64, key_hi64)
    buf[19] = (mac40 >> 32) & 0xFF
    buf[20] = (mac40 >> 24) & 0xFF
    buf[21] = (mac40 >> 16) & 0xFF
    buf[22] = (mac40 >> 8) & 0xFF
    buf[23] = mac40 & 0xFF

    buf[24] = 0x01
    struct.pack_into(">QQ", buf, 25, aux_param0 & MASK64, aux_param1 & MASK64)
    if ext_qty_hi16:
        struct.pack_into(">H", buf, 41, int(ext_qty_hi16) & 0x7FFF)

    tail48 = calc_tail_siphash48(buf, key_lo64, key_hi64, seq_hi50)
    buf[56] = (tail48 >> 40) & 0xFF
    buf[57] = (tail48 >> 32) & 0xFF
    buf[58] = (tail48 >> 24) & 0xFF
    buf[59] = (tail48 >> 16) & 0xFF
    buf[60] = (tail48 >> 8) & 0xFF
    buf[61] = tail48 & 0xFF
    buf[62] = 0xA1
    buf[63] = 0xE0
    return bytes(buf)


def _validate_wire_basket_legs(legs: List[WireBasketLeg]) -> None:
    num_legs = len(legs)
    if not (2 <= num_legs <= 4):
        raise ValueError("Wire basket must contain 2..4 legs")
    for leg_idx, leg in enumerate(legs):
        if not (1 <= int(leg.market_id) <= 0xFFFF):
            raise ValueError(f"legs[{leg_idx}].market_id out of [1, 65535]")
        _validate_price_ticks_48(leg.price_ticks, f"legs[{leg_idx}].price_ticks")
    if not (1 <= int(legs[0].qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
        raise ValueError(f"legs[0].qty_lots out of [1, {MAX_WIRE_HEADER_QTY_LOTS}]")
    need_ext_mkt16 = num_legs >= 3 and (
        int(legs[2].market_id) > 0xFF or (num_legs >= 4 and int(legs[3].market_id) > 0xFF)
    )
    max_leg2_qty = (
        QUOTE_AUX_QTY_50_MASK
        if num_legs == 2
        else (MAX_WIRE_BASKET_LEG24_QTY_LOTS if need_ext_mkt16 else QUOTE_AUX_QTY_MASK)
    )
    if not (1 <= int(legs[1].qty_lots) <= max_leg2_qty):
        raise ValueError(f"legs[1].qty_lots out of [1, {max_leg2_qty}]")
    for leg_idx in range(2, num_legs):
        px_i = int(legs[leg_idx].price_ticks)
        if not (MIN_WIRE_BASKET_LEG34_PRICE_TICKS <= px_i <= MAX_WIRE_BASKET_LEG34_PRICE_TICKS):
            raise ValueError(f"legs[{leg_idx}].price_ticks out of signed 32-bit wire range")
        if not (1 <= int(legs[leg_idx].qty_lots) <= MAX_WIRE_BASKET_LEG24_QTY_LOTS):
            raise ValueError(
                f"legs[{leg_idx}].qty_lots out of 24-bit wire range [1, {MAX_WIRE_BASKET_LEG24_QTY_LOTS}]"
            )


def _validate_priority_fee_ppm(priority_fee_ppm: int) -> int:
    ppm_i = int(priority_fee_ppm)
    if not (0 <= ppm_i <= MAX_PRIORITY_FEE_PPM):
        raise ValueError(f"priority_fee_ppm {ppm_i} out of [0, {MAX_PRIORITY_FEE_PPM}]")
    return ppm_i


def _validate_express_surplus_bid_bps(express_surplus_bid_bps: int) -> int:
    bps_i = int(express_surplus_bid_bps)
    if not (0 <= bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
        raise ValueError(
            f"express_surplus_bid_bps {bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
        )
    return bps_i


def pack_order_ext_priority_fee_ppm(
    frame_bytes: bytes | bytearray,
    priority_fee_ppm: int,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    seq_hi50: int = DEFAULT_SEQ_HI50,
) -> bytes:
    ppm_i = _validate_priority_fee_ppm(priority_fee_ppm)
    buf = bytearray(frame_bytes)
    if ppm_i == 0:
        return bytes(buf)
    struct.pack_into(">H", buf, 52, ppm_i)
    tail48 = calc_tail_siphash48(buf, key_lo64, key_hi64, seq_hi50)
    for i in range(6):
        buf[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
    return bytes(buf)


def unpack_order_priority_fee_ppm(frame_bytes: bytes) -> int:
    return int(struct.unpack_from(">H", frame_bytes, 52)[0])


def pack_wire_express_surplus_bid_bps(
    frame_bytes: bytes | bytearray,
    express_surplus_bid_bps: int,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    seq_hi50: int = DEFAULT_SEQ_HI50,
) -> bytes:
    bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
    buf = bytearray(frame_bytes)
    if bps_i == 0:
        return bytes(buf)
    struct.pack_into(">H", buf, 52, bps_i)
    tail48 = calc_tail_siphash48(buf, key_lo64, key_hi64, seq_hi50)
    for i in range(6):
        buf[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
    return bytes(buf)


def unpack_wire_express_surplus_bid_bps(frame_bytes: bytes) -> int:
    return int(struct.unpack_from(">H", frame_bytes, 52)[0])


def _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps: int) -> int:
    bps_i = int(bounty_rebate_bid_bps)
    if not (0 <= bps_i <= MAX_LIQ_BOUNTY_REBATE_BID_BPS):
        raise ValueError(
            f"bounty_rebate_bid_bps {bps_i} out of [0, {MAX_LIQ_BOUNTY_REBATE_BID_BPS}]"
        )
    return bps_i


def pack_wire_liq_bounty_rebate_bid_bps(
    frame_bytes: bytes | bytearray,
    bounty_rebate_bid_bps: int,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    seq_hi50: int = DEFAULT_SEQ_HI50,
) -> bytes:
    bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
    buf = bytearray(frame_bytes)
    if bps_i == 0:
        return bytes(buf)
    struct.pack_into(">H", buf, 52, bps_i)
    tail48 = calc_tail_siphash48(buf, key_lo64, key_hi64, seq_hi50)
    for i in range(6):
        buf[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
    return bytes(buf)


def unpack_wire_liq_bounty_rebate_bid_bps(frame_bytes: bytes) -> int:
    return int(struct.unpack_from(">H", frame_bytes, 52)[0])


def pack_wire_basket_frame(
    account_id: int,
    legs: List[WireBasketLeg],
    stp: StpMode = StpMode.CANCEL_RESTING,
    margin_spot: bool = False,
    seq_lo: int = 1,
    seq_hi50: int = DEFAULT_SEQ_HI50,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    express_surplus_bid_bps: int = 0,
) -> bytes:
    _validate_wire_basket_legs(legs)
    num_legs = len(legs)
    bid_bps_i = int(express_surplus_bid_bps)
    if not (0 <= bid_bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
        raise ValueError(
            f"express_surplus_bid_bps {bid_bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
        )
    if num_legs >= 4 and bid_bps_i > 0:
        raise ValueError("express_surplus_bid_bps cannot be combined with 4-leg wire baskets")
    hdr = ArenaHeader(
        op=BaseOp.ATOMIC_SPREAD,
        tif=TimeInForce.FOK,
        stp=stp,
        market_id=legs[0].market_id,
        account_id=account_id,
        side=legs[0].side,
        seq_lo=seq_lo,
        price_ticks=legs[0].price_ticks,
        qty_lots=legs[0].qty_lots,
    )
    any_margin_spot = margin_spot or any(l.margin_spot for l in legs)
    aux0, aux1 = pack_atomic_spread_aux(
        leg2_market_id=legs[1].market_id,
        leg2_side=legs[1].side,
        leg2_price_ticks=legs[1].price_ticks,
        leg2_qty_lots=legs[1].qty_lots,
        leg1_is_market=legs[0].is_market,
        leg1_reduce_only=legs[0].reduce_only,
        leg2_is_market=legs[1].is_market,
        leg2_reduce_only=legs[1].reduce_only,
        margin_spot=any_margin_spot,
    )
    aux1 |= SPREAD_AUX1_FLAG_MULTI_LEG_BASKET
    if num_legs == 2:
        aux1 |= SPREAD_AUX1_FLAG_BASKET_2_LEGS
    elif num_legs >= 4:
        aux1 |= SPREAD_AUX1_FLAG_BASKET_4_LEGS
    if num_legs >= 3:
        if legs[2].side == OrderSide.ASK:
            aux1 |= SPREAD_AUX1_FLAG_LEG3_ASK
        if legs[2].is_market:
            aux1 |= SPREAD_AUX1_FLAG_LEG3_MARKET
        if legs[2].reduce_only:
            aux1 |= SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY
    if num_legs >= 4:
        aux1 |= (legs[3].market_id & 0xFF) << SPREAD_AUX1_LEG4_MKT_SHIFT
        if legs[3].side == OrderSide.ASK:
            aux1 |= SPREAD_AUX1_FLAG_LEG4_ASK
        if legs[3].is_market:
            aux1 |= SPREAD_AUX1_FLAG_LEG4_MARKET
        if legs[3].reduce_only:
            aux1 |= SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY
    if num_legs >= 3 and (legs[2].market_id > 0xFF or (num_legs >= 4 and legs[3].market_id > 0xFF)):
        aux1 = (
            (aux1 & ~0x0000_00FF_FF00_0000)
            | SPREAD_AUX1_FLAG_BASKET_EXT_MKT16
            | (((legs[2].market_id >> 8) & 0xFF) << SPREAD_AUX1_LEG3_MKT_HI8_SHIFT)
            | ((((legs[3].market_id >> 8) & 0xFF) << SPREAD_AUX1_LEG4_MKT_HI8_SHIFT) if num_legs >= 4 else 0)
        )

    buf = bytearray(ARENA_WIRE_BYTES)
    m0, m1, hi24 = hdr.pack_words()
    struct.pack_into(">QQ", buf, 0, m0, m1)
    buf[16] = (hi24 >> 16) & 0xFF
    buf[17] = (hi24 >> 8) & 0xFF
    buf[18] = hi24 & 0xFF

    mac40 = calc_pre_siphash40(hdr, seq_hi50, key_lo64, key_hi64)
    buf[19] = (mac40 >> 32) & 0xFF
    buf[20] = (mac40 >> 24) & 0xFF
    buf[21] = (mac40 >> 16) & 0xFF
    buf[22] = (mac40 >> 8) & 0xFF
    buf[23] = mac40 & 0xFF

    buf[24] = 0x01
    struct.pack_into(">QQ", buf, 25, aux0 & MASK64, aux1 & MASK64)

    if num_legs == 2:
        q2_hi16 = pack_quote_ask_qty_hi16(legs[1].qty_lots)
        struct.pack_into(">H", buf, 41, q2_hi16)
    elif num_legs >= 3:
        struct.pack_into(">I", buf, 41, legs[2].price_ticks & 0xFFFF_FFFF)
        q3 = legs[2].qty_lots & 0xFFFFFF
        buf[49] = (q3 >> 16) & 0xFF
        buf[50] = (q3 >> 8) & 0xFF
        buf[51] = q3 & 0xFF
        buf[55] = legs[2].market_id & 0xFF
    if num_legs >= 4:
        struct.pack_into(">I", buf, 45, legs[3].price_ticks & 0xFFFF_FFFF)
        q4 = legs[3].qty_lots & 0xFFFFFF
        buf[52] = (q4 >> 16) & 0xFF
        buf[53] = (q4 >> 8) & 0xFF
        buf[54] = q4 & 0xFF
    elif bid_bps_i > 0:
        struct.pack_into(">H", buf, 52, bid_bps_i)

    tail48 = calc_tail_siphash48(buf, key_lo64, key_hi64, seq_hi50)
    buf[56] = (tail48 >> 40) & 0xFF
    buf[57] = (tail48 >> 32) & 0xFF
    buf[58] = (tail48 >> 24) & 0xFF
    buf[59] = (tail48 >> 16) & 0xFF
    buf[60] = (tail48 >> 8) & 0xFF
    buf[61] = tail48 & 0xFF
    buf[62] = 0xA1
    buf[63] = 0xE0
    return bytes(buf)


def siphash24_pair64(key_lo64: int, key_hi64: int, w0: int, w1: int) -> int:
    k_lo = int(key_lo64) & MASK64
    k_hi = int(key_hi64) & MASK64
    w2 = (16 << 56) & MASK64
    v0 = (k_lo ^ 0x736F6D6570736575) & MASK64
    v1 = (k_hi ^ 0x646F72616E646F6D) & MASK64
    v2 = (k_lo ^ 0x6C7967656E657261) & MASK64
    v3 = (k_hi ^ 0x7465646279746573) & MASK64
    for m in (int(w0) & MASK64, int(w1) & MASK64, w2):
        v3 ^= m
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= m
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def siphash24_quad64(key_lo64: int, key_hi64: int, w0: int, w1: int, w2: int, w3: int) -> int:
    k_lo = int(key_lo64) & MASK64
    k_hi = int(key_hi64) & MASK64
    w4 = (32 << 56) & MASK64
    v0 = (k_lo ^ 0x736F6D6570736575) & MASK64
    v1 = (k_hi ^ 0x646F72616E646F6D) & MASK64
    v2 = (k_lo ^ 0x6C7967656E657261) & MASK64
    v3 = (k_hi ^ 0x7465646279746573) & MASK64
    for m in (int(w0) & MASK64, int(w1) & MASK64, int(w2) & MASK64, int(w3) & MASK64, w4):
        v3 ^= m
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= m
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def _sdk_csprng_u64_nonzero() -> int:
    for _ in range(16):
        val = int.from_bytes(secrets.token_bytes(8), "big")
        if val != 0:
            return val
    raise RuntimeError("OS CSPRNG returned zero 64-bit salt repeatedly")


def compute_session_key_wrap_pad(
    cur_key_lo64: int,
    cur_key_hi64: int,
    seq_hi50: int,
    seq_lo: int,
    account_id: int,
    wrap_salt64: int,
) -> tuple[int, int]:
    wrap_klo = siphash24_pair64(
        (int(cur_key_lo64) ^ 0x575241505F4B3031) & MASK64,
        (int(cur_key_hi64) ^ 0x575241505F4B3032) & MASK64,
        0x575241505F4B4559,
        0x53455353494F4E31,
    )
    wrap_khi = siphash24_pair64(
        (int(cur_key_lo64) ^ 0x575241505F4B3033) & MASK64,
        (int(cur_key_hi64) ^ 0x575241505F4B3034) & MASK64,
        0x575241505F4B4559,
        0x53455353494F4E32,
    )
    w0 = (
        ((int(seq_hi50) & 0x0003_FFFF_FFFF_FFFF) << 14)
        | (int(seq_lo) & 0x3FFF)
    ) & MASK64
    aid = int(account_id) & 0xFFFF_FFFF
    salt = int(wrap_salt64) & MASK64
    pad_lo = siphash24_quad64(
        wrap_klo, wrap_khi, w0, salt, ((0x4B57_5230 << 32) | aid) & MASK64, 0x5041445F56320000
    )
    pad_hi = siphash24_quad64(
        wrap_klo, wrap_khi, w0, salt, ((0x4B57_5231 << 32) | aid) & MASK64, 0x5041445F56320001
    )
    return pad_lo, pad_hi


def pack_encrypted_register_session_key_frame(
    account_id: int,
    seq_lo: int,
    seq_hi50: int,
    cur_key_lo64: int,
    cur_key_hi64: int,
    new_key_lo64: int,
    new_key_hi64: int,
    wrap_salt64: Optional[int] = None,
) -> bytes:
    eff_seq_lo = int(seq_lo) & 0x3FFF
    eff_salt64 = _sdk_csprng_u64_nonzero() if wrap_salt64 is None else (int(wrap_salt64) & MASK64)
    if eff_salt64 == 0:
        raise ValueError("wrap_salt64 must be non-zero")
    hdr = ArenaHeader(
        op=BaseOp.REGISTER_SESSION_KEY,
        tif=TimeInForce.GTC,
        stp=StpMode.CANCEL_RESTING,
        market_id=0,
        account_id=int(account_id),
        side=OrderSide.BID,
        seq_lo=eff_seq_lo,
        price_ticks=0,
        qty_lots=0,
    )
    pad_lo, pad_hi = compute_session_key_wrap_pad(
        cur_key_lo64, cur_key_hi64, seq_hi50, eff_seq_lo, account_id, eff_salt64
    )
    buf = bytearray(
        pack_wire_frame(
            hdr,
            (int(new_key_lo64) ^ pad_lo) & MASK64,
            (int(new_key_hi64) ^ pad_hi) & MASK64,
            seq_hi50,
            cur_key_lo64,
            cur_key_hi64,
        )
    )
    struct.pack_into(">Q", buf, 41, eff_salt64)
    buf[51] |= WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP
    tail48 = calc_tail_siphash48(buf, cur_key_lo64, cur_key_hi64, seq_hi50)
    for i in range(6):
        buf[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
    return bytes(buf)


def unpack_register_session_key_wire(
    frame_bytes: bytes | bytearray,
    seq_hi50: int,
    cur_key_lo64: int,
    cur_key_hi64: int,
    allow_legacy_plaintext: bool = False,
) -> tuple[int, int, bool]:
    hdr, _, raw_aux0, raw_aux1 = unpack_wire_frame(frame_bytes)
    was_encrypted = bool(frame_bytes[51] & WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP)
    if not was_encrypted:
        if not allow_legacy_plaintext:
            raise ValueError("Unencrypted RegisterSessionKey frame rejected")
        return raw_aux0 & MASK64, raw_aux1 & MASK64, False
    wrap_salt64 = struct.unpack_from(">Q", frame_bytes, 41)[0]
    if wrap_salt64 == 0:
        raise ValueError("Encrypted RegisterSessionKey frame missing non-zero wrap_salt64")
    pad_lo, pad_hi = compute_session_key_wrap_pad(
        cur_key_lo64, cur_key_hi64, seq_hi50, hdr.seq_lo, hdr.account_id, wrap_salt64
    )
    return (raw_aux0 ^ pad_lo) & MASK64, (raw_aux1 ^ pad_hi) & MASK64, True


def unpack_wire_frame(
    frame_bytes: bytes | bytearray,
) -> tuple[ArenaHeader, int, int, int]:
    if len(frame_bytes) < ARENA_WIRE_BYTES:
        raise ValueError(f"Expected {ARENA_WIRE_BYTES} bytes, got {len(frame_bytes)}")
    m0, m1 = struct.unpack_from(">QQ", frame_bytes, 0)
    hi24 = (frame_bytes[16] << 16) | (frame_bytes[17] << 8) | frame_bytes[18]
    op_fl = (m0 >> 56) & 0xFF
    op = BaseOp((op_fl >> 4) & 0xF)
    fl4 = op_fl & 0xF
    tif = TimeInForce(fl4 & 0x3)
    stp = StpMode((fl4 >> 2) & 0x3)
    market_id = (m0 >> 40) & 0xFFFF
    account_id = (m0 >> 16) & 0xFFFFFF
    sd_s = m0 & 0xFFFF
    side = OrderSide((sd_s >> 14) & 0x3)
    seq_lo = sd_s & 0x3FFF
    p48 = (m1 >> 16) & 0xFFFF_FFFF_FFFF
    price_ticks = (p48 - (1 << 48)) if (p48 & (1 << 47)) else p48
    qty_lots = (((m1 & 0xFFFF) << 24) | hi24) & 0xFF_FFFF_FFFF
    rx_mac40 = (
        (frame_bytes[19] << 32)
        | (frame_bytes[20] << 24)
        | (frame_bytes[21] << 16)
        | (frame_bytes[22] << 8)
        | frame_bytes[23]
    )
    aux0, aux1 = struct.unpack_from(">QQ", frame_bytes, 25)
    hdr = ArenaHeader(
        op=op,
        tif=tif,
        stp=stp,
        market_id=market_id,
        account_id=account_id,
        side=side,
        seq_lo=seq_lo,
        price_ticks=price_ticks,
        qty_lots=qty_lots,
    )
    return hdr, rx_mac40, aux0, aux1


def unpack_wire_basket_legs34(
    frame_bytes: bytes | bytearray,
    aux1: int,
) -> tuple[int, WireBasketLeg, WireBasketLeg]:
    leg3 = WireBasketLeg(0, OrderSide.BID, 0, 0)
    leg4 = WireBasketLeg(0, OrderSide.BID, 0, 0)
    if (aux1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) or not (aux1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET):
        return 2, leg3, leg4
    num_legs = 4 if (aux1 & SPREAD_AUX1_FLAG_BASKET_4_LEGS) else 3
    margin_spot = bool(aux1 & SPREAD_AUX1_FLAG_MARGIN_SPOT)
    ext_mkt16 = bool(aux1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16)
    leg3_hi8 = (((aux1 >> SPREAD_AUX1_LEG3_MKT_HI8_SHIFT) & 0xFF) << 8) if ext_mkt16 else 0
    p3 = struct.unpack_from(">i", frame_bytes, 41)[0]
    q3 = (frame_bytes[49] << 16) | (frame_bytes[50] << 8) | frame_bytes[51]
    leg3 = WireBasketLeg(
        market_id=frame_bytes[55] | leg3_hi8,
        side=OrderSide.ASK if (aux1 & SPREAD_AUX1_FLAG_LEG3_ASK) else OrderSide.BID,
        price_ticks=p3,
        qty_lots=q3,
        is_market=bool(aux1 & SPREAD_AUX1_FLAG_LEG3_MARKET),
        reduce_only=bool(aux1 & SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY),
        margin_spot=margin_spot,
    )
    if num_legs >= 4:
        leg4_hi8 = (((aux1 >> SPREAD_AUX1_LEG4_MKT_HI8_SHIFT) & 0xFF) << 8) if ext_mkt16 else 0
        p4 = struct.unpack_from(">i", frame_bytes, 45)[0]
        q4 = (frame_bytes[52] << 16) | (frame_bytes[53] << 8) | frame_bytes[54]
        leg4 = WireBasketLeg(
            market_id=((aux1 >> SPREAD_AUX1_LEG4_MKT_SHIFT) & 0xFF) | leg4_hi8,
            side=OrderSide.ASK if (aux1 & SPREAD_AUX1_FLAG_LEG4_ASK) else OrderSide.BID,
            price_ticks=p4,
            qty_lots=q4,
            is_market=bool(aux1 & SPREAD_AUX1_FLAG_LEG4_MARKET),
            reduce_only=bool(aux1 & SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY),
            margin_spot=margin_spot,
        )
    return num_legs, leg3, leg4


def unpack_wire_basket_frame(
    frame_bytes: bytes | bytearray,
) -> tuple[ArenaHeader, List[WireBasketLeg], bool]:
    hdr, _, aux0, aux1 = unpack_wire_frame(frame_bytes)
    margin_spot = bool(aux1 & SPREAD_AUX1_FLAG_MARGIN_SPOT)
    b2_hi16 = 0
    if (aux1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) or not (aux1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET):
        b2_hi16 = struct.unpack_from(">H", frame_bytes, 41)[0]
    (
        leg2_market_id,
        leg2_side,
        leg2_price_ticks,
        leg2_qty_lots,
        leg1_is_market,
        leg1_reduce_only,
        leg2_is_market,
        leg2_reduce_only,
    ) = unpack_atomic_spread_aux(aux0, aux1, b2_hi16)
    leg1 = WireBasketLeg(
        market_id=hdr.market_id,
        side=hdr.side,
        price_ticks=hdr.price_ticks,
        qty_lots=hdr.qty_lots,
        is_market=leg1_is_market,
        reduce_only=leg1_reduce_only,
        margin_spot=margin_spot,
    )
    leg2 = WireBasketLeg(
        market_id=leg2_market_id,
        side=leg2_side,
        price_ticks=leg2_price_ticks,
        qty_lots=leg2_qty_lots,
        is_market=leg2_is_market,
        reduce_only=leg2_reduce_only,
        margin_spot=margin_spot,
    )
    num_legs, leg3, leg4 = unpack_wire_basket_legs34(frame_bytes, aux1)
    legs = [leg1, leg2]
    if num_legs >= 3:
        legs.append(leg3)
    if num_legs >= 4:
        legs.append(leg4)
    return hdr, legs, margin_spot


def pack_auto_liquidate_sweep_frame(
    account_id: int,
    market_id: int = 0,
    target_account_id: int = 0,
    max_qty_lots: int = 0,
    min_bounty_micro: int = 0,
    auto_offload_to_book: bool = True,
    seq_lo: int = 1,
    seq_hi50: int = DEFAULT_SEQ_HI50,
    key_lo64: int = DEFAULT_KEY_LO64,
    key_hi64: int = DEFAULT_KEY_HI64,
    stp: StpMode = StpMode.CANCEL_RESTING,
    hedge_margin_spot: bool = False,
    bounty_rebate_bid_bps: int = 0,
) -> bytes:
    bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
    if bid_bps_i > 0 and int(target_account_id) != 0 and int(target_account_id) == int(account_id):
        raise ValueError("Cannot submit bounty_rebate_bid_bps against own account_id")
    hdr = ArenaHeader(
        op=BaseOp.LIQUIDATE_ACCOUNT,
        tif=TimeInForce.IOC if auto_offload_to_book else TimeInForce.GTC,
        stp=stp,
        market_id=int(market_id) & 0xFFFF,
        account_id=account_id,
        side=OrderSide.BID,
        seq_lo=seq_lo,
        price_ticks=max(0, int(min_bounty_micro)),
        qty_lots=max(0, int(max_qty_lots)),
    )
    aux1 = LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP
    if not auto_offload_to_book:
        aux1 |= LIQ_AUX1_FLAG_NO_OFFLOAD
    if hedge_margin_spot:
        aux1 |= LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT
    frm = pack_wire_frame(
        hdr,
        int(target_account_id) & 0xFFFF_FFFF,
        aux1,
        seq_hi50,
        key_lo64,
        key_hi64,
    )
    if bid_bps_i > 0:
        frm = pack_wire_liq_bounty_rebate_bid_bps(frm, bid_bps_i, key_lo64, key_hi64, seq_hi50)
    return frm


@dataclass
class ArenaWireResponse:
    status_code: WireStatusCode
    order_status: WireOrderStatus
    wal_seq: int
    order_id: int
    filled_lots: int
    resting_lots: int
    avg_price_ticks: int
    best_bid_ticks: int
    best_ask_ticks: int
    fee_or_position: int
    bid_filled_lots: int = 0
    ask_filled_lots: int = 0
    side_fills_exact: bool = False

    def pack_bytes(self) -> bytes:
        os_byte = int(self.order_status) & 0x7F
        has_exact_side_fills = (
            (self.bid_filled_lots > 0 or self.ask_filled_lots > 0)
            and 0 <= int(self.bid_filled_lots) <= 0xFFFF
            and 0 <= int(self.wal_seq) <= 0xFFFF_FFFF
        )
        if has_exact_side_fills:
            os_byte |= 0x80
            w0_seq = ((int(self.bid_filled_lots) & 0xFFFF) << 32) | (int(self.wal_seq) & 0xFFFF_FFFF)
        else:
            w0_seq = int(self.wal_seq) & 0xFFFF_FFFF_FFFF
        w0 = ((int(self.status_code) & 0xFF) << 56) | (os_byte << 48) | w0_seq
        return struct.pack(
            ">QQQQqqqq",
            w0 & MASK64,
            int(self.order_id) & MASK64,
            int(self.filled_lots) & MASK64,
            int(self.resting_lots) & MASK64,
            int(self.avg_price_ticks),
            int(self.best_bid_ticks),
            int(self.best_ask_ticks),
            int(self.fee_or_position),
        )

    @classmethod
    def unpack_bytes(cls, raw: bytes) -> "ArenaWireResponse":
        if len(raw) != ARENA_WIRE_BYTES:
            raise ValueError(f"Expected 64 bytes, got {len(raw)}")
        w0, oid, filled, resting, avg_px, bid_px, ask_px, fee_pos = struct.unpack(
            ">QQQQqqqq", raw
        )
        os_raw = (w0 >> 48) & 0xFF
        if os_raw & 0x80:
            wal_seq = w0 & 0xFFFF_FFFF
            raw_bid16 = (w0 >> 32) & 0xFFFF
            bid_filled = min(filled, raw_bid16)
            ask_filled = filled - bid_filled
            side_fills_exact = True
        else:
            wal_seq = w0 & 0xFFFF_FFFF_FFFF
            bid_filled = 0
            ask_filled = 0
            side_fills_exact = (filled == 0)
        return cls(
            status_code=WireStatusCode((w0 >> 56) & 0xFF),
            order_status=WireOrderStatus(os_raw & 0x7F),
            wal_seq=wal_seq,
            order_id=oid,
            filled_lots=filled,
            resting_lots=resting,
            avg_price_ticks=avg_px,
            best_bid_ticks=bid_px,
            best_ask_ticks=ask_px,
            fee_or_position=fee_pos,
            bid_filled_lots=bid_filled,
            ask_filled_lots=ask_filled,
            side_fills_exact=side_fills_exact,
        )


_GLOBAL_SYNC_NONCE_LOCK = threading.Lock()
_SYNC_BASE_EPOCH_US: int = time.time_ns() // 1_000
_SYNC_BASE_PERF_US: int = time.perf_counter_ns() // 1_000
_GLOBAL_LAST_SYNC_NONCE: int = 0


def _alloc_monotonic_sync_nonce(instance_floor: int = 0) -> int:
    """Allocate a strictly monotonic process-wide microsecond sync nonce."""
    global _GLOBAL_LAST_SYNC_NONCE
    with _GLOBAL_SYNC_NONCE_LOCK:
        perf_elapsed_us = max(0, (time.perf_counter_ns() // 1_000) - _SYNC_BASE_PERF_US)
        now_us = max(time.time_ns() // 1_000, _SYNC_BASE_EPOCH_US + perf_elapsed_us)
        nxt = max(_GLOBAL_LAST_SYNC_NONCE + 1, int(instance_floor) + 1, now_us)
        _GLOBAL_LAST_SYNC_NONCE = nxt
        return nxt


class ArenaBinaryClient:
    """Low-latency 64-byte binary TCP (`TCP_NODELAY`) & UDP client."""

    @staticmethod
    def _is_non_mutating_op(op: BaseOp) -> bool:
        return op in (
            BaseOp.HEARTBEAT,
            BaseOp.QUERY_BOOK_BBO,
            BaseOp.QUERY_ACCOUNT,
            BaseOp.SET_CANCEL_ON_DISCONNECT,
        )

    def __init__(
        self,
        account_id: int,
        host: str = "127.0.0.1",
        tcp_port: int = 19100,
        udp_port: int = 19101,
        key_lo64: int = DEFAULT_KEY_LO64,
        key_hi64: int = DEFAULT_KEY_HI64,
        seq_hi50: int = DEFAULT_SEQ_HI50,
        initial_seq: int = 1,
        auto_retry_mutating_on_resync: bool = False,
    ) -> None:
        acct_int = int(account_id)
        if acct_int < 0 or acct_int > 0xFFFFFF:
            raise ValueError(
                f"account_id {account_id} out of 24-bit wire range [0, 16777215]"
            )
        self.account_id = acct_int
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.key_lo64 = key_lo64
        self.key_hi64 = key_hi64
        self.auto_retry_mutating_on_resync = bool(auto_retry_mutating_on_resync)
        self._default_init_seq_hi50 = int(seq_hi50) & ((1 << 50) - 1)
        self._default_init_seq = int(initial_seq) & 0x3FFF
        self._next_seq_by_account: Dict[int, int] = {
            self.account_id: self._default_init_seq
        }
        self._pending_hi50_wrap: Dict[int, bool] = {self.account_id: False}
        self._seq_hi50_by_account: Dict[int, int] = {
            self.account_id: self._default_init_seq_hi50
        }
        self._saved_cred_seq_state: Dict[tuple[int, int, int], tuple[int, int, bool]] = {}
        self._verified_seq_by_account: set[int] = set()
        self._ambiguous_disconnect_by_account: set[int] = set()
        self._last_sync_nonce: int = 0
        self._resyncing_hi50: bool = False
        self._tried_resync_hi50: bool = False
        self._tcp_sock: Optional[socket.socket] = None

    def _seq_bucket_account(self, account_id: Optional[int] = None) -> int:
        eff_acct = int(self.account_id if account_id is None else account_id)
        uses_prov = (self.key_lo64 != DEFAULT_KEY_LO64 or self.key_hi64 != DEFAULT_KEY_HI64)
        return int(self.account_id) if uses_prov else eff_acct

    @property
    def seq_hi50(self) -> int:
        return self._seq_hi50_by_account.get(int(self.account_id), self._default_init_seq_hi50)

    @seq_hi50.setter
    def seq_hi50(self, val: int) -> None:
        aid = int(self.account_id)
        self._seq_hi50_by_account[aid] = int(val) & ((1 << 50) - 1)
        self._pending_hi50_wrap[aid] = False
        self._verified_seq_by_account.discard(aid)

    def _effective_seq_hi50(self, account_id: Optional[int] = None) -> int:
        seq_acct = self._seq_bucket_account(account_id)
        return self._seq_hi50_by_account.get(seq_acct, self._default_init_seq_hi50)

    @property
    def _next_seq(self) -> int:
        return self._next_seq_by_account.get(int(self.account_id), self._default_init_seq)

    @_next_seq.setter
    def _next_seq(self, val: int) -> None:
        aid = int(self.account_id)
        self._next_seq_by_account[aid] = int(val) & 0x3FFF
        self._pending_hi50_wrap[aid] = False
        self._verified_seq_by_account.discard(aid)

    def set_seq_epoch(self, seq_hi50: int, next_seq_lo: int = 1) -> None:
        hi50_val = int(seq_hi50) & ((1 << 50) - 1)
        seq_val = int(next_seq_lo) & 0x3FFF
        self._default_init_seq_hi50 = hi50_val
        self._tried_resync_hi50 = False
        self._seq_hi50_by_account.clear()
        self._verified_seq_by_account.clear()
        self._ambiguous_disconnect_by_account.clear()
        self._seq_hi50_by_account[self.account_id] = hi50_val
        self._next_seq_by_account[self.account_id] = seq_val
        self._pending_hi50_wrap[self.account_id] = False

    def set_account_id(self, account_id: int) -> None:
        acct_int = int(account_id)
        if acct_int < 0 or acct_int > 0xFFFFFF:
            raise ValueError(
                f"account_id {account_id} out of 24-bit wire range [0, 16777215]"
            )
        self.account_id = acct_int
        self._next_seq_by_account.setdefault(self.account_id, self._default_init_seq)
        self._seq_hi50_by_account.setdefault(self.account_id, self._default_init_seq_hi50)
        self._pending_hi50_wrap.setdefault(self.account_id, False)

    def set_credentials(
        self,
        account_id: int,
        key_lo64: int,
        key_hi64: int,
        seq_hi50: Optional[int] = None,
        initial_seq: Optional[int] = None,
    ) -> None:
        acct_int = int(account_id)
        if acct_int < 0 or acct_int > 0xFFFFFF:
            raise ValueError(
                f"account_id {account_id} out of 24-bit wire range [0, 16777215]"
            )
        new_lo = int(key_lo64) & MASK64
        new_hi = int(key_hi64) & MASK64
        old_cred_key = (int(self.account_id), int(self.key_lo64), int(self.key_hi64))
        if int(self.account_id) in self._seq_hi50_by_account or int(self.account_id) in self._next_seq_by_account:
            self._saved_cred_seq_state[old_cred_key] = (
                self._seq_hi50_by_account.get(int(self.account_id), self._default_init_seq_hi50),
                self._next_seq_by_account.get(int(self.account_id), self._default_init_seq),
                bool(self._pending_hi50_wrap.get(int(self.account_id), False)),
            )
        self.account_id = acct_int
        self.key_lo64 = new_lo
        self.key_hi64 = new_hi
        self._tried_resync_hi50 = False
        self._verified_seq_by_account.clear()
        self._ambiguous_disconnect_by_account.clear()
        self._seq_hi50_by_account.clear()
        self._next_seq_by_account.clear()
        self._pending_hi50_wrap.clear()
        new_cred_key = (self.account_id, self.key_lo64, self.key_hi64)
        if seq_hi50 is None and initial_seq is None and new_cred_key in self._saved_cred_seq_state:
            s_hi50, s_next, s_wrap = self._saved_cred_seq_state[new_cred_key]
            self._default_init_seq_hi50 = DEFAULT_SEQ_HI50
            self._default_init_seq = 1
            self._seq_hi50_by_account[self.account_id] = s_hi50
            self._next_seq_by_account[self.account_id] = s_next
            self._pending_hi50_wrap[self.account_id] = s_wrap
        else:
            eff_hi50 = (
                (int(seq_hi50) & ((1 << 50) - 1))
                if seq_hi50 is not None
                else DEFAULT_SEQ_HI50
            )
            eff_seq = (
                (int(initial_seq) & 0x3FFF)
                if initial_seq is not None
                else 1
            )
            self._default_init_seq_hi50 = eff_hi50
            self._default_init_seq = eff_seq
            self._seq_hi50_by_account[self.account_id] = eff_hi50
            self._next_seq_by_account[self.account_id] = eff_seq
            self._pending_hi50_wrap[self.account_id] = False

    def has_ambiguous_disconnect(self, account_id: Optional[int] = None) -> bool:
        return self._seq_bucket_account(account_id) in self._ambiguous_disconnect_by_account

    def clear_ambiguous_disconnect(self, account_id: Optional[int] = None) -> None:
        if account_id is None:
            self._ambiguous_disconnect_by_account.clear()
        else:
            self._ambiguous_disconnect_by_account.discard(self._seq_bucket_account(account_id))

    def peek_next_seq_lo(self, account_id: Optional[int] = None) -> int:
        seq_acct = self._seq_bucket_account(account_id)
        return self._next_seq_by_account.get(seq_acct, self._default_init_seq)

    def connect_tcp(self, timeout: float = 2.5) -> None:
        self.close()
        raw_host = urllib.parse.unquote(str(self.host or "").strip())
        if not raw_host:
            raise OSError("ArenaBinaryClient host must not be empty")
        if raw_host.startswith("[") and raw_host.endswith("]"):
            raw_host = raw_host[1:-1]
        infos = socket.getaddrinfo(raw_host, self.tcp_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        last_err: Optional[OSError] = None
        s: Optional[socket.socket] = None
        for family, socktype, proto, _, sockaddr in infos:
            cand: Optional[socket.socket] = None
            try:
                cand = socket.socket(family, socktype, proto)
                cand.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                cand.settimeout(timeout)
                cand.connect(sockaddr)
                s = cand
                break
            except OSError as exc:
                last_err = exc
                if cand is not None:
                    try:
                        cand.close()
                    except OSError as cls_err:
                        _ = cls_err
        if s is None:
            raise (last_err or OSError(f"Unable to connect to {raw_host}:{self.tcp_port}"))
        self._tcp_sock = s

    def close(self) -> None:
        self._tried_resync_hi50 = False
        if self._tcp_sock is not None:
            try:
                self._tcp_sock.close()
            finally:
                self._tcp_sock = None

    def close_tcp(self) -> None:
        self.close()

    def _alloc_seq(self, account_id: Optional[int] = None) -> int:
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_acct = self._seq_bucket_account(eff_acct)
        if self._pending_hi50_wrap.get(seq_acct, False):
            self._pending_hi50_wrap[seq_acct] = False
            cur_hi50 = self._seq_hi50_by_account.get(seq_acct, self._default_init_seq_hi50)
            self._seq_hi50_by_account[seq_acct] = (cur_hi50 + 1) & ((1 << 50) - 1)
        seq = self._next_seq_by_account.get(seq_acct, self._default_init_seq) & 0x3FFF
        self._next_seq_by_account[seq_acct] = (seq + 1) & 0x3FFF
        if seq == 0x3FFF:
            self._pending_hi50_wrap[seq_acct] = True
        return seq

    def _send_frame_once(self, frame: bytes, use_udp: bool = False) -> ArenaWireResponse:
        is_mutating = False
        once_seq_acct = self.account_id
        if (
            len(frame) == ARENA_WIRE_BYTES
            and frame[24] == 0x01
            and frame[62] == 0xA1
            and frame[63] == 0xE0
        ):
            h_once, _, _, _ = unpack_wire_frame(frame)
            is_mutating = not self._is_non_mutating_op(h_once.op)
            once_seq_acct = self._seq_bucket_account(h_once.account_id)
        if use_udp:
            raw_host = urllib.parse.unquote(str(self.host or "").strip())
            if not raw_host:
                raise OSError("ArenaBinaryClient host must not be empty")
            if raw_host.startswith("[") and raw_host.endswith("]"):
                raw_host = raw_host[1:-1]
            infos = socket.getaddrinfo(raw_host, self.udp_port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            if not infos:
                raise OSError(f"Unable to resolve UDP host {raw_host}:{self.udp_port}")
            family, socktype, proto, _, sockaddr = infos[0]
            try:
                exp_ip = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
                if isinstance(exp_ip, ipaddress.IPv6Address) and exp_ip.ipv4_mapped is not None:
                    exp_ip = exp_ip.ipv4_mapped
            except ValueError:
                exp_ip = None
            exp_port = int(sockaddr[1])
            udp_deadline = time.monotonic() + 2.5
            with socket.socket(family, socktype, proto) as us:
                us.settimeout(2.5)
                us.sendto(frame, sockaddr)
                try:
                    while True:
                        rem_u = udp_deadline - time.monotonic()
                        if rem_u <= 0.0:
                            raise TimeoutError("UDP frame recv exceeded deadline waiting for server peer")
                        us.settimeout(max(0.01, rem_u))
                        data, peer = us.recvfrom(max(ARENA_WIRE_BYTES + 1, 2048))
                        peer_host = str(peer[0]).split("%", 1)[0]
                        peer_port = int(peer[1])
                        peer_matches = (peer_port == exp_port)
                        if peer_matches:
                            if exp_ip is not None:
                                try:
                                    got_ip = ipaddress.ip_address(peer_host)
                                    if isinstance(got_ip, ipaddress.IPv6Address) and got_ip.ipv4_mapped is not None:
                                        got_ip = got_ip.ipv4_mapped
                                    peer_matches = (got_ip == exp_ip)
                                except ValueError:
                                    peer_matches = (peer_host == str(sockaddr[0]))
                            else:
                                peer_matches = (peer_host == str(sockaddr[0]))
                        if peer_matches and len(data) == ARENA_WIRE_BYTES:
                            return ArenaWireResponse.unpack_bytes(data)
                except Exception:
                    if is_mutating:
                        self._ambiguous_disconnect_by_account.add(once_seq_acct)
                    raise

        if self._tcp_sock is None:
            self.connect_tcp()
        assert self._tcp_sock is not None
        prev_timeout = self._tcp_sock.gettimeout()
        eff_tcp_timeout = float(prev_timeout) if (prev_timeout is not None and float(prev_timeout) > 0.0) else 5.0
        tcp_deadline = time.monotonic() + eff_tcp_timeout
        tx_done = 0
        try:
            mv = memoryview(frame)
            while tx_done < len(frame):
                rem_t = tcp_deadline - time.monotonic()
                if rem_t <= 0.0:
                    raise TimeoutError("TCP frame send exceeded wall-clock deadline")
                self._tcp_sock.settimeout(max(0.01, rem_t))
                sent = self._tcp_sock.send(mv[tx_done:])
                if sent <= 0:
                    raise ConnectionError("Server closed TCP connection during send")
                tx_done += sent
            rx = bytearray()
            while len(rx) < ARENA_WIRE_BYTES:
                rem_t = tcp_deadline - time.monotonic()
                if rem_t <= 0.0:
                    raise TimeoutError("TCP frame recv exceeded wall-clock deadline")
                self._tcp_sock.settimeout(max(0.01, rem_t))
                chunk = self._tcp_sock.recv(ARENA_WIRE_BYTES - len(rx))
                if not chunk:
                    raise ConnectionError("Server closed TCP connection")
                rx.extend(chunk)
        except BaseException:
            if tx_done > 0 and is_mutating:
                self._ambiguous_disconnect_by_account.add(once_seq_acct)
            self.close_tcp()
            raise
        finally:
            if self._tcp_sock is not None:
                self._tcp_sock.settimeout(prev_timeout)
        return ArenaWireResponse.unpack_bytes(bytes(rx))

    def _sync_sequence_for_account(
        self,
        synced_acct: int,
        bump_hi50: bool = False,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        eff_acct = int(synced_acct)
        if eff_acct < 0 or eff_acct > 0xFFFFFF:
            raise ValueError(
                f"account_id {synced_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_acct = self._seq_bucket_account(eff_acct)
        hi50_mask = (1 << 50) - 1
        has_prev_hi50 = seq_acct in self._seq_hi50_by_account
        prev_hi50_val = self._seq_hi50_by_account.get(seq_acct, 0)
        has_prev_next = seq_acct in self._next_seq_by_account
        prev_next_val = self._next_seq_by_account.get(seq_acct, 0)
        has_prev_wrap = seq_acct in self._pending_hi50_wrap
        prev_wrap_val = self._pending_hi50_wrap.get(seq_acct, False)
        was_verified = seq_acct in self._verified_seq_by_account

        def _rollback_seq_state() -> None:
            if has_prev_hi50:
                self._seq_hi50_by_account[seq_acct] = prev_hi50_val
            else:
                self._seq_hi50_by_account.pop(seq_acct, None)
            if has_prev_next:
                self._next_seq_by_account[seq_acct] = prev_next_val
            else:
                self._next_seq_by_account.pop(seq_acct, None)
            if has_prev_wrap:
                self._pending_hi50_wrap[seq_acct] = prev_wrap_val
            else:
                self._pending_hi50_wrap.pop(seq_acct, None)
            if was_verified:
                self._verified_seq_by_account.add(seq_acct)
            else:
                self._verified_seq_by_account.discard(seq_acct)

        had_pending_wrap = bool(self._pending_hi50_wrap.get(seq_acct, False))
        pre_alloc_hi50 = self._seq_hi50_by_account.get(seq_acct, self._default_init_seq_hi50) & hi50_mask
        sync_seq_lo = self._alloc_seq(seq_acct)
        cur_hi50 = self._seq_hi50_by_account.get(seq_acct, self._default_init_seq_hi50) & hi50_mask
        # Avoid double-incrementing `seq_hi50` when `_alloc_seq` just consumed a pending 0x3FFF wrap!
        if had_pending_wrap:
            try_hi50 = cur_hi50
        else:
            try_hi50 = ((cur_hi50 + 1) & hi50_mask) if bump_hi50 else cur_hi50
        sync_nonce = _alloc_monotonic_sync_nonce(self._last_sync_nonce)
        self._last_sync_nonce = sync_nonce
        sync_hdr = ArenaHeader(
            op=BaseOp.HEARTBEAT,
            account_id=seq_acct,
            seq_lo=sync_seq_lo,
        )
        req = pack_wire_frame(
            sync_hdr,
            HEARTBEAT_AUX0_SYNC_SEQ,
            sync_nonce & MASK64,
            try_hi50,
            self.key_lo64,
            self.key_hi64,
        )
        try:
            resp = self._send_frame_once(req, use_udp=use_udp)
            tried_hi50_set = {try_hi50}
            fallback_candidates: List[int] = []
            if had_pending_wrap:
                fallback_candidates.append(pre_alloc_hi50)
            if not bump_hi50 and not had_pending_wrap:
                fallback_candidates.append((cur_hi50 + 1) & hi50_mask)
            fallback_candidates.append(DEFAULT_SEQ_HI50)
            for cand_hi50 in fallback_candidates:
                if resp.status_code != WireStatusCode.REJECT_INVALID_MAC:
                    break
                if cand_hi50 in tried_hi50_set:
                    continue
                tried_hi50_set.add(cand_hi50)
                sync_nonce = _alloc_monotonic_sync_nonce(sync_nonce)
                self._last_sync_nonce = sync_nonce
                cand_req = pack_wire_frame(
                    sync_hdr,
                    HEARTBEAT_AUX0_SYNC_SEQ,
                    sync_nonce & MASK64,
                    cand_hi50,
                    self.key_lo64,
                    self.key_hi64,
                )
                resp = self._send_frame_once(cand_req, use_udp=use_udp)
        except Exception:
            _rollback_seq_state()
            raise
        if resp.status_code == WireStatusCode.OK:
            synced_hi50 = resp.resting_lots & hi50_mask
            synced_last_seq_lo = resp.order_id & 0x3FFF
            if synced_last_seq_lo == 0x3FFF:
                self._seq_hi50_by_account[seq_acct] = (synced_hi50 + 1) & hi50_mask
                self._next_seq_by_account[seq_acct] = 0
            else:
                self._seq_hi50_by_account[seq_acct] = synced_hi50
                self._next_seq_by_account[seq_acct] = (synced_last_seq_lo + 1) & 0x3FFF
            self._pending_hi50_wrap[seq_acct] = False
            self._verified_seq_by_account.add(seq_acct)
        else:
            _rollback_seq_state()
        return resp

    def send_frame(self, frame: bytes, use_udp: bool = False) -> ArenaWireResponse:
        resp = self._send_frame_once(frame, use_udp=use_udp)
        valid_frame_shape = (
            len(frame) == ARENA_WIRE_BYTES
            and frame[24] == 0x01
            and frame[62] == 0xA1
            and frame[63] == 0xE0
        )
        if resp.status_code not in (WireStatusCode.REJECT_INVALID_MAC, WireStatusCode.REJECT_REPLAY_OR_STALE):
            if valid_frame_shape:
                hdr_ok, _, _, _ = unpack_wire_frame(frame)
                self._verified_seq_by_account.add(self._seq_bucket_account(hdr_ok.account_id))
            self._tried_resync_hi50 = False
            return resp
        if not valid_frame_shape or self._resyncing_hi50 or self._tried_resync_hi50:
            return resp
        uses_provisioned = (self.key_lo64 != DEFAULT_KEY_LO64 or self.key_hi64 != DEFAULT_KEY_HI64)
        hdr, rx_mac40, raw_aux0, raw_aux1 = unpack_wire_frame(frame)
        seq_acct = self._seq_bucket_account(hdr.account_id)
        is_latest_allocated = self.peek_next_seq_lo(hdr.account_id) == ((hdr.seq_lo + 1) & 0x3FFF)
        was_unverified_before_sync = seq_acct not in self._verified_seq_by_account
        is_unverified_stale = (
            uses_provisioned
            and resp.status_code == WireStatusCode.REJECT_REPLAY_OR_STALE
            and was_unverified_before_sync
            and is_latest_allocated
        )
        if (
            (resp.status_code == WireStatusCode.REJECT_INVALID_MAC and uses_provisioned and is_latest_allocated)
            or is_unverified_stale
        ):
            rx_tail48 = int.from_bytes(frame[56:62], "big")
            cur_hi50 = self._seq_hi50_by_account.get(seq_acct, self._default_init_seq_hi50)
            match_cur = (rx_mac40 == calc_pre_siphash40(hdr, cur_hi50, self.key_lo64, self.key_hi64))
            match_prev = (
                not match_cur
                and cur_hi50 > 0
                and rx_mac40 == calc_pre_siphash40(hdr, cur_hi50 - 1, self.key_lo64, self.key_hi64)
            )
            used_hi50 = (cur_hi50 - 1) if match_prev else cur_hi50
            old_hi50 = used_hi50
            pre_match = match_cur or match_prev
            if pre_match and rx_tail48 == calc_tail_siphash48(frame, self.key_lo64, self.key_hi64, used_hi50):
                self._tried_resync_hi50 = True
                self._resyncing_hi50 = True
                try:
                    sync_resp = self._sync_sequence_for_account(
                        seq_acct,
                        bump_hi50=is_unverified_stale,
                        use_udp=use_udp,
                    )
                    if sync_resp.status_code == WireStatusCode.OK:
                        is_unverified_pre_exec_mac = (
                            resp.status_code == WireStatusCode.REJECT_INVALID_MAC
                            and was_unverified_before_sync
                        )
                        may_auto_resubmit = self._is_non_mutating_op(hdr.op) or (
                            not self.has_ambiguous_disconnect(hdr.account_id)
                            and (self.auto_retry_mutating_on_resync or is_unverified_pre_exec_mac)
                        )
                        if not may_auto_resubmit:
                            return resp
                        old_seq = hdr.seq_lo
                        new_seq = self._alloc_seq(hdr.account_id)
                        eff_hi50 = self._effective_seq_hi50(hdr.account_id)
                        rebuilt_hdr = ArenaHeader(
                            op=hdr.op,
                            tif=hdr.tif,
                            stp=hdr.stp,
                            market_id=hdr.market_id,
                            account_id=hdr.account_id,
                            side=hdr.side,
                            seq_lo=new_seq,
                            price_ticks=hdr.price_ticks,
                            qty_lots=hdr.qty_lots,
                        )
                        m0, m1, hi24 = rebuilt_hdr.pack_words()
                        rebuilt = bytearray(frame)
                        struct.pack_into(">QQ", rebuilt, 0, m0, m1)
                        rebuilt[16] = (hi24 >> 16) & 0xFF
                        rebuilt[17] = (hi24 >> 8) & 0xFF
                        rebuilt[18] = hi24 & 0xFF
                        if (
                            hdr.op == BaseOp.REGISTER_SESSION_KEY
                            and (rebuilt[51] & WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0
                        ):
                            old_salt64 = struct.unpack_from(">Q", rebuilt, 41)[0]
                            if old_salt64 == 0:
                                raise ValueError("Missing non-zero wrap_salt64 on RegisterSessionKey resync")
                            old_pad_lo, old_pad_hi = compute_session_key_wrap_pad(
                                self.key_lo64, self.key_hi64, old_hi50, old_seq, hdr.account_id, old_salt64
                            )
                            new_k_lo = (raw_aux0 ^ old_pad_lo) & MASK64
                            new_k_hi = (raw_aux1 ^ old_pad_hi) & MASK64
                            new_salt64 = _sdk_csprng_u64_nonzero()
                            new_pad_lo, new_pad_hi = compute_session_key_wrap_pad(
                                self.key_lo64, self.key_hi64, eff_hi50, new_seq, hdr.account_id, new_salt64
                            )
                            struct.pack_into(
                                ">QQ",
                                rebuilt,
                                25,
                                (new_k_lo ^ new_pad_lo) & MASK64,
                                (new_k_hi ^ new_pad_hi) & MASK64,
                            )
                            struct.pack_into(">Q", rebuilt, 41, new_salt64)
                        rebuilt[19:24] = calc_pre_siphash40(
                            rebuilt_hdr, eff_hi50, self.key_lo64, self.key_hi64
                        ).to_bytes(5, "big")
                        rebuilt[56:62] = calc_tail_siphash48(
                            rebuilt, self.key_lo64, self.key_hi64, eff_hi50
                        ).to_bytes(6, "big")
                        retried = self._send_frame_once(bytes(rebuilt), use_udp=use_udp)
                        if retried.status_code not in (
                            WireStatusCode.REJECT_INVALID_MAC,
                            WireStatusCode.REJECT_REPLAY_OR_STALE,
                        ):
                            self._verified_seq_by_account.add(seq_acct)
                            self._tried_resync_hi50 = False
                        return retried
                finally:
                    self._resyncing_hi50 = False
        return resp

    def send_batch(self, frames: List[bytes], timeout: float = 5.0) -> List[ArenaWireResponse]:
        """Deadlock-free pipelined multi-frame TCP streaming batch round-trip."""
        if not frames:
            return []
        for idx, frm in enumerate(frames):
            if len(frm) != ARENA_WIRE_BYTES:
                raise ValueError(f"Frame {idx} must be {ARENA_WIRE_BYTES} bytes, got {len(frm)}")
        if self._tcp_sock is None:
            self.connect_tcp(timeout=timeout)
        assert self._tcp_sock is not None
        sock = self._tcp_sock

        tx_payload = b"".join(frames)
        total_bytes = len(tx_payload)
        tx_mv = memoryview(tx_payload)
        rx_buf = bytearray(total_bytes)
        rx_mv = memoryview(rx_buf)
        tx_off = 0
        rx_off = 0
        deadline = time.monotonic() + timeout

        prev_timeout = sock.gettimeout()
        sock.setblocking(False)
        try:
            with selectors.DefaultSelector() as sel:
                cur_mask = 0
                while tx_off < total_bytes or rx_off < total_bytes:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        raise TimeoutError(
                            f"Timed out during pipelined send_batch (tx={tx_off}/{total_bytes}, rx={rx_off}/{total_bytes})"
                        )
                    want_mask = (selectors.EVENT_READ if rx_off < total_bytes else 0) | (
                        selectors.EVENT_WRITE if tx_off < total_bytes else 0
                    )
                    if cur_mask == 0:
                        sel.register(sock, want_mask)
                        cur_mask = want_mask
                    elif want_mask != cur_mask:
                        sel.modify(sock, want_mask)
                        cur_mask = want_mask
                    events = sel.select(min(rem, 0.05))
                    if not events:
                        continue
                    ev_mask = events[0][1]
                    if (ev_mask & selectors.EVENT_WRITE) and tx_off < total_bytes:
                        tx_end = min(total_bytes, tx_off + 65536)
                        try:
                            sent = sock.send(tx_mv[tx_off:tx_end])
                        except (BlockingIOError, InterruptedError):
                            sent = None
                        if sent is not None:
                            if sent <= 0:
                                raise ConnectionError("TCP socket closed during send_batch write")
                            tx_off += sent
                    if (ev_mask & selectors.EVENT_READ) and rx_off < total_bytes:
                        rx_end = min(total_bytes, rx_off + 65536)
                        try:
                            got = sock.recv_into(rx_mv[rx_off:rx_end])
                        except (BlockingIOError, InterruptedError):
                            got = None
                        if got is not None:
                            if got == 0:
                                raise ConnectionError("Server closed TCP connection during send_batch read")
                            rx_off += got
        except Exception:
            if tx_off > 0:
                for idx_tx, frm_tx in enumerate(frames):
                    if idx_tx * ARENA_WIRE_BYTES >= tx_off:
                        break
                    if (
                        len(frm_tx) == ARENA_WIRE_BYTES
                        and frm_tx[24] == 0x01
                        and frm_tx[62] == 0xA1
                        and frm_tx[63] == 0xE0
                    ):
                        h_tx, _, _, _ = unpack_wire_frame(frm_tx)
                        if not self._is_non_mutating_op(h_tx.op):
                            self._ambiguous_disconnect_by_account.add(
                                self._seq_bucket_account(h_tx.account_id)
                            )
            self.close_tcp()
            raise
        finally:
            if self._tcp_sock is not None:
                sock.settimeout(prev_timeout if prev_timeout is not None else timeout)

        resps = [
            ArenaWireResponse.unpack_bytes(bytes(rx_mv[i * ARENA_WIRE_BYTES : (i + 1) * ARENA_WIRE_BYTES]))
            for i in range(len(frames))
        ]
        uses_provisioned = (self.key_lo64 != DEFAULT_KEY_LO64 or self.key_hi64 != DEFAULT_KEY_HI64)
        all_valid_shapes = all(
            len(frm) == ARENA_WIRE_BYTES and frm[24] == 0x01 and frm[62] == 0xA1 and frm[63] == 0xE0
            for frm in frames
        )
        if not self._resyncing_hi50 and not self._tried_resync_hi50 and resps and all_valid_shapes:
            last_seq_by_acct: Dict[int, int] = {}
            saw_max_seq_by_acct: set[int] = set()
            wrapped_in_batch: set[int] = set()
            contiguous_in_batch = True
            for frm in frames:
                h_f, _, _, _ = unpack_wire_frame(frm)
                b_acct = self._seq_bucket_account(h_f.account_id)
                if b_acct in last_seq_by_acct and h_f.seq_lo != ((last_seq_by_acct[b_acct] + 1) & 0x3FFF):
                    contiguous_in_batch = False
                if b_acct in saw_max_seq_by_acct and h_f.seq_lo == 0:
                    wrapped_in_batch.add(b_acct)
                if h_f.seq_lo == 0x3FFF:
                    saw_max_seq_by_acct.add(b_acct)
                last_seq_by_acct[b_acct] = h_f.seq_lo
            all_pre_exec_rejects = contiguous_in_batch
            accts_to_sync: Dict[int, tuple[int, bool]] = {}
            for frm, r in zip(frames, resps):
                h_i, mac_i, _, _ = unpack_wire_frame(frm)
                seq_acct_i = self._seq_bucket_account(h_i.account_id)
                if r.status_code not in (
                    WireStatusCode.REJECT_INVALID_MAC,
                    WireStatusCode.REJECT_REPLAY_OR_STALE,
                ):
                    all_pre_exec_rejects = False
                    self._verified_seq_by_account.add(seq_acct_i)
                    self._tried_resync_hi50 = False
                    continue
                if not uses_provisioned or self.peek_next_seq_lo(h_i.account_id) != (
                    (last_seq_by_acct[seq_acct_i] + 1) & 0x3FFF
                ):
                    all_pre_exec_rejects = False
                    continue
                if r.status_code == WireStatusCode.REJECT_REPLAY_OR_STALE and (
                    seq_acct_i in self._verified_seq_by_account
                ):
                    all_pre_exec_rejects = False
                    continue
                cand_hi50 = self._seq_hi50_by_account.get(seq_acct_i, self._default_init_seq_hi50)
                rx_tail48 = int.from_bytes(frm[56:62], "big")
                match_cur = (mac_i == calc_pre_siphash40(h_i, cand_hi50, self.key_lo64, self.key_hi64))
                match_prev = (
                    not match_cur
                    and seq_acct_i in wrapped_in_batch
                    and cand_hi50 > 0
                    and mac_i == calc_pre_siphash40(h_i, cand_hi50 - 1, self.key_lo64, self.key_hi64)
                )
                used_hi50 = (cand_hi50 - 1) if match_prev else cand_hi50
                mac_ok = (match_cur or match_prev) and rx_tail48 == calc_tail_siphash48(
                    frm, self.key_lo64, self.key_hi64, used_hi50
                )
                if not mac_ok:
                    all_pre_exec_rejects = False
                    continue
                need_bump = r.status_code == WireStatusCode.REJECT_REPLAY_OR_STALE
                prev_entry = accts_to_sync.get(seq_acct_i)
                if prev_entry is None:
                    accts_to_sync[seq_acct_i] = (seq_acct_i, need_bump)
                else:
                    accts_to_sync[seq_acct_i] = (prev_entry[0], prev_entry[1] or need_bump)
            if all_pre_exec_rejects and accts_to_sync:
                pre_hi50_map = dict(self._seq_hi50_by_account)
                pre_verified_set = set(self._verified_seq_by_account)
                self._tried_resync_hi50 = True
                self._resyncing_hi50 = True
                try:
                    synced = True
                    for _, (raw_aid, bump_h) in accts_to_sync.items():
                        sync_resp = self._sync_sequence_for_account(
                            raw_aid, bump_hi50=bump_h, use_udp=False
                        )
                        if sync_resp.status_code != WireStatusCode.OK:
                            synced = False
                            break
                    if synced:
                        batch_may_auto_resubmit = True
                        for orig_chk, r_chk in zip(frames, resps):
                            h_chk, _, _, _ = unpack_wire_frame(orig_chk)
                            chk_seq_acct = self._seq_bucket_account(h_chk.account_id)
                            is_unverified_pre_exec_mac = (
                                r_chk.status_code == WireStatusCode.REJECT_INVALID_MAC
                                and chk_seq_acct not in pre_verified_set
                            )
                            if not (
                                self._is_non_mutating_op(h_chk.op)
                                or (
                                    not self.has_ambiguous_disconnect(h_chk.account_id)
                                    and (self.auto_retry_mutating_on_resync or is_unverified_pre_exec_mac)
                                )
                            ):
                                batch_may_auto_resubmit = False
                                break
                        if not batch_may_auto_resubmit:
                            return resps
                        rebuilt_frames: List[bytes] = []
                        for orig in frames:
                            hdr, rx_mac40, raw_aux0, raw_aux1 = unpack_wire_frame(orig)
                            orig_acct = self._seq_bucket_account(hdr.account_id)
                            old_hi50 = pre_hi50_map.get(orig_acct, self._default_init_seq_hi50)
                            if (
                                old_hi50 > 0
                                and calc_pre_siphash40(hdr, old_hi50, self.key_lo64, self.key_hi64) != rx_mac40
                                and calc_pre_siphash40(hdr, old_hi50 - 1, self.key_lo64, self.key_hi64) == rx_mac40
                            ):
                                old_hi50 -= 1
                            old_seq = hdr.seq_lo
                            new_seq = self._alloc_seq(hdr.account_id)
                            eff_hi50 = self._effective_seq_hi50(hdr.account_id)
                            rebuilt_hdr = ArenaHeader(
                                op=hdr.op,
                                tif=hdr.tif,
                                stp=hdr.stp,
                                market_id=hdr.market_id,
                                account_id=hdr.account_id,
                                side=hdr.side,
                                seq_lo=new_seq,
                                price_ticks=hdr.price_ticks,
                                qty_lots=hdr.qty_lots,
                            )
                            m0, m1, hi24 = rebuilt_hdr.pack_words()
                            rebuilt = bytearray(orig)
                            struct.pack_into(">QQ", rebuilt, 0, m0, m1)
                            rebuilt[16] = (hi24 >> 16) & 0xFF
                            rebuilt[17] = (hi24 >> 8) & 0xFF
                            rebuilt[18] = hi24 & 0xFF
                            if (
                                hdr.op == BaseOp.REGISTER_SESSION_KEY
                                and (rebuilt[51] & WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0
                            ):
                                old_salt64 = struct.unpack_from(">Q", rebuilt, 41)[0]
                                if old_salt64 == 0:
                                    raise ValueError("Missing non-zero wrap_salt64 on RegisterSessionKey batch resync")
                                old_pad_lo, old_pad_hi = compute_session_key_wrap_pad(
                                    self.key_lo64, self.key_hi64, old_hi50, old_seq, hdr.account_id, old_salt64
                                )
                                new_k_lo = (raw_aux0 ^ old_pad_lo) & MASK64
                                new_k_hi = (raw_aux1 ^ old_pad_hi) & MASK64
                                new_salt64 = _sdk_csprng_u64_nonzero()
                                new_pad_lo, new_pad_hi = compute_session_key_wrap_pad(
                                    self.key_lo64, self.key_hi64, eff_hi50, new_seq, hdr.account_id, new_salt64
                                )
                                struct.pack_into(
                                    ">QQ",
                                    rebuilt,
                                    25,
                                    (new_k_lo ^ new_pad_lo) & MASK64,
                                    (new_k_hi ^ new_pad_hi) & MASK64,
                                )
                                struct.pack_into(">Q", rebuilt, 41, new_salt64)
                            rebuilt[19:24] = calc_pre_siphash40(
                                rebuilt_hdr, eff_hi50, self.key_lo64, self.key_hi64
                            ).to_bytes(5, "big")
                            rebuilt[56:62] = calc_tail_siphash48(
                                rebuilt, self.key_lo64, self.key_hi64, eff_hi50
                            ).to_bytes(6, "big")
                            rebuilt_frames.append(bytes(rebuilt))
                        self._resyncing_hi50 = False
                        return self.send_batch(rebuilt_frames, timeout=timeout)
                finally:
                    self._resyncing_hi50 = False
        elif all_valid_shapes:
            for frm, r in zip(frames, resps):
                if r.status_code not in (
                    WireStatusCode.REJECT_INVALID_MAC,
                    WireStatusCode.REJECT_REPLAY_OR_STALE,
                ):
                    h_i, _, _, _ = unpack_wire_frame(frm)
                    self._verified_seq_by_account.add(self._seq_bucket_account(h_i.account_id))
                    self._tried_resync_hi50 = False
        return resps

    def build_order_frame(
        self,
        market_id: int,
        side: OrderSide,
        price_ticks: int,
        qty_lots: int,
        tif: TimeInForce = TimeInForce.GTC,
        stp: StpMode = StpMode.CANCEL_RESTING,
        reduce_only: bool = False,
        is_market: bool = False,
        cancel_on_disconnect: bool = False,
        client_tag: int = 0,
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp_decrement_and_cancel: bool = False,
        account_id: Optional[int] = None,
        priority_fee_ppm: int = 0,
    ) -> bytes:
        px = _validate_price_ticks_48(price_ticks, "price_ticks")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        prio_ppm_i = int(priority_fee_ppm)
        if not (0 <= prio_ppm_i <= MAX_PRIORITY_FEE_PPM):
            raise ValueError(f"priority_fee_ppm {prio_ppm_i} out of [0, {MAX_PRIORITY_FEE_PPM}]")
        if not (1 <= int(qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"qty_lots {qty_lots} out of 40-bit wire range [1, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        if not (0 <= int(client_tag) <= MASK64):
            raise ValueError("client_tag out of 64-bit unsigned range [0, 2^64 - 1]")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        eff_client_tag = client_tag
        aux1 = pack_order_aux1(
            reduce_only=reduce_only,
            is_market=is_market,
            cancel_on_disconnect=cancel_on_disconnect,
            post_only_slide=post_only_slide,
            min_qty_lots=min_qty_lots,
            primary_peg=primary_peg,
            midpoint_peg=midpoint_peg,
            margin_spot=margin_spot,
            display_qty_lots=display_qty_lots,
            dark_midpoint=dark_midpoint,
            auto_skew_ticks=auto_skew_ticks,
            peg_offset_ticks=peg_offset_ticks,
            oco_linked=oco_linked,
            max_lifetime_wal_seqs=max_lifetime_wal_seqs,
            jit_elastic_mult=jit_elastic_mult,
            mark_peg=mark_peg,
            auto_flip_ticks=auto_flip_ticks,
            trailing_peg=trailing_peg,
        )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.NEW_ORDER,
            tif=tif,
            stp=stp,
            market_id=market_id,
            account_id=eff_acct,
            side=side,
            seq_lo=seq_lo,
            price_ticks=px,
            qty_lots=qty_lots,
        )
        raw = bytearray(pack_wire_frame(hdr, eff_client_tag, aux1, eff_hi50, self.key_lo64, self.key_hi64))
        need_rehash = False
        if stp_decrement_and_cancel:
            raw[51] |= WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL
            need_rehash = True
        if (
            prio_ppm_i > 0
            and tif != TimeInForce.POST_ONLY
            and not (
                post_only_slide
                or primary_peg
                or midpoint_peg
                or dark_midpoint
                or mark_peg
                or trailing_peg
            )
        ):
            struct.pack_into(">H", raw, 52, prio_ppm_i)
            need_rehash = True
        if need_rehash:
            tail48 = calc_tail_siphash48(raw, self.key_lo64, self.key_hi64, eff_hi50)
            for i in range(6):
                raw[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
        return bytes(raw)

    def build_cancel_frame(
        self, market_id: int, order_id: int, account_id: Optional[int] = None
    ) -> bytes:
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (0 <= int(order_id) <= MASK64):
            raise ValueError("order_id out of 64-bit unsigned range [0, 2^64 - 1]")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.CANCEL,
            market_id=market_id,
            account_id=eff_acct,
            seq_lo=seq_lo,
        )
        return pack_wire_frame(hdr, order_id, 0, eff_hi50, self.key_lo64, self.key_hi64)

    def build_quote_frame(
        self,
        market_id: int,
        bid_price_ticks: int,
        bid_qty_lots: int,
        ask_price_ticks: int,
        ask_qty_lots: int,
        tif: TimeInForce = TimeInForce.GTC,
        stp: StpMode = StpMode.CANCEL_RESTING,
        cancel_on_disconnect: bool = False,
        post_only_slide: bool = False,
        margin_spot: bool = False,
        auto_skew_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        auto_flip_ticks: int = 0,
        quote_peg_mode: int = 0,
        peg_offset_ticks: int = 0,
        client_tag: int = 0,
        ladder_by_tag: bool = False,
        account_id: Optional[int] = None,
    ) -> bytes:
        bid_px = _validate_price_ticks_48(bid_price_ticks, "bid_price_ticks")
        ask_px = _validate_price_ticks_48(ask_price_ticks, "ask_price_ticks")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (0 <= int(client_tag) <= MASK64):
            raise ValueError("client_tag out of 64-bit unsigned range [0, 2^64 - 1]")
        if not (0 <= int(bid_qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"bid_qty_lots {bid_qty_lots} out of 40-bit wire range [0, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        if not (0 <= int(ask_qty_lots) <= QUOTE_AUX_QTY_50_MASK):
            raise ValueError(
                f"ask_qty_lots {ask_qty_lots} out of 50-bit wire range [0, {QUOTE_AUX_QTY_50_MASK}]"
            )
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        aux0 = ask_px & MASK64
        aux1 = pack_quote_aux1(
            ask_qty_lots=ask_qty_lots,
            cancel_on_disconnect=cancel_on_disconnect,
            post_only_slide=post_only_slide,
            margin_spot=margin_spot,
            auto_skew_ticks=auto_skew_ticks,
            oco_linked=oco_linked,
            max_lifetime_wal_seqs=max_lifetime_wal_seqs,
            jit_elastic_mult=jit_elastic_mult,
            auto_flip_ticks=auto_flip_ticks,
            quote_peg_mode=quote_peg_mode,
            peg_offset_ticks=peg_offset_ticks,
        )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.TWO_SIDED_QUOTE_REPLACE,
            tif=tif,
            stp=stp,
            market_id=market_id,
            account_id=eff_acct,
            side=OrderSide.BID,
            seq_lo=seq_lo,
            price_ticks=bid_px,
            qty_lots=bid_qty_lots,
        )
        raw = bytearray(
            pack_wire_frame(
                hdr,
                aux0,
                aux1,
                eff_hi50,
                self.key_lo64,
                self.key_hi64,
                ext_qty_hi16=pack_quote_ask_qty_hi16(ask_qty_lots),
            )
        )
        if client_tag != 0 or ladder_by_tag:
            struct.pack_into(">Q", raw, 43, int(client_tag) & MASK64)
            if ladder_by_tag:
                raw[51] |= WIRE_EXT51_FLAG_LADDER_BY_TAG
            tail48 = calc_tail_siphash48(raw, self.key_lo64, self.key_hi64, eff_hi50)
            for i in range(6):
                raw[56 + i] = (tail48 >> (40 - 8 * i)) & 0xFF
        return bytes(raw)

    def build_cod_frame(
        self, market_id: int = 0, enable: bool = True, timeout_ms: int = 0
    ) -> bytes:
        if not (0 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [0, 65535]")
        if not (0 <= int(timeout_ms) <= 86_400_000):
            raise ValueError("timeout_ms out of [0, 86400000]")
        hdr = ArenaHeader(
            op=BaseOp.SET_CANCEL_ON_DISCONNECT,
            market_id=market_id,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
        )
        return pack_wire_frame(
            hdr, 1 if enable else 0, timeout_ms, self.seq_hi50, self.key_lo64, self.key_hi64
        )

    def build_atomic_spread_frame(
        self,
        leg1_market_id: int,
        leg1_side: OrderSide,
        leg1_price_ticks: int,
        leg1_qty_lots: int,
        leg2_market_id: int,
        leg2_side: OrderSide,
        leg2_price_ticks: int,
        leg2_qty_lots: int,
        leg1_is_market: bool = False,
        leg1_reduce_only: bool = False,
        leg2_is_market: bool = False,
        leg2_reduce_only: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        margin_spot: bool = False,
        account_id: Optional[int] = None,
        express_surplus_bid_bps: int = 0,
    ) -> bytes:
        bid_bps_i = int(express_surplus_bid_bps)
        if not (0 <= bid_bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
            raise ValueError(
                f"express_surplus_bid_bps {bid_bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
            )
        l1_px = _validate_price_ticks_48(leg1_price_ticks, "leg1_price_ticks")
        _validate_price_ticks_48(leg2_price_ticks, "leg2_price_ticks")
        if not (1 <= int(leg1_market_id) <= 0xFFFF):
            raise ValueError("leg1_market_id out of [1, 65535]")
        if not (1 <= int(leg2_market_id) <= 0xFFFF):
            raise ValueError("leg2_market_id out of [1, 65535]")
        if not (1 <= int(leg1_qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"leg1_qty_lots {leg1_qty_lots} out of 40-bit wire range [1, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        if not (1 <= int(leg2_qty_lots) <= QUOTE_AUX_QTY_50_MASK):
            raise ValueError(
                f"leg2_qty_lots {leg2_qty_lots} out of 50-bit wire range [1, {QUOTE_AUX_QTY_50_MASK}]"
            )
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        aux0, aux1 = pack_atomic_spread_aux(
            leg2_market_id=leg2_market_id,
            leg2_side=leg2_side,
            leg2_price_ticks=leg2_price_ticks,
            leg2_qty_lots=leg2_qty_lots,
            leg1_is_market=leg1_is_market,
            leg1_reduce_only=leg1_reduce_only,
            leg2_is_market=leg2_is_market,
            leg2_reduce_only=leg2_reduce_only,
            margin_spot=margin_spot,
        )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.ATOMIC_SPREAD,
            tif=TimeInForce.IOC,
            stp=stp,
            market_id=leg1_market_id,
            account_id=eff_acct,
            side=leg1_side,
            seq_lo=seq_lo,
            price_ticks=l1_px,
            qty_lots=leg1_qty_lots,
        )
        frm = pack_wire_frame(
            hdr,
            aux0,
            aux1,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
            ext_qty_hi16=pack_quote_ask_qty_hi16(leg2_qty_lots),
        )
        if bid_bps_i > 0:
            frm = pack_wire_express_surplus_bid_bps(frm, bid_bps_i, self.key_lo64, self.key_hi64, eff_hi50)
        return frm

    def build_atomic_basket_frame(
        self,
        legs: List[WireBasketLeg],
        stp: StpMode = StpMode.CANCEL_RESTING,
        margin_spot: bool = False,
        account_id: Optional[int] = None,
        express_surplus_bid_bps: int = 0,
    ) -> bytes:
        _validate_wire_basket_legs(legs)
        bid_bps_i = int(express_surplus_bid_bps)
        if not (0 <= bid_bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
            raise ValueError(
                f"express_surplus_bid_bps {bid_bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
            )
        if len(legs) >= 4 and bid_bps_i > 0:
            raise ValueError("express_surplus_bid_bps cannot be combined with 4-leg wire baskets")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        return pack_wire_basket_frame(
            account_id=eff_acct,
            legs=legs,
            stp=stp,
            margin_spot=margin_spot,
            seq_lo=seq_lo,
            seq_hi50=eff_hi50,
            key_lo64=self.key_lo64,
            key_hi64=self.key_hi64,
            express_surplus_bid_bps=bid_bps_i,
        )

    def build_mint_redeem_frame(
        self,
        market_id: int,
        side: OrderSide,
        qty_lots: int,
        limit_cost_or_payout_micro: int = 0,
        account_id: Optional[int] = None,
    ) -> bytes:
        if limit_cost_or_payout_micro < 0 or limit_cost_or_payout_micro > ((1 << 63) - 1):
            raise ValueError("limit_cost_or_payout_micro must be in [0, 2^63 - 1]")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (1 <= int(qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"qty_lots out of 40-bit wire range [1, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.MINT_REDEEM_SET,
            tif=TimeInForce.IOC,
            stp=StpMode.CANCEL_RESTING,
            market_id=market_id,
            account_id=eff_acct,
            side=side,
            seq_lo=seq_lo,
            price_ticks=min(limit_cost_or_payout_micro, (1 << 47) - 1),
            qty_lots=qty_lots,
        )
        aux0 = limit_cost_or_payout_micro if limit_cost_or_payout_micro > 0 else 0
        return pack_wire_frame(hdr, aux0, 0, eff_hi50, self.key_lo64, self.key_hi64)

    def build_flash_arbitrage_frame(
        self,
        market_id: int,
        side: OrderSide,
        qty_lots: int,
        limit_price_ticks: int = 0,
        min_profit_micro: int = 0,
        is_market: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        express_surplus_bid_bps: int = 0,
        account_id: Optional[int] = None,
    ) -> bytes:
        bid_bps_i = int(express_surplus_bid_bps)
        if not (0 <= bid_bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
            raise ValueError(
                f"express_surplus_bid_bps {bid_bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
            )
        lim_px = _validate_price_ticks_48(limit_price_ticks, "limit_price_ticks")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (1 <= int(qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"qty_lots out of 40-bit wire range [1, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        min_prof = int(min_profit_micro)
        if not (-(1 << 63) <= min_prof <= ((1 << 63) - 1)):
            raise ValueError("min_profit_micro out of signed 64-bit range [-2^63, 2^63 - 1]")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        aux1 = MINT_AUX1_FLAG_FLASH_ARB
        if is_market or lim_px <= 0:
            aux1 |= MINT_AUX1_FLAG_FLASH_MARKET
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.MINT_REDEEM_SET,
            tif=TimeInForce.IOC,
            stp=stp,
            market_id=market_id,
            account_id=eff_acct,
            side=side,
            seq_lo=seq_lo,
            price_ticks=lim_px,
            qty_lots=qty_lots,
        )
        frm = pack_wire_frame(
            hdr, int(min_profit_micro) & MASK64, aux1, eff_hi50, self.key_lo64, self.key_hi64
        )
        if bid_bps_i > 0:
            frm = pack_wire_express_surplus_bid_bps(frm, bid_bps_i, self.key_lo64, self.key_hi64, eff_hi50)
        return frm

    def deposit_usd(self, amount_micro: int, use_udp: bool = False) -> ArenaWireResponse:
        amt = int(amount_micro)
        if amt <= 0 or amt > ((1 << 63) - 1):
            raise ValueError("amount_micro must be in [1, 2^63 - 1]")
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.DEPOSIT_COLLATERAL,
            account_id=self.account_id,
            seq_lo=seq_lo,
        )
        return self.send_frame(
            pack_wire_frame(hdr, 0, amt, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def withdraw_usd(self, amount_micro: int, use_udp: bool = False) -> ArenaWireResponse:
        amt = int(amount_micro)
        if amt <= 0 or amt > ((1 << 63) - 1):
            raise ValueError("amount_micro must be in [1, 2^63 - 1]")
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.WITHDRAW_COLLATERAL,
            account_id=self.account_id,
            seq_lo=seq_lo,
        )
        return self.send_frame(
            pack_wire_frame(hdr, 0, amt, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def deposit_base(self, asset_id: int, lots: int, use_udp: bool = False) -> ArenaWireResponse:
        aid_b = int(asset_id)
        qty_b = int(lots)
        if not (1 <= aid_b <= 0xFF):
            raise ValueError("asset_id must be in [1, 255]")
        if not (1 <= qty_b <= ((1 << 63) - 1)):
            raise ValueError("lots must be in [1, 2^63 - 1]")
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.DEPOSIT_COLLATERAL,
            account_id=self.account_id,
            seq_lo=seq_lo,
        )
        return self.send_frame(
            pack_wire_frame(hdr, aid_b, qty_b, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def withdraw_base(self, asset_id: int, lots: int, use_udp: bool = False) -> ArenaWireResponse:
        aid_b = int(asset_id)
        qty_b = int(lots)
        if not (1 <= aid_b <= 0xFF):
            raise ValueError("asset_id must be in [1, 255]")
        if not (1 <= qty_b <= ((1 << 63) - 1)):
            raise ValueError("lots must be in [1, 2^63 - 1]")
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.WITHDRAW_COLLATERAL,
            account_id=self.account_id,
            seq_lo=seq_lo,
        )
        return self.send_frame(
            pack_wire_frame(hdr, aid_b, qty_b, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def place_order(
        self,
        market_id: int,
        side: OrderSide,
        price_ticks: int,
        qty_lots: int,
        tif: TimeInForce = TimeInForce.GTC,
        stp: StpMode = StpMode.CANCEL_RESTING,
        reduce_only: bool = False,
        is_market: bool = False,
        client_tag: int = 0,
        use_udp: bool = False,
        cancel_on_disconnect: bool = False,
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp_decrement_and_cancel: bool = False,
        account_id: Optional[int] = None,
        priority_fee_ppm: int = 0,
    ) -> ArenaWireResponse:
        frame = self.build_order_frame(
            market_id=market_id,
            side=side,
            price_ticks=price_ticks,
            qty_lots=qty_lots,
            tif=tif,
            stp=stp,
            reduce_only=reduce_only,
            is_market=is_market,
            cancel_on_disconnect=cancel_on_disconnect,
            client_tag=client_tag,
            post_only_slide=post_only_slide,
            min_qty_lots=min_qty_lots,
            primary_peg=primary_peg,
            midpoint_peg=midpoint_peg,
            margin_spot=margin_spot,
            display_qty_lots=display_qty_lots,
            dark_midpoint=dark_midpoint,
            auto_skew_ticks=auto_skew_ticks,
            peg_offset_ticks=peg_offset_ticks,
            oco_linked=oco_linked,
            max_lifetime_wal_seqs=max_lifetime_wal_seqs,
            jit_elastic_mult=jit_elastic_mult,
            mark_peg=mark_peg,
            auto_flip_ticks=auto_flip_ticks,
            trailing_peg=trailing_peg,
            stp_decrement_and_cancel=stp_decrement_and_cancel,
            account_id=account_id,
            priority_fee_ppm=priority_fee_ppm,
        )
        return self.send_frame(frame, use_udp=use_udp)

    submit_order = place_order

    def set_cancel_on_disconnect(
        self, market_id: int = 0, enable: bool = True, timeout_ms: int = 0
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_cod_frame(market_id=market_id, enable=enable, timeout_ms=timeout_ms),
            use_udp=False,
        )

    def quote_replace(
        self,
        market_id: int,
        bid_price_ticks: int,
        bid_qty_lots: int,
        ask_price_ticks: int,
        ask_qty_lots: int,
        tif: TimeInForce = TimeInForce.GTC,
        stp: StpMode = StpMode.CANCEL_RESTING,
        cancel_on_disconnect: bool = False,
        post_only_slide: bool = False,
        margin_spot: bool = False,
        auto_skew_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        auto_flip_ticks: int = 0,
        quote_peg_mode: int = 0,
        peg_offset_ticks: int = 0,
        client_tag: int = 0,
        ladder_by_tag: bool = False,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        frame = self.build_quote_frame(
            market_id=market_id,
            bid_price_ticks=bid_price_ticks,
            bid_qty_lots=bid_qty_lots,
            ask_price_ticks=ask_price_ticks,
            ask_qty_lots=ask_qty_lots,
            tif=tif,
            stp=stp,
            cancel_on_disconnect=cancel_on_disconnect,
            post_only_slide=post_only_slide,
            margin_spot=margin_spot,
            auto_skew_ticks=auto_skew_ticks,
            oco_linked=oco_linked,
            max_lifetime_wal_seqs=max_lifetime_wal_seqs,
            jit_elastic_mult=jit_elastic_mult,
            auto_flip_ticks=auto_flip_ticks,
            quote_peg_mode=quote_peg_mode,
            peg_offset_ticks=peg_offset_ticks,
            client_tag=client_tag,
            ladder_by_tag=ladder_by_tag,
            account_id=account_id,
        )
        return self.send_frame(frame, use_udp=use_udp)

    two_sided_quote_replace = quote_replace

    def atomic_basket(
        self,
        legs: List[WireBasketLeg],
        stp: StpMode = StpMode.CANCEL_RESTING,
        margin_spot: bool = False,
        use_udp: bool = False,
        express_surplus_bid_bps: int = 0,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        frame = self.build_atomic_basket_frame(
            legs=legs,
            stp=stp,
            margin_spot=margin_spot,
            account_id=account_id,
            express_surplus_bid_bps=express_surplus_bid_bps,
        )
        return self.send_frame(frame, use_udp=use_udp)

    send_atomic_basket = atomic_basket

    def atomic_spread(
        self,
        leg1_market_id: int,
        leg1_side: OrderSide,
        leg1_price_ticks: int,
        leg1_qty_lots: int,
        leg2_market_id: int,
        leg2_side: OrderSide,
        leg2_price_ticks: int,
        leg2_qty_lots: int,
        leg1_is_market: bool = False,
        leg1_reduce_only: bool = False,
        leg2_is_market: bool = False,
        leg2_reduce_only: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        margin_spot: bool = False,
        use_udp: bool = False,
        express_surplus_bid_bps: int = 0,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        frame = self.build_atomic_spread_frame(
            leg1_market_id=leg1_market_id,
            leg1_side=leg1_side,
            leg1_price_ticks=leg1_price_ticks,
            leg1_qty_lots=leg1_qty_lots,
            leg2_market_id=leg2_market_id,
            leg2_side=leg2_side,
            leg2_price_ticks=leg2_price_ticks,
            leg2_qty_lots=leg2_qty_lots,
            leg1_is_market=leg1_is_market,
            leg1_reduce_only=leg1_reduce_only,
            leg2_is_market=leg2_is_market,
            leg2_reduce_only=leg2_reduce_only,
            stp=stp,
            margin_spot=margin_spot,
            account_id=account_id,
            express_surplus_bid_bps=express_surplus_bid_bps,
        )
        return self.send_frame(frame, use_udp=use_udp)

    def mint_redeem_set(
        self,
        market_id: int,
        side: OrderSide,
        qty_lots: int,
        limit_cost_or_payout_micro: int = 0,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        frame = self.build_mint_redeem_frame(
            market_id=market_id,
            side=side,
            qty_lots=qty_lots,
            limit_cost_or_payout_micro=limit_cost_or_payout_micro,
            account_id=account_id,
        )
        return self.send_frame(frame, use_udp=use_udp)

    def flash_arbitrage(
        self,
        market_id: int,
        side: OrderSide,
        qty_lots: int,
        limit_price_ticks: int = 0,
        min_profit_micro: int = 0,
        is_market: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        use_udp: bool = False,
        express_surplus_bid_bps: int = 0,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        frame = self.build_flash_arbitrage_frame(
            market_id=market_id,
            side=side,
            qty_lots=qty_lots,
            limit_price_ticks=limit_price_ticks,
            min_profit_micro=min_profit_micro,
            is_market=is_market,
            stp=stp,
            express_surplus_bid_bps=express_surplus_bid_bps,
            account_id=account_id,
        )
        return self.send_frame(frame, use_udp=use_udp)

    def cancel_order(
        self,
        market_id: int,
        order_id: int,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_cancel_frame(market_id=market_id, order_id=order_id, account_id=account_id),
            use_udp=use_udp,
        )

    def cancel_all(
        self,
        market_id: int = 0,
        client_tag_filter: int = 0,
        market_bitmask: int = 0,
        side_filter: int | str = 0,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        if not (0 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [0, 65535]")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        if not (0 <= int(client_tag_filter) <= CANCEL_ALL_TAG_MASK) or (
            int(client_tag_filter) != 0 and (int(client_tag_filter) & CANCEL_ALL_TAG_MASK) == 0
        ):
            raise ValueError("client_tag_filter out of 62-bit unsigned range [0, 2^62 - 1]")
        if not (0 <= int(market_bitmask) <= MASK64):
            raise ValueError("market_bitmask out of 64-bit unsigned range [0, 2^64 - 1]")
        aux0 = int(client_tag_filter) & CANCEL_ALL_TAG_MASK
        sf_norm = side_filter.strip().lower() if isinstance(side_filter, str) else side_filter
        if sf_norm in (0, "", None):
            aux0 |= 0
        elif sf_norm in (1, "bid", "bids", "buy"):
            aux0 |= CANCEL_ALL_FLAG_BID_ONLY
        elif sf_norm in (2, "ask", "asks", "sell"):
            aux0 |= CANCEL_ALL_FLAG_ASK_ONLY
        else:
            raise ValueError(f"Invalid side_filter {side_filter!r}; expected 0|1|2|'bid'|'ask'")
        hdr = ArenaHeader(
            op=BaseOp.CANCEL_ALL_ACCOUNT,
            market_id=market_id,
            account_id=eff_acct,
            seq_lo=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        return self.send_frame(
            pack_wire_frame(
                hdr,
                aux0 & MASK64,
                market_bitmask & MASK64,
                eff_hi50,
                self.key_lo64,
                self.key_hi64,
            ),
            use_udp=use_udp,
        )

    def heartbeat(self, use_udp: bool = False, account_id: Optional[int] = None) -> ArenaWireResponse:
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.HEARTBEAT,
            account_id=eff_acct,
            seq_lo=seq_lo,
        )
        return self.send_frame(
            pack_wire_frame(hdr, 0, 0, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def sync_sequence(
        self, use_udp: bool = False, account_id: Optional[int] = None
    ) -> ArenaWireResponse:
        eff_acct = int(self.account_id if account_id is None else account_id)
        self._tried_resync_hi50 = False
        return self._sync_sequence_for_account(eff_acct, bump_hi50=False, use_udp=use_udp)

    def modify_order(
        self,
        market_id: int,
        order_id: int,
        new_price_ticks: int,
        new_qty_lots: int,
        keep_priority: bool = False,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        new_px = _validate_price_ticks_48(new_price_ticks, "new_price_ticks")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (1 <= int(new_qty_lots) <= MAX_WIRE_HEADER_QTY_LOTS):
            raise ValueError(
                f"new_qty_lots {new_qty_lots} out of 40-bit wire range [1, {MAX_WIRE_HEADER_QTY_LOTS}]"
            )
        if not (0 <= int(order_id) <= MASK64):
            raise ValueError("order_id out of 64-bit unsigned range [0, 2^64 - 1]")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        seq_lo = self._alloc_seq(eff_acct)
        eff_hi50 = self._effective_seq_hi50(eff_acct)
        hdr = ArenaHeader(
            op=BaseOp.MODIFY_IN_PLACE,
            market_id=market_id,
            account_id=eff_acct,
            seq_lo=seq_lo,
            price_ticks=new_px,
            qty_lots=new_qty_lots,
        )
        aux1 = MODIFY_AUX_FLAG_KEEP_PRIORITY if keep_priority else 0
        return self.send_frame(
            pack_wire_frame(hdr, order_id, aux1, eff_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def distribute_margin_yield(
        self,
        reward_usd_micro: int,
        sponsor_account_id: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        rew_px = _validate_price_ticks_48(reward_usd_micro, "reward_usd_micro")
        if not (0 <= int(sponsor_account_id) <= 0xFFFF_FFFF):
            raise ValueError("sponsor_account_id out of 32-bit range [0, 2^32 - 1]")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
            price_ticks=rew_px,
        )
        aux0 = sponsor_account_id & 0xFFFF_FFFF
        return self.send_frame(
            pack_wire_frame(hdr, aux0, MARK_AUX1_FLAG_DISTRIBUTE_YIELD, self.seq_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def build_set_protocol_account_frame(self, protocol_account_id: int) -> bytes:
        proto_aid = int(protocol_account_id)
        if not (0 <= proto_aid <= 0xFFFF_FFFF):
            raise ValueError("protocol_account_id out of 32-bit range [0, 2^32 - 1]")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
            price_ticks=proto_aid,
        )
        aux0 = proto_aid & 0xFFFF_FFFF
        return pack_wire_frame(
            hdr, aux0, MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT, self.seq_hi50, self.key_lo64, self.key_hi64
        )

    def set_protocol_account(
        self, protocol_account_id: int, use_udp: bool = False
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_set_protocol_account_frame(protocol_account_id),
            use_udp=use_udp,
        )

    def build_link_sub_account_frame(
        self,
        sub_account_id: int,
        max_guaranty_usd_micro: int = 0,
        master_account_id: int = 0,
    ) -> bytes:
        sub_aid = int(sub_account_id)
        if not (0 < sub_aid <= 0xFFFF_FFFF):
            raise ValueError("sub_account_id must be in [1, 2^32 - 1]")
        master_in = int(master_account_id)
        if master_in < 0:
            raise ValueError("master_account_id must be >= 0")
        eff_master = master_in if master_in > 0 else self.account_id
        guaranty_in = int(max_guaranty_usd_micro)
        if guaranty_in < -2:
            raise ValueError(
                "max_guaranty_usd_micro must be >= -2 (-2=unlink, -1=freeze/0 guaranty, 0=unlimited, >0=cap)"
            )
        eff_guaranty = guaranty_in
        _validate_price_ticks_48(eff_guaranty, "max_guaranty_usd_micro")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=eff_master,
            seq_lo=0,
            price_ticks=eff_guaranty,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq(eff_master)
        eff_hi50 = self._effective_seq_hi50(eff_master)
        return pack_wire_frame(
            hdr,
            sub_aid,
            MARK_AUX1_FLAG_LINK_SUB_ACCOUNT,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def link_sub_account(
        self,
        sub_account_id: int,
        max_guaranty_usd_micro: int = 0,
        master_account_id: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_link_sub_account_frame(
                sub_account_id=sub_account_id,
                max_guaranty_usd_micro=max_guaranty_usd_micro,
                master_account_id=master_account_id,
            ),
            use_udp=use_udp,
        )

    def build_bind_builder_frame(
        self,
        builder_account_id: int,
        builder_fee_share_bps: int,
        trader_account_id: int = 0,
    ) -> bytes:
        builder_aid = int(builder_account_id)
        if not (0 <= builder_aid <= 0xFFFF_FFFF):
            raise ValueError("builder_account_id must be in [0, 2^32 - 1]")
        trader_in = int(trader_account_id)
        if trader_in < 0:
            raise ValueError("trader_account_id must be >= 0")
        eff_trader = trader_in if trader_in > 0 else self.account_id
        fee_bps = int(builder_fee_share_bps)
        if fee_bps < 0:
            raise ValueError("builder_fee_share_bps must be >= 0")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=eff_trader,
            seq_lo=0,
            price_ticks=fee_bps,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq(eff_trader)
        eff_hi50 = self._effective_seq_hi50(eff_trader)
        return pack_wire_frame(
            hdr,
            builder_aid,
            MARK_AUX1_FLAG_BIND_BUILDER,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def bind_builder_code(
        self,
        builder_account_id: int,
        builder_fee_share_bps: int,
        trader_account_id: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_bind_builder_frame(
                builder_account_id=builder_account_id,
                builder_fee_share_bps=builder_fee_share_bps,
                trader_account_id=trader_account_id,
            ),
            use_udp=use_udp,
        )

    def build_configure_mmp_frame(
        self,
        window_wal_seqs: int,
        max_fill_lots: int,
        max_delta_lots: int = 0,
        cooldown_wal_seqs: int = 0,
    ) -> bytes:
        win_i = int(window_wal_seqs)
        fill_i = int(max_fill_lots)
        delta_i = int(max_delta_lots)
        cool_i = int(cooldown_wal_seqs)
        if win_i < 0 or win_i > 0xFFFF_FFFF or cool_i < 0 or cool_i > 0xFFFF_FFFF:
            raise ValueError("window_wal_seqs and cooldown_wal_seqs must be in [0, 2^32 - 1]")
        if fill_i < 0 or delta_i < 0:
            raise ValueError("max_fill_lots and max_delta_lots must be >= 0")
        clamped_delta = min(delta_i, MAX_WIRE_PRICE_TICKS_48)
        aux0 = ((win_i & 0xFFFF_FFFF) << 32) | (cool_i & 0xFFFF_FFFF)
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=clamped_delta,
            qty_lots=fill_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            aux0,
            MARK_AUX1_FLAG_CONFIG_MMP,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def configure_mmp(
        self,
        window_wal_seqs: int,
        max_fill_lots: int,
        max_delta_lots: int = 0,
        cooldown_wal_seqs: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_configure_mmp_frame(
                window_wal_seqs=window_wal_seqs,
                max_fill_lots=max_fill_lots,
                max_delta_lots=max_delta_lots,
                cooldown_wal_seqs=cooldown_wal_seqs,
            ),
            use_udp=use_udp,
        )

    def build_configure_payout_frame(
        self,
        payout_asset_id: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> bytes:
        aid_i = int(payout_asset_id)
        if not (0 <= aid_i <= 0xFFFF):
            raise ValueError("payout_asset_id must be in [0, 65535]")
        target_aid = int(payout_target_account_id)
        if not (0 <= target_aid <= 0xFFFF_FFFF):
            raise ValueError("payout_target_account_id must be in [0, 2^32 - 1]")
        eff_flags = int(payout_mode_flags) & 0xFF
        if auto_repay_borrow:
            eff_flags |= PAYOUT_FLAG_AUTO_REPAY_BORROW
        if compound_bonding_curve:
            eff_flags |= PAYOUT_FLAG_COMPOUND_BONDING_CURVE
        if auto_compound_quotes:
            eff_flags |= PAYOUT_FLAG_AUTO_COMPOUND_QUOTES
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=aid_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=eff_flags,
            qty_lots=aid_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            target_aid,
            MARK_AUX1_FLAG_CONFIG_PAYOUT,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def configure_payout_preferences(
        self,
        payout_asset_id: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_configure_payout_frame(
                payout_asset_id=payout_asset_id,
                payout_mode_flags=payout_mode_flags,
                payout_target_account_id=payout_target_account_id,
                auto_repay_borrow=auto_repay_borrow,
                compound_bonding_curve=compound_bonding_curve,
                auto_compound_quotes=auto_compound_quotes,
            ),
            use_udp=use_udp,
        )

    def build_configure_auto_repo_frame(
        self,
        epoch_marks: int,
        clock_market_id: int = 0,
    ) -> bytes:
        em_i = int(epoch_marks)
        if not (0 <= em_i <= 0xFFFF_FFFF):
            raise ValueError("epoch_marks must be in [0, 2^32 - 1]")
        cm_i = int(clock_market_id)
        if not (0 <= cm_i <= 0xFFFF):
            raise ValueError("clock_market_id must be in [0, 65535]")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=cm_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=em_i,
            qty_lots=em_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            em_i,
            MARK_AUX1_FLAG_CONFIG_AUTO_REPO,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def configure_auto_repo_scheduler(
        self,
        epoch_marks: int,
        use_udp: bool = False,
        clock_market_id: int = 0,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_configure_auto_repo_frame(
                epoch_marks=epoch_marks,
                clock_market_id=clock_market_id,
            ),
            use_udp=use_udp,
        )

    def build_configure_payout_portfolio_frame(
        self,
        primary_asset_id: int = 0,
        primary_share_bps: int = 10_000,
        secondary_asset_id: int = 0,
        secondary_share_bps: int = 0,
        tertiary_asset_id: int = 0,
        tertiary_share_bps: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        max_margin_util_bps: int = 0,
        max_price_ticks: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> bytes:
        target_aid = int(payout_target_account_id)
        if not (0 <= target_aid <= 0xFFFF_FFFF):
            raise ValueError("payout_target_account_id must be in [0, 2^32 - 1]")
        eff_flags = int(payout_mode_flags) & 0xFF
        if auto_repay_borrow:
            eff_flags |= PAYOUT_FLAG_AUTO_REPAY_BORROW
        if compound_bonding_curve:
            eff_flags |= PAYOUT_FLAG_COMPOUND_BONDING_CURVE
        if auto_compound_quotes:
            eff_flags |= PAYOUT_FLAG_AUTO_COMPOUND_QUOTES
        p_aid = int(primary_asset_id)
        s_aid = int(secondary_asset_id)
        t_aid = int(tertiary_asset_id)
        invalid_aid = (p_aid < 0 or p_aid > 0xFF or s_aid < 0 or s_aid > 0xFF or t_aid < 0 or t_aid > 0xFF)
        p_bps = min(0x3FFF, max(0, int(primary_share_bps)))
        s_bps = min(0x3FFF, max(0, int(secondary_share_bps)))
        t_bps = min(0xFFFF, max(0, int(tertiary_share_bps)))
        u_bps = min(0xFFFF, max(0, int(max_margin_util_bps)))
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=((p_aid & 0xFF) << 8) | (s_aid & 0xFF),
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=int(max_price_ticks),
            qty_lots=(p_bps << 22) | (s_bps << 8) | (t_aid & 0xFF),
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux0 = (target_aid << 32) | (t_bps << 16) | u_bps
        aux1 = (
            MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES
            | ((1 << 24) if invalid_aid else 0)
            | (eff_flags << 32)
        )
        return pack_wire_frame(
            hdr,
            aux0,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def configure_payout_portfolio(
        self,
        primary_asset_id: int = 0,
        primary_share_bps: int = 10_000,
        secondary_asset_id: int = 0,
        secondary_share_bps: int = 0,
        tertiary_asset_id: int = 0,
        tertiary_share_bps: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        max_margin_util_bps: int = 0,
        max_price_ticks: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_configure_payout_portfolio_frame(
                primary_asset_id=primary_asset_id,
                primary_share_bps=primary_share_bps,
                secondary_asset_id=secondary_asset_id,
                secondary_share_bps=secondary_share_bps,
                tertiary_asset_id=tertiary_asset_id,
                tertiary_share_bps=tertiary_share_bps,
                payout_mode_flags=payout_mode_flags,
                payout_target_account_id=payout_target_account_id,
                max_margin_util_bps=max_margin_util_bps,
                max_price_ticks=max_price_ticks,
                auto_repay_borrow=auto_repay_borrow,
                compound_bonding_curve=compound_bonding_curve,
                auto_compound_quotes=auto_compound_quotes,
            ),
            use_udp=use_udp,
        )

    def build_fund_market_vault_frame(
        self,
        market_id: int,
        asset_id: int,
        amount: int,
        duration_marks: int,
        maker_share_bps: int = 7_500,
    ) -> bytes:
        mkt_i = int(market_id)
        aid = int(asset_id)
        amt_i = int(amount)
        dur_i = int(duration_marks)
        if not (0 <= aid <= 0xFFFF):
            raise ValueError("asset_id must be in [0, 65535]")
        if not (0 <= amt_i <= MASK64):
            raise ValueError("amount must be in [0, 2^64 - 1]")
        if not (0 <= dur_i <= 0xFFFF_FFFF):
            raise ValueError("duration_marks must be in [0, 2^32 - 1]")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=mkt_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=int(maker_share_bps),
            qty_lots=(dur_i << 8) | (aid & 0xFF),
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux1 = MARK_AUX1_FLAG_FUND_MARKET_VAULT | (aid << 32)
        return pack_wire_frame(
            hdr,
            amt_i,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def fund_market_liquidity_vault(
        self,
        market_id: int,
        asset_id: int,
        amount: int,
        duration_marks: int,
        maker_share_bps: int = 7_500,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_fund_market_vault_frame(
                market_id=market_id,
                asset_id=asset_id,
                amount=amount,
                duration_marks=duration_marks,
                maker_share_bps=maker_share_bps,
            ),
            use_udp=use_udp,
        )

    def build_configure_default_incentives_frame(
        self,
        enabled: bool = True,
        pillar_mask: Optional[int] = None,
        repo_epoch_marks: int = 60,
        two_sided_bonus_bps: int = 2_500,
        claim_collateral_weight_bps: int = 9_000,
    ) -> bytes:
        bonus_i = int(two_sided_bonus_bps)
        repo_i = int(repo_epoch_marks)
        if not (0 <= bonus_i <= 0xFFFF):
            raise ValueError("two_sided_bonus_bps must be in [0, 65535]")
        if not (0 <= repo_i <= 0xFFFF_FFFF):
            raise ValueError("repo_epoch_marks must be in [0, 2^32 - 1]")
        if pillar_mask is not None:
            pm_i = int(pillar_mask)
            if not (0 <= pm_i <= 0xFFFF):
                raise ValueError("pillar_mask must be in [0, 65535]")
            eff_mask = pm_i
        else:
            eff_mask = INCENTIVE_PILLARS_ALL_ON if enabled else 0
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=bonus_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=int(claim_collateral_weight_bps),
            qty_lots=repo_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            eff_mask,
            MARK_AUX1_FLAG_DEFAULT_INCENTIVES,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def configure_default_trader_incentives(
        self,
        enabled: bool = True,
        pillar_mask: Optional[int] = None,
        repo_epoch_marks: int = 60,
        two_sided_bonus_bps: int = 2_500,
        claim_collateral_weight_bps: int = 9_000,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_configure_default_incentives_frame(
                enabled=enabled,
                pillar_mask=pillar_mask,
                repo_epoch_marks=repo_epoch_marks,
                two_sided_bonus_bps=two_sided_bonus_bps,
                claim_collateral_weight_bps=claim_collateral_weight_bps,
            ),
            use_udp=use_udp,
        )

    def build_subscribe_express_port_frame(
        self,
        duration_epochs: int = 1,
        max_fee_usd_micro: int = 0,
        account_id: Optional[int] = None,
    ) -> bytes:
        dur_i = int(duration_epochs)
        max_fee_i = int(max_fee_usd_micro)
        if not (1 <= dur_i <= MAX_EXPRESS_PORT_LEASE_EPOCHS):
            raise ValueError(
                f"duration_epochs {dur_i} out of [1, {MAX_EXPRESS_PORT_LEASE_EPOCHS}]"
            )
        if max_fee_i < 0:
            raise ValueError("max_fee_usd_micro must be >= 0")
        eff_acct = int(self.account_id if account_id is None else account_id)
        if not (0 <= eff_acct <= 0xFFFFFF):
            raise ValueError(
                f"account_id {eff_acct} out of 24-bit wire range [0, 16777215]"
            )
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=eff_acct,
            seq_lo=0,
            price_ticks=max_fee_i,
            qty_lots=dur_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq(eff_acct)
        return pack_wire_frame(
            hdr,
            0,
            MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT,
            self._effective_seq_hi50(eff_acct),
            self.key_lo64,
            self.key_hi64,
        )

    def subscribe_express_port(
        self,
        duration_epochs: int = 1,
        max_fee_usd_micro: int = 0,
        use_udp: bool = False,
        account_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_subscribe_express_port_frame(
                duration_epochs=duration_epochs,
                max_fee_usd_micro=max_fee_usd_micro,
                account_id=account_id,
            ),
            use_udp=use_udp,
        )

    def build_set_express_port_fee_frame(
        self,
        fee_per_epoch_usd_micro: int,
    ) -> bytes:
        fee_i = int(fee_per_epoch_usd_micro)
        if not (
            MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
            <= fee_i
            <= MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
        ):
            raise ValueError(
                f"fee_per_epoch_usd_micro {fee_i} out of "
                f"[{MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}, {MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}]"
            )
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=fee_i,
            qty_lots=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            1 << 63,
            MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def set_express_port_fee_per_epoch(
        self,
        fee_per_epoch_usd_micro: int,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_set_express_port_fee_frame(fee_per_epoch_usd_micro),
            use_udp=use_udp,
        )

    def build_distribute_base_yield_frame(
        self,
        base_asset_id: int,
        total_lots: int,
    ) -> bytes:
        aid_b = int(base_asset_id)
        eff_lots = int(total_lots)
        if not (1 <= aid_b <= 0xFF):
            raise ValueError("base_asset_id must be in [1, 255]")
        if not (1 <= eff_lots <= MAX_WIRE_PRICE_TICKS_48):
            raise ValueError(
                f"total_lots must be in [1, {MAX_WIRE_PRICE_TICKS_48}]"
            )
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=aid_b & 0xFFFF,
            account_id=self.account_id,
            seq_lo=seq_lo,
            price_ticks=eff_lots,
            qty_lots=eff_lots if eff_lots <= MAX_WIRE_HEADER_QTY_LOTS else 0,
        )
        return pack_wire_frame(
            hdr,
            aid_b & 0xFFFF,
            MARK_AUX1_FLAG_BASE_YIELD,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def distribute_base_asset_yield(
        self,
        base_asset_id: int,
        total_lots: int,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_distribute_base_yield_frame(
                base_asset_id=base_asset_id,
                total_lots=total_lots,
            ),
            use_udp=use_udp,
        )

    def build_prime_transfer_frame(
        self,
        to_account_id: int,
        amount: int,
        asset_id: int = 0,
        from_account_id: int = 0,
    ) -> bytes:
        to_aid = int(to_account_id)
        if not (1 <= to_aid <= 0xFFFF_FFFF):
            raise ValueError("to_account_id must be in [1, 2^32 - 1]")
        amt_i = int(amount)
        if amt_i <= 0:
            raise ValueError("amount must be > 0")
        _validate_price_ticks_48(amt_i, "amount")
        aid_i = int(asset_id)
        if not (0 <= aid_i <= 0xFF):
            raise ValueError("asset_id must be in [0, 255]")
        from_in = int(from_account_id)
        if from_in < 0:
            raise ValueError("from_account_id must be >= 0")
        eff_from = from_in if from_in > 0 else self.account_id
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=aid_i,
            account_id=eff_from,
            seq_lo=0,
            price_ticks=amt_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq(eff_from)
        eff_hi50 = self._effective_seq_hi50(eff_from)
        return pack_wire_frame(
            hdr,
            to_aid,
            MARK_AUX1_FLAG_SUB_TRANSFER,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def prime_internal_transfer(
        self,
        to_account_id: int,
        amount: int,
        asset_id: int = 0,
        from_account_id: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_prime_transfer_frame(
                to_account_id=to_account_id,
                amount=amount,
                asset_id=asset_id,
                from_account_id=from_account_id,
            ),
            use_udp=use_udp,
        )

    prime_transfer = prime_internal_transfer

    def rotate_session_key(
        self, new_key_lo64: int, new_key_hi64: int, encrypt: bool = True
    ) -> ArenaWireResponse:
        if not (0 <= int(new_key_lo64) <= MASK64) or not (0 <= int(new_key_hi64) <= MASK64):
            raise ValueError("new_key_lo64 and new_key_hi64 must be in [0, 2^64 - 1]")
        seq_lo = self._alloc_seq()
        if encrypt:
            frame = pack_encrypted_register_session_key_frame(
                account_id=self.account_id,
                seq_lo=seq_lo,
                seq_hi50=self.seq_hi50,
                cur_key_lo64=self.key_lo64,
                cur_key_hi64=self.key_hi64,
                new_key_lo64=new_key_lo64,
                new_key_hi64=new_key_hi64,
                wrap_salt64=_sdk_csprng_u64_nonzero(),
            )
        else:
            hdr = ArenaHeader(
                op=BaseOp.REGISTER_SESSION_KEY,
                account_id=self.account_id,
                seq_lo=seq_lo,
            )
            frame = pack_wire_frame(
                hdr, new_key_lo64, new_key_hi64, self.seq_hi50, self.key_lo64, self.key_hi64
            )
        resp = self.send_frame(frame)
        if resp.status_code == WireStatusCode.OK:
            self.key_lo64 = new_key_lo64 & MASK64
            self.key_hi64 = new_key_hi64 & MASK64
            if int(resp.resting_lots) > 0:
                new_hi = int(resp.resting_lots) & MASK50
                self._seq_hi50_by_account[int(self.account_id)] = new_hi
                self._next_seq_by_account[int(self.account_id)] = 1
                self._pending_hi50_wrap[int(self.account_id)] = False
                self._verified_seq_by_account.add(int(self.account_id))
                self._tried_resync_hi50 = False
            else:
                self._verified_seq_by_account.discard(int(self.account_id))
                self._tried_resync_hi50 = False
            self._saved_cred_seq_state[(int(self.account_id), self.key_lo64, self.key_hi64)] = (
                self._seq_hi50_by_account.get(int(self.account_id), self._default_init_seq_hi50),
                self._next_seq_by_account.get(int(self.account_id), self._default_init_seq),
                bool(self._pending_hi50_wrap.get(int(self.account_id), False)),
            )
        return resp

    def query_bbo(self, market_id: int, use_udp: bool = False) -> ArenaWireResponse:
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        hdr = ArenaHeader(
            op=BaseOp.QUERY_BOOK_BBO,
            market_id=market_id,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
        )
        return self.send_frame(
            pack_wire_frame(hdr, 0, 0, self.seq_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def query_account(self, market_id: int = 0, use_udp: bool = False) -> ArenaWireResponse:
        if not (0 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [0, 65535]")
        hdr = ArenaHeader(
            op=BaseOp.QUERY_ACCOUNT,
            market_id=market_id,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
        )
        return self.send_frame(
            pack_wire_frame(hdr, 0, 0, self.seq_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def update_mark_funding(
        self, market_id: int, mark_price_ticks: int, funding_delta_phi: int = 0, use_udp: bool = False
    ) -> ArenaWireResponse:
        mk_px = _validate_price_ticks_48(mark_price_ticks, "mark_price_ticks")
        if not (1 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [1, 65535]")
        if not (-(1 << 63) <= int(funding_delta_phi) <= ((1 << 63) - 1)):
            raise ValueError("funding_delta_phi out of signed 64-bit range [-2^63, 2^63 - 1]")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=market_id,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
            price_ticks=mk_px,
        )
        return self.send_frame(
            pack_wire_frame(hdr, funding_delta_phi & MASK64, 0, self.seq_hi50, self.key_lo64, self.key_hi64),
            use_udp=use_udp,
        )

    def build_liquidate_account_frame(
        self,
        market_id: int,
        target_account_id: int,
        partial_lots: int = 0,
        allow_l3_offload: bool = True,
        stp: StpMode = StpMode.CANCEL_RESTING,
        hedge_margin_spot: bool = False,
        bounty_rebate_bid_bps: int = 0,
    ) -> bytes:
        mkt_i = int(market_id)
        target_aid = int(target_account_id)
        lots_i = int(partial_lots)
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if not (1 <= target_aid <= 0xFFFF_FFFF):
            raise ValueError("target_account_id must be in [1, 2^32 - 1]")
        if lots_i < 0:
            raise ValueError("partial_lots must be >= 0")
        if bid_bps_i > 0 and target_aid == int(self.account_id):
            raise ValueError("bounty_rebate_bid_bps > 0 cannot be used with self-knockout")
        hdr = ArenaHeader(
            op=BaseOp.LIQUIDATE_ACCOUNT,
            tif=TimeInForce.IOC if allow_l3_offload else TimeInForce.GTC,
            stp=stp,
            market_id=mkt_i,
            account_id=self.account_id,
            seq_lo=0,
            qty_lots=lots_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux1 = 0
        if not allow_l3_offload:
            aux1 |= LIQ_AUX1_FLAG_NO_OFFLOAD
        if hedge_margin_spot:
            aux1 |= LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT
        frm = pack_wire_frame(
            hdr,
            target_aid,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )
        if bid_bps_i > 0:
            frm = pack_wire_liq_bounty_rebate_bid_bps(frm, bid_bps_i, self.key_lo64, self.key_hi64, self.seq_hi50)
        return frm

    def liquidate_account(
        self,
        market_id: int,
        target_account_id: int,
        partial_lots: int = 0,
        use_udp: bool = False,
        allow_l3_offload: bool = True,
        stp: StpMode = StpMode.CANCEL_RESTING,
        hedge_margin_spot: bool = False,
        bounty_rebate_bid_bps: int = 0,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_liquidate_account_frame(
                market_id=market_id,
                target_account_id=target_account_id,
                partial_lots=partial_lots,
                allow_l3_offload=allow_l3_offload,
                stp=stp,
                hedge_margin_spot=hedge_margin_spot,
                bounty_rebate_bid_bps=bounty_rebate_bid_bps,
            ),
            use_udp=use_udp,
        )

    liquidate = liquidate_account

    def build_knockout_frame(self, market_id: int, knockout_price_ticks: int) -> bytes:
        ko_px = _validate_price_ticks_48(knockout_price_ticks, "knockout_price_ticks")
        if not (0 <= int(market_id) <= 0xFFFF):
            raise ValueError("market_id out of [0, 65535]")
        hdr = ArenaHeader(
            op=BaseOp.LIQUIDATE_ACCOUNT,
            market_id=market_id,
            account_id=self.account_id,
            seq_lo=self._alloc_seq(),
            price_ticks=ko_px,
        )
        return pack_wire_frame(
            hdr,
            self.account_id,
            LIQ_AUX1_FLAG_SET_KNOCKOUT,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def set_position_knockout(
        self, market_id: int, knockout_price_ticks: int, use_udp: bool = False
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_knockout_frame(market_id, knockout_price_ticks),
            use_udp=use_udp,
        )

    def build_drawdown_stop_frame(self, stop_equity_usd_micro: int) -> bytes:
        return self.build_knockout_frame(0, stop_equity_usd_micro)

    def set_account_drawdown_stop(
        self, stop_equity_usd_micro: int, use_udp: bool = False
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_drawdown_stop_frame(stop_equity_usd_micro),
            use_udp=use_udp,
        )

    set_drawdown_stop = set_account_drawdown_stop

    def build_auto_delta_hedge_frame(
        self,
        base_asset_id: int = 0,
        preferred_market_id: int = 0,
        max_slippage_bps: int = 200,
        max_qty_lots: int = 0,
        margin_spot: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
    ) -> bytes:
        aid_i = int(base_asset_id)
        mkt_i = int(preferred_market_id)
        slip_i = int(max_slippage_bps)
        qty_i = int(max_qty_lots)
        if not (0 <= aid_i <= 0xFFFF):
            raise ValueError("base_asset_id must be in [0, 65535]")
        if slip_i < 0 or qty_i < 0:
            raise ValueError("max_slippage_bps and max_qty_lots must be >= 0")
        hdr = ArenaHeader(
            op=BaseOp.LIQUIDATE_ACCOUNT,
            tif=TimeInForce.IOC,
            stp=stp,
            market_id=mkt_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=slip_i,
            qty_lots=qty_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux1 = LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE | (LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT if margin_spot else 0)
        return pack_wire_frame(
            hdr,
            aid_i,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def auto_delta_hedge(
        self,
        base_asset_id: int = 0,
        preferred_market_id: int = 0,
        max_slippage_bps: int = 200,
        max_qty_lots: int = 0,
        margin_spot: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_auto_delta_hedge_frame(
                base_asset_id=base_asset_id,
                preferred_market_id=preferred_market_id,
                max_slippage_bps=max_slippage_bps,
                max_qty_lots=max_qty_lots,
                margin_spot=margin_spot,
                stp=stp,
            ),
            use_udp=use_udp,
        )

    delta_hedge = auto_delta_hedge

    def build_auto_cross_arb_frame(
        self,
        primary_market_id: int,
        secondary_market_id: int = 0,
        max_qty_lots: int = 0,
        min_profit_micro: int = 0,
        margin_spot: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        express_surplus_bid_bps: int = 0,
    ) -> bytes:
        bid_bps_i = int(express_surplus_bid_bps)
        if not (0 <= bid_bps_i <= MAX_EXPRESS_SURPLUS_BID_BPS):
            raise ValueError(
                f"express_surplus_bid_bps {bid_bps_i} out of [0, {MAX_EXPRESS_SURPLUS_BID_BPS}]"
            )
        pmkt_i = int(primary_market_id)
        smkt_i = int(secondary_market_id)
        qty_i = int(max_qty_lots)
        if not (0 <= smkt_i <= 0xFFFF):
            raise ValueError("secondary_market_id must be in [0, 65535]")
        if qty_i < 0:
            raise ValueError("max_qty_lots must be >= 0")
        hdr = ArenaHeader(
            op=BaseOp.LIQUIDATE_ACCOUNT,
            tif=TimeInForce.IOC,
            stp=stp,
            market_id=pmkt_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=int(min_profit_micro),
            qty_lots=qty_i,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux1 = LIQ_AUX1_FLAG_AUTO_CROSS_ARB | (LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT if margin_spot else 0)
        frm = pack_wire_frame(
            hdr,
            smkt_i,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )
        if bid_bps_i > 0:
            frm = pack_wire_express_surplus_bid_bps(frm, bid_bps_i, self.key_lo64, self.key_hi64, self.seq_hi50)
        return frm

    def auto_cross_arb(
        self,
        primary_market_id: int,
        secondary_market_id: int = 0,
        max_qty_lots: int = 0,
        min_profit_micro: int = 0,
        margin_spot: bool = False,
        stp: StpMode = StpMode.CANCEL_RESTING,
        use_udp: bool = False,
        express_surplus_bid_bps: int = 0,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_auto_cross_arb_frame(
                primary_market_id=primary_market_id,
                secondary_market_id=secondary_market_id,
                max_qty_lots=max_qty_lots,
                min_profit_micro=min_profit_micro,
                margin_spot=margin_spot,
                stp=stp,
                express_surplus_bid_bps=express_surplus_bid_bps,
            ),
            use_udp=use_udp,
        )

    def build_auto_liquidation_sweep_frame(
        self,
        market_id: int = 0,
        target_account_id: int = 0,
        max_lots: int = 0,
        min_bounty_micro: int = 0,
        flash_offload_to_book: bool = True,
        stp: StpMode = StpMode.CANCEL_RESTING,
        auto_offload_to_book: Optional[bool] = None,
        hedge_margin_spot: bool = False,
        max_qty_lots: Optional[int] = None,
        bounty_rebate_bid_bps: int = 0,
    ) -> bytes:
        eff_offload = flash_offload_to_book if auto_offload_to_book is None else bool(auto_offload_to_book)
        eff_lots = int(max_lots if max_qty_lots is None else max_qty_lots)
        mkt_i = int(market_id)
        target_aid = int(target_account_id)
        bounty_i = int(min_bounty_micro)
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if not (0 <= target_aid <= 0xFFFF_FFFF):
            raise ValueError("target_account_id must be in [0, 2^32 - 1]")
        if bid_bps_i > 0 and target_aid != 0 and target_aid == int(self.account_id):
            raise ValueError("bounty_rebate_bid_bps > 0 cannot target self")
        if eff_lots < 0 or bounty_i < 0:
            raise ValueError("max_lots and min_bounty_micro must be >= 0")
        hdr = ArenaHeader(
            op=BaseOp.LIQUIDATE_ACCOUNT,
            tif=TimeInForce.IOC if eff_offload else TimeInForce.GTC,
            stp=stp,
            market_id=mkt_i,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=bounty_i,
            qty_lots=eff_lots,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        aux1 = LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP
        if not eff_offload:
            aux1 |= LIQ_AUX1_FLAG_NO_OFFLOAD
        if hedge_margin_spot:
            aux1 |= LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT
        frm = pack_wire_frame(
            hdr,
            target_aid,
            aux1,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )
        if bid_bps_i > 0:
            frm = pack_wire_liq_bounty_rebate_bid_bps(frm, bid_bps_i, self.key_lo64, self.key_hi64, self.seq_hi50)
        return frm

    build_auto_liquidate_sweep_frame = build_auto_liquidation_sweep_frame
    pack_auto_liquidate_sweep_frame = build_auto_liquidation_sweep_frame

    def auto_liquidation_sweep(
        self,
        market_id: int = 0,
        target_account_id: int = 0,
        max_lots: int = 0,
        min_bounty_micro: int = 0,
        flash_offload_to_book: bool = True,
        stp: StpMode = StpMode.CANCEL_RESTING,
        use_udp: bool = False,
        auto_offload_to_book: Optional[bool] = None,
        hedge_margin_spot: bool = False,
        max_qty_lots: Optional[int] = None,
        bounty_rebate_bid_bps: int = 0,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_auto_liquidation_sweep_frame(
                market_id=market_id,
                target_account_id=target_account_id,
                max_lots=max_lots,
                min_bounty_micro=min_bounty_micro,
                flash_offload_to_book=flash_offload_to_book,
                stp=stp,
                auto_offload_to_book=auto_offload_to_book,
                hedge_margin_spot=hedge_margin_spot,
                max_qty_lots=max_qty_lots,
                bounty_rebate_bid_bps=bounty_rebate_bid_bps,
            ),
            use_udp=use_udp,
        )

    auto_liquidate_sweep = auto_liquidation_sweep
    auto_liquidate = auto_liquidation_sweep

    def build_save_wal_snapshot_frame(self) -> bytes:
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=0,
            qty_lots=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            0,
            MARK_AUX1_FLAG_SAVE_SNAPSHOT,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def save_wal_snapshot(self, use_udp: bool = False) -> ArenaWireResponse:
        return self.send_frame(
            self.build_save_wal_snapshot_frame(),
            use_udp=use_udp,
        )

    def build_sweep_insurance_frame(
        self, reserve_floor_usd_micro: int = 0, max_sweep_usd_micro: int = 0
    ) -> bytes:
        eff_floor = int(reserve_floor_usd_micro)
        eff_max = int(max_sweep_usd_micro)
        if not (0 <= eff_floor <= MAX_WIRE_PRICE_TICKS_48):
            raise ValueError(
                f"reserve_floor_usd_micro must be in [0, {MAX_WIRE_PRICE_TICKS_48}]"
            )
        if not (0 <= eff_max <= ((1 << 63) - 1)):
            raise ValueError("max_sweep_usd_micro must be in [0, 2^63 - 1]")
        seq_lo = self._alloc_seq()
        eff_hi50 = self.seq_hi50
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=seq_lo,
            price_ticks=eff_floor,
            qty_lots=min(eff_max, MAX_WIRE_HEADER_QTY_LOTS),
        )
        return pack_wire_frame(
            hdr,
            eff_max,
            MARK_AUX1_FLAG_SWEEP_INSURANCE,
            eff_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def sweep_excess_insurance_fund(
        self,
        reserve_floor_usd_micro: int = 0,
        max_sweep_usd_micro: int = 0,
        use_udp: bool = False,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_sweep_insurance_frame(
                reserve_floor_usd_micro=reserve_floor_usd_micro,
                max_sweep_usd_micro=max_sweep_usd_micro,
            ),
            use_udp=use_udp,
        )

    sweep_insurance = sweep_excess_insurance_fund

    def build_harvest_custody_float_yield_frame(
        self,
        yield_rate_bps: int = 1,
        protocol_spread_share_bps: int = -1,
        protocol_spread_bps: Optional[int] = None,
    ) -> bytes:
        eff_spread = int(protocol_spread_bps) if protocol_spread_bps is not None else int(protocol_spread_share_bps)
        aux0 = (eff_spread + 1) if eff_spread >= 0 else 0
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=max(1, int(yield_rate_bps)),
            qty_lots=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            aux0,
            MARK_AUX1_FLAG_HARVEST_FLOAT_YIELD,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def harvest_custody_float_yield(
        self,
        yield_rate_bps: int = 1,
        protocol_spread_share_bps: int = -1,
        use_udp: bool = False,
        protocol_spread_bps: Optional[int] = None,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_harvest_custody_float_yield_frame(
                yield_rate_bps=yield_rate_bps,
                protocol_spread_share_bps=protocol_spread_share_bps,
                protocol_spread_bps=protocol_spread_bps,
            ),
            use_udp=use_udp,
        )

    def build_harvest_overnight_spot_repo_frame(
        self,
        base_asset_id: int = 1,
        override_rate_bps: int = 0,
        base_id: Optional[int] = None,
    ) -> bytes:
        eff_base = int(base_id if base_id is not None else base_asset_id)
        rate_i = int(override_rate_bps)
        if not (1 <= eff_base <= 0xFF):
            raise ValueError("base_asset_id must be in [1, 255]")
        if rate_i < 0:
            raise ValueError("override_rate_bps must be >= 0")
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=eff_base,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=rate_i,
            qty_lots=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            eff_base,
            MARK_AUX1_FLAG_HARVEST_SPOT_REPO,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def harvest_overnight_spot_repo(
        self,
        base_asset_id: int = 1,
        override_rate_bps: int = 0,
        use_udp: bool = False,
        base_id: Optional[int] = None,
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_harvest_overnight_spot_repo_frame(
                base_asset_id=base_asset_id,
                override_rate_bps=override_rate_bps,
                base_id=base_id,
            ),
            use_udp=use_udp,
        )

    def build_harvest_negative_usd_repo_frame(self, override_rate_bps: int = 0) -> bytes:
        hdr = ArenaHeader(
            op=BaseOp.UPDATE_MARK_FUNDING,
            market_id=0,
            account_id=self.account_id,
            seq_lo=0,
            price_ticks=max(0, int(override_rate_bps)),
            qty_lots=0,
        )
        hdr.pack_words()
        hdr.seq_lo = self._alloc_seq()
        return pack_wire_frame(
            hdr,
            0,
            MARK_AUX1_FLAG_HARVEST_USD_REPO,
            self.seq_hi50,
            self.key_lo64,
            self.key_hi64,
        )

    def harvest_negative_usd_repo(
        self, override_rate_bps: int = 0, use_udp: bool = False
    ) -> ArenaWireResponse:
        return self.send_frame(
            self.build_harvest_negative_usd_repo_frame(override_rate_bps=override_rate_bps),
            use_udp=use_udp,
        )
# =============================================================================
# Pure-Python Ethereum Keccak-256 (0x01 padding), EIP-55, EIP-191 & secp256k1
# =============================================================================
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_RHO = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)
_KECCAK_PI = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)


def _keccak_f1600(st: List[int]) -> None:
    for rnd in range(24):
        bc = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
        for x in range(5):
            t = bc[(x + 4) % 5] ^ _rotl64(bc[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                st[y + x] ^= t
        t = st[1]
        for i in range(24):
            j = _KECCAK_PI[i]
            st[j], t = _rotl64(t, _KECCAK_RHO[i]), st[j]
        for y in range(0, 25, 5):
            row = st[y : y + 5]
            for x in range(5):
                st[y + x] = row[x] ^ ((~row[(x + 1) % 5] & MASK64) & row[(x + 2) % 5])
        st[0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 (0x01 domain byte, rate = 136 bytes)."""
    rate = 136
    st = [0] * 25
    mv = memoryview(data)
    offset = 0
    n = len(data)
    while offset + rate <= n:
        words = struct.unpack_from("<17Q", mv, offset)
        for i in range(17):
            st[i] ^= words[i]
        _keccak_f1600(st)
        offset += rate

    tail = bytearray(rate)
    rem = n - offset
    if rem:
        tail[:rem] = mv[offset:]
    tail[rem] ^= 0x01
    tail[rate - 1] ^= 0x80
    words = struct.unpack("<17Q", tail)
    for i in range(17):
        st[i] ^= words[i]
    _keccak_f1600(st)
    return struct.pack("<4Q", st[0], st[1], st[2], st[3])


def format_eip55_address(addr20: bytes) -> str:
    if len(addr20) != 20:
        raise ValueError("Ethereum address must be 20 bytes")
    low = addr20.hex()
    h = keccak256(low.encode("ascii")).hex()
    chars = ["0", "x"]
    for c, hc in zip(low, h):
        if "a" <= c <= "f" and int(hc, 16) >= 8:
            chars.append(c.upper())
        else:
            chars.append(c)
    return "".join(chars)


def eip191_personal_sign_hash(message: str | bytes) -> bytes:
    raw = message.encode("utf-8") if isinstance(message, str) else message
    prefix = f"\x19Ethereum Signed Message:\n{len(raw)}".encode("ascii")
    return keccak256(prefix + raw)


def _rlp_length_prefix(length: int, base: int) -> bytes:
    if length <= 55:
        return bytes([base + length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(len_bytes)]) + len_bytes


def rlp_encode(item: Any) -> bytes:
    """Ethereum Yellow Paper Appendix B Recursive Length Prefix (RLP) encoder."""
    if isinstance(item, bool):
        return rlp_encode(1 if item else 0)
    if isinstance(item, int):
        if item < 0:
            raise ValueError(f"RLP integers must be non-negative, got {item}")
        if item == 0:
            return b"\x80"
        raw_int = item.to_bytes((item.bit_length() + 7) // 8, "big")
        return rlp_encode(raw_int)
    if isinstance(item, (bytes, bytearray, memoryview)):
        raw = bytes(item)
        if len(raw) == 1 and raw[0] < 0x80:
            return raw
        return _rlp_length_prefix(len(raw), 0x80) + raw
    if isinstance(item, str):
        return rlp_encode(item.encode("utf-8"))
    if isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(elem) for elem in item)
        return _rlp_length_prefix(len(payload), 0xC0) + payload
    raise TypeError(f"Unsupported RLP item type: {type(item)!r}")


_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _secp_point_add(
    p1: Optional[tuple[int, int]], p2: Optional[tuple[int, int]]
) -> Optional[tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _SECP_P == 0:
            return None
        lam = (3 * x1 * x1 * pow(2 * y1, -1, _SECP_P)) % _SECP_P
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % _SECP_P, -1, _SECP_P)) % _SECP_P
    x3 = (lam * lam - x1 - x2) % _SECP_P
    y3 = (lam * (x1 - x3) - y1) % _SECP_P
    return x3, y3


def _secp_scalar_mul(k: int, pt: tuple[int, int] = (_SECP_GX, _SECP_GY)) -> Optional[tuple[int, int]]:
    k %= _SECP_N
    if k == 0:
        return None
    acc: Optional[tuple[int, int]] = None
    addend: Optional[tuple[int, int]] = pt
    while k > 0:
        if k & 1:
            acc = _secp_point_add(acc, addend)
        addend = _secp_point_add(addend, addend)
        k >>= 1
    return acc


def _rfc6979_secp256k1_k(priv_int: int, msg_hash32: bytes) -> int:
    x_bytes = priv_int.to_bytes(32, "big")
    h1_int = int.from_bytes(msg_hash32, "big") % _SECP_N
    h1_bytes = h1_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x_bytes + h1_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x_bytes + h1_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < _SECP_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def secp256k1_ecrecover_eth_address(msg_hash32: bytes, sig_hex: str) -> str:
    """Recover EIP-55 Ethereum signer address from 32-byte digest & 65-byte `0x...` signature."""
    s_clean = sig_hex[2:] if sig_hex.startswith(("0x", "0X")) else sig_hex
    sig = bytes.fromhex(s_clean)
    if len(msg_hash32) != 32 or len(sig) != 65:
        raise ValueError("Expected 32-byte hash and 65-byte signature")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v_raw = sig[64]
    recid = (v_raw - 27) if v_raw in (27, 28) else v_raw
    if recid not in (0, 1) or not (1 <= r < _SECP_N) or not (1 <= s <= _SECP_N // 2):
        raise ValueError("Invalid or malleable secp256k1 signature parameters")
    if r >= _SECP_P:
        raise ValueError("Unsupported r >= p")
    y_sq = (pow(r, 3, _SECP_P) + 7) % _SECP_P
    y = pow(y_sq, (_SECP_P + 1) // 4, _SECP_P)
    if (y * y) % _SECP_P != y_sq:
        raise ValueError("Signature r does not lie on secp256k1")
    if (y & 1) != recid:
        y = _SECP_P - y
    r_inv = pow(r, -1, _SECP_N)
    e = int.from_bytes(msg_hash32, "big") % _SECP_N
    u1 = ((_SECP_N - e) * r_inv) % _SECP_N
    u2 = (s * r_inv) % _SECP_N
    q = _secp_point_add(_secp_scalar_mul(u1, (_SECP_GX, _SECP_GY)), _secp_scalar_mul(u2, (r, y)))
    if q is None:
        raise ValueError("Recovered point at infinity")
    pub64 = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return format_eip55_address(keccak256(pub64)[12:])


def compute_ledger_tip_digest(
    wal_seq: int,
    ledger_chain_hash_hex: str,
    state_root_hex: str,
    chain_id: int = 0,
    clearinghouse_address: str = "",
) -> bytes:
    """Compute 32-byte `ARENA_LEDGER_TIP_V2_1` Keccak-256 digest matching C++ `AuthManager::compute_ledger_tip_digest`."""
    ch_clean = ledger_chain_hash_hex[2:] if ledger_chain_hash_hex.startswith(("0x", "0X")) else ledger_chain_hash_hex
    sr_clean = state_root_hex[2:] if state_root_hex.startswith(("0x", "0X")) else state_root_hex
    ch_bytes = bytes.fromhex(ch_clean)
    sr_bytes = bytes.fromhex(sr_clean)
    if len(ch_bytes) != 32 or len(sr_bytes) != 32:
        raise ValueError("ledger_chain_hash and state_root must each be 32 bytes")
    clh_raw = str(clearinghouse_address or "").strip()
    if clh_raw:
        clh_clean = clh_raw[2:] if clh_raw.startswith(("0x", "0X")) else clh_raw
        clh_bytes = bytes.fromhex(clh_clean)
        if len(clh_bytes) != 20:
            raise ValueError("clearinghouse_address must be 20 bytes when specified")
    else:
        clh_bytes = b"\x00" * 20
    payload = (
        b"ARENA_LEDGER_TIP_V2_1"
        + struct.pack(">Q", int(chain_id) & MASK64)
        + clh_bytes
        + struct.pack(">Q", wal_seq & MASK64)
        + ch_bytes
        + sr_bytes
    )
    return keccak256(payload)


def verify_ledger_tip(
    tip_resp: Dict[str, Any],
    expected_operator_address: str = "",
    *,
    allow_self_asserted_signer: bool = False,
    expected_chain_id: Optional[int] = None,
    expected_clearinghouse_address: str = "",
) -> bool:
    """Cryptographically verify a `GET /ledger/tip` response via `Keccak-256` + `secp256k1` `ecrecover`."""
    try:
        wal_seq = int(tip_resp["wal_seq"])
        chain_hex = str(tip_resp["ledger_chain_hash"])
        root_hex = str(tip_resp["state_root"])
        sig_hex = str(tip_resp["operator_signature"])
        tip_domain = str(tip_resp.get("tip_domain") or "").strip()
        if tip_domain and tip_domain != "ARENA_LEDGER_TIP_V2_1":
            return False
        chain_id = int(tip_resp.get("chain_id") or 0)
        ch_addr = str(tip_resp.get("clearinghouse_address") or "").strip()
        if expected_chain_id is not None and chain_id != int(expected_chain_id):
            return False
        exp_ch = str(expected_clearinghouse_address or "").strip()
        if exp_ch:
            ec_clean = exp_ch[2:] if exp_ch.startswith(("0x", "0X")) else exp_ch
            ac_clean = ch_addr[2:] if ch_addr.startswith(("0x", "0X")) else ch_addr
            if not ac_clean or bytes.fromhex(ec_clean) != bytes.fromhex(ac_clean):
                return False
        exp_raw = str(expected_operator_address or "").strip()
        if exp_raw:
            exp_clean = exp_raw[2:] if exp_raw.startswith(("0x", "0X")) else exp_raw
            exp_bytes = bytes.fromhex(exp_clean)
            if len(exp_bytes) != 20 or exp_bytes == b"\x00" * 20:
                return False
            op_addr = "0x" + exp_bytes.hex()
            payload_op = str(tip_resp.get("operator_eth_address") or "").strip()
            if payload_op:
                p_clean = payload_op[2:] if payload_op.startswith(("0x", "0X")) else payload_op
                if bytes.fromhex(p_clean) != exp_bytes:
                    return False
        else:
            if not allow_self_asserted_signer:
                return False
            payload_op = str(tip_resp["operator_eth_address"]).strip()
            p_clean = payload_op[2:] if payload_op.startswith(("0x", "0X")) else payload_op
            p_bytes = bytes.fromhex(p_clean)
            if len(p_bytes) != 20 or p_bytes == b"\x00" * 20:
                return False
            op_addr = "0x" + p_bytes.hex()
        digest = compute_ledger_tip_digest(wal_seq, chain_hex, root_hex, chain_id=chain_id, clearinghouse_address=ch_addr)
        if "tip_digest" in tip_resp:
            td = str(tip_resp["tip_digest"])
            td_clean = td[2:] if td.startswith(("0x", "0X")) else td
            if bytes.fromhex(td_clean) != digest:
                return False
        recovered = secp256k1_ecrecover_eth_address(digest, sig_hex)
        return recovered.lower() == op_addr.lower()
    except Exception:
        return False


def compute_escape_leaf_hash(
    account_id: int,
    asset_id: int,
    merkle_balance_units: int,
    owner_wallet: str,
) -> bytes:
    """Compute 32-byte `ARENA_ESCAPE_LEAF_V1_4` leaf hash matching `Clearinghouse.sol::claimMerkleEmergencyEscape`."""
    w_clean = owner_wallet[2:] if owner_wallet.startswith(("0x", "0X")) else owner_wallet
    w_bytes = bytes.fromhex(w_clean)
    if len(w_bytes) != 20:
        raise ValueError(f"Expected 20-byte owner_wallet address, got {len(w_bytes)} bytes")
    preimage = (
        b"ARENA_ESCAPE_LEAF_V1_4"
        + struct.pack(
            ">IHQ",
            int(account_id) & 0xFFFF_FFFF,
            int(asset_id) & 0xFFFF,
            int(merkle_balance_units) & MASK64,
        )
        + w_bytes
    )
    return keccak256(preimage)


def verify_escape_merkle_proof(
    proof_resp: Dict[str, Any],
    expected_escape_merkle_root: str = "",
    *,
    allow_self_asserted_root: bool = False,
) -> bool:
    """Verify a `GET /settlement/escape_proof` sorted-pair Merkle proof against a trusted `escape_merkle_root`."""
    try:
        if not proof_resp.get("ok"):
            return False
        owner_addr = str(
            proof_resp.get("owner_eth_address")
            or proof_resp.get("owner_wallet")
            or ""
        )
        if not owner_addr:
            return False
        root_str = str(proof_resp["escape_merkle_root"]).strip()
        root_clean = root_str[2:] if root_str.startswith(("0x", "0X")) else root_str
        payload_root = bytes.fromhex(root_clean)
        if len(payload_root) != 32 or payload_root == b"\x00" * 32:
            return False
        exp_root_str = str(expected_escape_merkle_root or "").strip()
        if exp_root_str:
            exp_clean = exp_root_str[2:] if exp_root_str.startswith(("0x", "0X")) else exp_root_str
            trusted_root = bytes.fromhex(exp_clean)
            if len(trusted_root) != 32 or trusted_root == b"\x00" * 32:
                return False
            if payload_root != trusted_root:
                return False
        else:
            if not allow_self_asserted_root:
                return False
            trusted_root = payload_root
        leaf = compute_escape_leaf_hash(
            int(proof_resp["account_id"]),
            int(proof_resp["asset_id"]),
            int(proof_resp["merkle_balance_units"]),
            owner_addr,
        )
        if "leaf_hash" in proof_resp:
            lh = str(proof_resp["leaf_hash"])
            lh_clean = lh[2:] if lh.startswith(("0x", "0X")) else lh
            if bytes.fromhex(lh_clean) != leaf:
                return False
        cur = leaf
        for sib_hex in list(proof_resp.get("merkle_proof", [])):
            s_clean = str(sib_hex)[2:] if str(sib_hex).startswith(("0x", "0X")) else str(sib_hex)
            sib = bytes.fromhex(s_clean)
            if len(sib) != 32:
                return False
            cur = keccak256((cur + sib) if cur <= sib else (sib + cur))
        return cur == trusted_root
    except Exception:
        return False


ESCAPE_LEAVES_PUBLISHED_SIG = "EscapeLeavesPublished(uint64,bytes32,bytes)"
ESCAPE_LEAVES_PUBLISHED_TOPIC = "0x" + keccak256(ESCAPE_LEAVES_PUBLISHED_SIG.encode("ascii")).hex()
ESCAPE_LEAVES_STREAM_FINALIZED_SIG = "EscapeLeavesStreamFinalized(uint64,bytes32,address,uint64)"
ESCAPE_LEAVES_STREAM_FINALIZED_TOPIC = (
    "0x" + keccak256(ESCAPE_LEAVES_STREAM_FINALIZED_SIG.encode("ascii")).hex()
)
ESCAPE_LEAVES_CHUNK_RESET_SIG = "EscapeLeavesChunkReset(uint64,address)"
ESCAPE_LEAVES_CHUNK_RESET_TOPIC = (
    "0x" + keccak256(ESCAPE_LEAVES_CHUNK_RESET_SIG.encode("ascii")).hex()
)
EMPTY_ESCAPE_TREE_ROOT_HEX = "0x" + keccak256(b"ARENA_ESCAPE_EMPTY_V1_5").hex()
_SDK_HAS_COMMITTED_ESCAPE_TREE_SEL = "0x" + keccak256(b"hasCommittedEscapeTree()")[:4].hex()
_SDK_LAST_BATCH_SEQ_ID_SEL = "0x" + keccak256(b"lastBatchSeqId()")[:4].hex()
_SDK_CURRENT_ESCAPE_MERKLE_ROOT_SEL = "0x" + keccak256(b"currentEscapeMerkleRoot()")[:4].hex()
_SDK_ESCAPE_LEAVES_PUBLISHER_SEL = "0x" + keccak256(b"escapeLeavesPublisher(uint64)")[:4].hex()


def _parse_and_sort_packed_escape_leaves(
    packed_leaves_bytes: bytes | bytearray | memoryview | str,
) -> List[tuple[int, int, int, str]]:
    if isinstance(packed_leaves_bytes, str):
        clean = packed_leaves_bytes.strip()
        if clean.startswith(("0x", "0X")):
            clean = clean[2:]
        raw = bytes.fromhex(clean) if clean else b""
    else:
        raw = bytes(packed_leaves_bytes)
    if len(raw) % 34 != 0:
        raise ValueError(f"Packed escape leaves byte length must be a multiple of 34, got {len(raw)}")
    dedup_by_key: Dict[tuple[int, int], tuple[int, str]] = {}
    for off in range(0, len(raw), 34):
        acct, asset_id, units = struct.unpack_from(">IHQ", raw, off)
        addr20 = raw[off + 14 : off + 34]
        if acct <= 0 or units <= 0 or addr20 == (b"\x00" * 20):
            raise ValueError(
                f"Invalid packed escape leaf at byte offset {off}: "
                f"account_id={acct}, asset_id={asset_id}, units={units}"
            )
        owner = format_eip55_address(addr20)
        key = (int(acct), int(asset_id))
        prev = dedup_by_key.get(key)
        if prev is not None and (prev[0] != int(units) or prev[1].lower() != owner.lower()):
            raise ValueError(
                f"Conflicting duplicate escape leaf for account_id={acct}, asset_id={asset_id}: "
                f"{prev} vs {(int(units), owner)}"
            )
        dedup_by_key[key] = (int(units), owner)
    return [
        (acct, asset_id, units, owner)
        for (acct, asset_id), (units, owner) in sorted(dedup_by_key.items())
    ]


def compute_escape_merkle_root_from_packed_leaves(
    packed_leaves_bytes: bytes | bytearray | memoryview | str,
) -> str:
    """Compute the sorted-pair `Clearinghouse.sol` `escapeMerkleRoot` from 34-byte packed leaves."""
    leaves = _parse_and_sort_packed_escape_leaves(packed_leaves_bytes)
    if not leaves:
        return EMPTY_ESCAPE_TREE_ROOT_HEX
    level = [
        compute_escape_leaf_hash(acct, asset_id, units, owner)
        for acct, asset_id, units, owner in leaves
    ]
    while len(level) > 1:
        pairs = len(level) >> 1
        next_level: List[bytes] = []
        for j in range(pairs):
            a = level[j << 1]
            b = level[(j << 1) + 1]
            next_level.append(keccak256((a + b) if a <= b else (b + a)))
        if (len(level) & 1) == 1:
            next_level.append(level[-1])
        level = next_level
    return "0x" + level[0].hex()


def reconstruct_escape_merkle_proof_from_packed_leaves(
    packed_leaves_bytes: bytes | bytearray | memoryview | str,
    account_id: int,
    asset_id: int = 0,
    expected_escape_merkle_root: str = "",
) -> tuple[int, str, List[str]]:
    """
    Offline emergency escape Merkle proof reconstructor from 34-byte packed leaves
    (`4B BE account_id + 2B BE asset_id + 8B BE merkle_balance_units + 20B owner_eth_address`).
    Returns `(merkle_balance_units, owner_wallet, proof_bytes32_list)`.
    """
    target_acct = int(account_id)
    target_asset = int(asset_id)
    leaves = _parse_and_sort_packed_escape_leaves(packed_leaves_bytes)
    if not leaves:
        raise ValueError("Cannot reconstruct escape Merkle proof from empty packed leaves")

    target_idx = -1
    target_units = 0
    target_owner = ""
    level: List[bytes] = []
    for idx, (acct, aid, units, owner) in enumerate(leaves):
        level.append(compute_escape_leaf_hash(acct, aid, units, owner))
        if acct == target_acct and aid == target_asset:
            target_idx = idx
            target_units = units
            target_owner = owner

    if target_idx < 0:
        raise ValueError(
            f"Escape leaf not found for account_id={target_acct}, asset_id={target_asset}"
        )

    proof_hex_list: List[str] = []
    cur_idx = target_idx
    while len(level) > 1:
        pairs = len(level) >> 1
        if cur_idx < (pairs << 1):
            sib = level[cur_idx ^ 1]
            proof_hex_list.append("0x" + sib.hex())
            cur_idx >>= 1
        else:
            cur_idx = pairs
        next_level: List[bytes] = []
        for j in range(pairs):
            a = level[j << 1]
            b = level[(j << 1) + 1]
            next_level.append(keccak256((a + b) if a <= b else (b + a)))
        if (len(level) & 1) == 1:
            next_level.append(level[-1])
        level = next_level

    computed_root_hex = "0x" + level[0].hex()
    exp_root = str(expected_escape_merkle_root or "").strip()
    if exp_root:
        exp_norm = exp_root if exp_root.startswith(("0x", "0X")) else ("0x" + exp_root)
        if computed_root_hex.lower() != exp_norm.lower():
            raise ValueError(
                f"Reconstructed escape Merkle root mismatch: got {computed_root_hex}, expected {exp_norm}"
            )
    if not verify_escape_merkle_proof(
        {
            "ok": True,
            "account_id": target_acct,
            "asset_id": target_asset,
            "merkle_balance_units": target_units,
            "owner_eth_address": target_owner,
            "escape_merkle_root": computed_root_hex,
            "merkle_proof": proof_hex_list,
        },
        expected_escape_merkle_root=computed_root_hex,
    ):
        raise RuntimeError("Internal escape Merkle proof self-verification failed")
    return target_units, target_owner, proof_hex_list


def _decode_escape_leaves_published_data(data_hex: str) -> bytes:
    clean = data_hex[2:] if data_hex.startswith(("0x", "0X")) else data_hex
    raw = bytes.fromhex(clean) if clean else b""
    if len(raw) < 64:
        raise ValueError(f"EscapeLeavesPublished log data too short: {len(raw)} bytes")
    offset = int.from_bytes(raw[0:32], "big")
    if offset + 32 > len(raw):
        raise ValueError("EscapeLeavesPublished ABI bytes offset out of bounds")
    length = int.from_bytes(raw[offset : offset + 32], "big")
    if offset + 32 + length > len(raw):
        raise ValueError("EscapeLeavesPublished ABI bytes payload truncated")
    return raw[offset + 32 : offset + 32 + length]


def reconstruct_escape_merkle_proof_from_logs(
    evm: "EvmJsonRpcClient",
    clearinghouse: str,
    account_id: int,
    asset_id: int = 0,
    from_block: int = 0,
    to_block: int | str = "latest",
) -> tuple[int, str, List[str]]:
    """
    Scan on-chain `EscapeLeavesPublished`, `EscapeLeavesChunkReset`, and
    `EscapeLeavesStreamFinalized` logs for `Clearinghouse.lastBatchSeqId()`, pin all
    `eth_call` / `eth_getLogs` reads to a single `anchor_block`, discard chunks prior to
    any `EscapeLeavesChunkReset`, verify `tx_from == publisher` (or finalized chunk count +
    Merkle root), verify the sorted Merkle root against `currentEscapeMerkleRoot()`,
    and return `(merkle_balance_units, owner_wallet, proof_bytes32_list)`.
    """
    start_blk = max(0, int(from_block))
    if isinstance(to_block, str) and to_block.strip().lower() == "latest":
        end_blk = int(evm.block_number()) if callable(getattr(evm, "block_number", None)) else -1
    elif isinstance(to_block, str) and to_block.strip().startswith(("0x", "0X")):
        end_blk = int(to_block.strip(), 16)
    else:
        end_blk = int(to_block)
    anchor_tag: str = hex(end_blk) if end_blk >= 0 else "latest"
    log_to_block: int | str = end_blk if end_blk >= 0 else to_block

    def _call_at_anchor(sel: str) -> str:
        try:
            return evm.eth_call(clearinghouse, sel, block_tag=anchor_tag)
        except TypeError:
            return evm.eth_call(clearinghouse, sel)

    has_tree_hex = _call_at_anchor(_SDK_HAS_COMMITTED_ESCAPE_TREE_SEL)
    has_tree_raw = bytes.fromhex(has_tree_hex[2:] if has_tree_hex.startswith(("0x", "0X")) else has_tree_hex)
    if len(has_tree_raw) < 32 or int.from_bytes(has_tree_raw[:32], "big") == 0:
        raise RuntimeError("Clearinghouse hasCommittedEscapeTree() is false")

    seq_hex = _call_at_anchor(_SDK_LAST_BATCH_SEQ_ID_SEL)
    seq_raw = bytes.fromhex(seq_hex[2:] if seq_hex.startswith(("0x", "0X")) else seq_hex)
    last_batch_seq = int.from_bytes(seq_raw[:32], "big") if len(seq_raw) >= 32 else 0
    if last_batch_seq <= 0:
        raise RuntimeError("Clearinghouse lastBatchSeqId() is 0")

    root_hex = _call_at_anchor(_SDK_CURRENT_ESCAPE_MERKLE_ROOT_SEL)
    root_clean = root_hex[2:] if root_hex.startswith(("0x", "0X")) else root_hex
    root_bytes = bytes.fromhex(root_clean)
    if len(root_bytes) != 32:
        raise RuntimeError(f"Invalid currentEscapeMerkleRoot() response: {root_hex}")
    expected_root_hex = "0x" + root_bytes.hex()

    publisher_addr = ""
    publisher_topic: Optional[str] = None
    try:
        pub_hex = _call_at_anchor(
            _SDK_ESCAPE_LEAVES_PUBLISHER_SEL + int(last_batch_seq).to_bytes(32, "big").hex(),
        )
        pub_clean = pub_hex[2:] if pub_hex.startswith(("0x", "0X")) else pub_hex
        pub_raw = bytes.fromhex(pub_clean)
        if len(pub_raw) >= 32 and pub_raw[12:32] != (b"\x00" * 20):
            publisher_addr = "0x" + pub_raw[12:32].hex()
            publisher_topic = "0x" + ("00" * 12) + pub_raw[12:32].hex()
    except Exception:
        publisher_addr = ""
        publisher_topic = None

    batch_topic = "0x" + int(last_batch_seq).to_bytes(32, "big").hex()

    def _p_idx(v: Any) -> int:
        if v is None:
            return 0
        if isinstance(v, int):
            return v
        s = str(v).strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else (int(s) if s else 0)

    def _log_pos(lg: Dict[str, Any]) -> tuple[int, int, int]:
        return (
            _p_idx(lg.get("blockNumber", 0)),
            _p_idx(lg.get("transactionIndex", 0)),
            _p_idx(lg.get("logIndex", 0)),
        )

    def _query_logs_chunked(q_topics: List[Optional[str]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if end_blk >= 0:
            cur_end = end_blk
            cur_chunk = 2_000
            while cur_end >= start_blk:
                cur_start = max(start_blk, cur_end - cur_chunk + 1)
                span = cur_end - cur_start + 1
                try:
                    part = evm.get_logs(
                        address=clearinghouse,
                        topics=q_topics,
                        from_block=cur_start,
                        to_block=cur_end,
                    )
                except Exception as exc:
                    msg_lc = str(exc).lower()
                    if span > 10 and any(
                        m in msg_lc
                        for m in ("range", "block", "limit", "exceed", "too many", "too large", "10000", "-32005", "-32000")
                    ):
                        cur_chunk = max(10, min(cur_chunk, span) // 2)
                        continue
                    raise
                if part:
                    out.extend(lg for lg in part if isinstance(lg, dict) and lg.get("removed") is not True)
                cur_end = cur_start - 1
        else:
            part = evm.get_logs(
                address=clearinghouse,
                topics=q_topics,
                from_block=start_blk,
                to_block=log_to_block,
            )
            if part:
                out.extend(lg for lg in part if isinstance(lg, dict) and lg.get("removed") is not True)
        return out

    fin_topics: List[Optional[str]] = [
        ESCAPE_LEAVES_STREAM_FINALIZED_TOPIC,
        batch_topic,
        expected_root_hex,
    ]
    if publisher_topic is not None:
        fin_topics.append(publisher_topic)
    fin_logs = _query_logs_chunked(fin_topics)
    fin_pos: Optional[tuple[int, int, int]] = None
    fin_total_leaves: Optional[int] = None
    for lg in sorted(fin_logs, key=_log_pos):
        lt = list(lg.get("topics", []))
        if len(lt) < 3:
            continue
        if (
            str(lt[0]).lower() != ESCAPE_LEAVES_STREAM_FINALIZED_TOPIC.lower()
            or int(str(lt[1]), 16) != last_batch_seq
            or str(lt[2]).lower() != expected_root_hex.lower()
        ):
            continue
        if publisher_addr and len(lt) >= 4:
            topic_pub = "0x" + str(lt[3]).lower().removeprefix("0x")[-40:]
            if topic_pub != publisher_addr.lower():
                continue
        fin_pos = _log_pos(lg)
        d_hex = str(lg.get("data", "0x"))
        d_clean = d_hex[2:] if d_hex.startswith(("0x", "0X")) else d_hex
        if len(d_clean) >= 64:
            fin_total_leaves = int.from_bytes(bytes.fromhex(d_clean[:64]), "big")

    rst_topics: List[Optional[str]] = [ESCAPE_LEAVES_CHUNK_RESET_TOPIC, batch_topic]
    if publisher_topic is not None:
        rst_topics.append(publisher_topic)
    rst_logs = _query_logs_chunked(rst_topics)
    reset_cutoff: Optional[tuple[int, int, int]] = None
    for lg in sorted(rst_logs, key=_log_pos):
        lt = list(lg.get("topics", []))
        if len(lt) < 2:
            continue
        if (
            str(lt[0]).lower() != ESCAPE_LEAVES_CHUNK_RESET_TOPIC.lower()
            or int(str(lt[1]), 16) != last_batch_seq
        ):
            continue
        if publisher_addr and len(lt) >= 3:
            topic_sender = "0x" + str(lt[2]).lower().removeprefix("0x")[-40:]
            if topic_sender != publisher_addr.lower():
                continue
        pos = _log_pos(lg)
        if fin_pos is not None and pos > fin_pos:
            continue
        if reset_cutoff is None or pos > reset_cutoff:
            reset_cutoff = pos

    def _is_canonical_pub_tx(tx_h: str) -> bool:
        if not publisher_addr:
            return True
        if not tx_h:
            return False
        if not callable(getattr(evm, "rpc", None)):
            return True
        tx_obj = evm.rpc("eth_getTransactionByHash", [tx_h])
        if not isinstance(tx_obj, dict) or not tx_obj.get("from"):
            raise RuntimeError(
                f"Unable to resolve tx.from for EscapeLeavesPublished tx {tx_h} against publisher {publisher_addr}"
            )
        return str(tx_obj["from"]).strip().lower() == publisher_addr.lower()

    topics: List[Optional[str]] = [ESCAPE_LEAVES_PUBLISHED_TOPIC, batch_topic, expected_root_hex]
    raw_pub_logs = _query_logs_chunked(topics)
    seen_keys: set[tuple[str, int]] = set()
    window_logs: List[Dict[str, Any]] = []
    for lg in sorted(raw_pub_logs, key=_log_pos):
        lt = list(lg.get("topics", []))
        if len(lt) < 3:
            continue
        if (
            str(lt[0]).lower() != ESCAPE_LEAVES_PUBLISHED_TOPIC.lower()
            or int(str(lt[1]), 16) != last_batch_seq
            or str(lt[2]).lower() != expected_root_hex.lower()
        ):
            continue
        pos = _log_pos(lg)
        if reset_cutoff is not None and pos <= reset_cutoff:
            continue
        if fin_pos is not None and (pos[0], pos[1]) > (fin_pos[0], fin_pos[1]):
            continue
        tx_h = str(lg.get("transactionHash", "")).lower()
        l_idx = _p_idx(lg.get("logIndex", 0))
        if (tx_h, l_idx) in seen_keys:
            continue
        seen_keys.add((tx_h, l_idx))
        window_logs.append(lg)

    filtered_logs: List[Dict[str, Any]] = []
    if fin_pos is not None and fin_total_leaves is not None and fin_total_leaves > 0:
        # Try strict tx_from-verified chunks first (after EscapeLeavesChunkReset), then fall back
        # only if a smart-contract publisher wallet emitted matching totalLeaves before fin_pos.
        strict_logs = [lg for lg in window_logs if _is_canonical_pub_tx(str(lg.get("transactionHash", "")).lower())]
        candidates = [strict_logs]
        if len(strict_logs) != len(window_logs):
            candidates.append(window_logs)
        for cand_set in candidates:
            target_bytes = fin_total_leaves * 34
            chunks_data = [_decode_escape_leaves_published_data(str(lg.get("data", "0x"))) for lg in cand_set]
            acc_len = 0
            picked: List[Dict[str, Any]] = []
            for idx in range(len(cand_set) - 1, -1, -1):
                acc_len += len(chunks_data[idx])
                picked.append(cand_set[idx])
                if acc_len >= target_bytes:
                    break
            if acc_len == target_bytes:
                picked.reverse()
                test_buf = bytearray()
                for lg in picked:
                    test_buf.extend(_decode_escape_leaves_published_data(str(lg.get("data", "0x"))))
                try:
                    if compute_escape_merkle_root_from_packed_leaves(bytes(test_buf)).lower() == expected_root_hex.lower():
                        filtered_logs = picked
                        break
                except ValueError as merkle_err:
                    _ = merkle_err
        if not filtered_logs and strict_logs:
            filtered_logs = strict_logs
    else:
        for lg in window_logs:
            if _is_canonical_pub_tx(str(lg.get("transactionHash", "")).lower()):
                filtered_logs.append(lg)

    if not filtered_logs:
        raise LookupError(
            f"No EscapeLeavesPublished logs found on {clearinghouse} for batchSeqId={last_batch_seq}"
        )

    packed_buf = bytearray()
    for lg in sorted(filtered_logs, key=_log_pos):
        packed_buf.extend(_decode_escape_leaves_published_data(str(lg.get("data", "0x"))))

    return reconstruct_escape_merkle_proof_from_packed_leaves(
        bytes(packed_buf),
        account_id=account_id,
        asset_id=asset_id,
        expected_escape_merkle_root=expected_root_hex,
    )


class EthWalletSigner:
    """Zero-dependency SEC2 `secp256k1` Ethereum wallet signer (EIP-55 & EIP-191 `personal_sign`)."""

    def __init__(self, privkey_hex: Optional[str] = None) -> None:
        if privkey_hex is None:
            while True:
                cand = int.from_bytes(os.urandom(32), "big")
                if 1 <= cand < _SECP_N:
                    self._priv = cand
                    break
        else:
            clean = privkey_hex[2:] if privkey_hex.startswith(("0x", "0X")) else privkey_hex
            raw = bytes.fromhex(clean)
            if len(raw) != 32:
                raise ValueError("secp256k1 private key must be 32 bytes")
            self._priv = int.from_bytes(raw, "big")
            if not (1 <= self._priv < _SECP_N):
                raise ValueError("secp256k1 private key out of range [1, n-1]")
        pt = _secp_scalar_mul(self._priv)
        if pt is None:
            raise ValueError("Invalid secp256k1 public key")
        pub64 = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
        self.address = format_eip55_address(keccak256(pub64)[12:])

    @property
    def private_key_hex(self) -> str:
        return "0x" + self._priv.to_bytes(32, "big").hex()

    def _sign_digest_raw(self, digest32: bytes) -> tuple[int, int, int]:
        if len(digest32) != 32:
            raise ValueError("Digest must be 32 bytes")
        z = int.from_bytes(digest32, "big") % _SECP_N
        k = _rfc6979_secp256k1_k(self._priv, digest32)
        pt = _secp_scalar_mul(k)
        if pt is None or (pt[0] % _SECP_N) == 0:
            raise RuntimeError("Invalid RFC-6979 nonce point")
        r = pt[0] % _SECP_N
        recid = pt[1] & 1
        s = (pow(k, -1, _SECP_N) * (z + r * self._priv)) % _SECP_N
        if s == 0:
            raise RuntimeError("Invalid zero s signature")
        if s > _SECP_N // 2:
            s = _SECP_N - s
            recid ^= 1
        return r, s, recid

    def sign_digest(self, digest32: bytes) -> str:
        r, s, recid = self._sign_digest_raw(digest32)
        v = 27 + recid
        return "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])).hex()

    def personal_sign(self, message: str | bytes) -> str:
        return self.sign_digest(eip191_personal_sign_hash(message))

    def sign_legacy_transaction(
        self,
        nonce: int,
        gas_price: int,
        gas_limit: int,
        to_addr: str = "",
        value: int = 0,
        data: bytes | str = b"",
        chain_id: int = 31337,
    ) -> str:
        """Sign an EIP-155 legacy raw EVM transaction (`0x...` RLP hex) ready for `eth_sendRawTransaction`."""
        if not to_addr:
            to_bytes = b""
        else:
            clean_to = to_addr[2:] if to_addr.startswith(("0x", "0X")) else to_addr
            to_bytes = bytes.fromhex(clean_to)
            if len(to_bytes) != 20:
                raise ValueError(f"Expected 20-byte recipient address, got {len(to_bytes)} bytes")

        if isinstance(data, str):
            clean_data = data[2:] if data.startswith(("0x", "0X")) else data
            data_bytes = bytes.fromhex(clean_data) if clean_data else b""
        else:
            data_bytes = bytes(data)

        if chain_id > 0:
            signing_rlp = rlp_encode(
                [nonce, gas_price, gas_limit, to_bytes, value, data_bytes, chain_id, 0, 0]
            )
            r, s, recid = self._sign_digest_raw(keccak256(signing_rlp))
            v = recid + 35 + 2 * chain_id
        else:
            signing_rlp = rlp_encode([nonce, gas_price, gas_limit, to_bytes, value, data_bytes])
            r, s, recid = self._sign_digest_raw(keccak256(signing_rlp))
            v = 27 + recid

        signed_rlp = rlp_encode([nonce, gas_price, gas_limit, to_bytes, value, data_bytes, v, r, s])
        return "0x" + signed_rlp.hex()

    def sign_eip1559_transaction(
        self,
        nonce: int,
        max_priority_fee_per_gas: int,
        max_fee_per_gas: int,
        gas_limit: int,
        to_addr: str = "",
        value: int = 0,
        data: bytes | str = b"",
        chain_id: int = 31337,
        access_list: Optional[List[Any]] = None,
    ) -> str:
        """Sign an EIP-1559 Type-2 (`0x02 || rlp(...)`) raw EVM transaction ready for `eth_sendRawTransaction`."""
        if chain_id <= 0:
            raise ValueError(f"EIP-1559 chain_id must be positive, got {chain_id}")
        if max_priority_fee_per_gas < 0 or max_fee_per_gas < 0:
            raise ValueError("EIP-1559 gas fees must be non-negative")
        if max_fee_per_gas < max_priority_fee_per_gas:
            raise ValueError("max_fee_per_gas must be >= max_priority_fee_per_gas")

        if not to_addr:
            to_bytes = b""
        else:
            clean_to = to_addr[2:] if to_addr.startswith(("0x", "0X")) else to_addr
            to_bytes = bytes.fromhex(clean_to)
            if len(to_bytes) != 20:
                raise ValueError(f"Expected 20-byte recipient address, got {len(to_bytes)} bytes")

        if isinstance(data, str):
            clean_data = data[2:] if data.startswith(("0x", "0X")) else data
            data_bytes = bytes.fromhex(clean_data) if clean_data else b""
        else:
            data_bytes = bytes(data)

        eff_access_list = list(access_list) if access_list is not None else []
        unsigned_fields = [
            int(chain_id),
            int(nonce),
            int(max_priority_fee_per_gas),
            int(max_fee_per_gas),
            int(gas_limit),
            to_bytes,
            int(value),
            data_bytes,
            eff_access_list,
        ]
        signing_payload = b"\x02" + rlp_encode(unsigned_fields)
        r, s, y_parity = self._sign_digest_raw(keccak256(signing_payload))
        signed_payload = b"\x02" + rlp_encode(unsigned_fields + [y_parity, r, s])
        return "0x" + signed_payload.hex()


def compute_rbf_eip1559_fees(
    prev_max_fee: int,
    prev_tip: int,
    new_base: int,
    live_tip: int = 0,
    gas_bump_bps: int = 1500,
    max_fee_cap_wei: int = 0,
) -> tuple[int, int]:
    """
    Compute EIP-1559 replacement fees satisfying >= +15% bump over BOTH `prev_max_fee` and `prev_tip`
    even when `new_base` drops between attempts:
      `bumped_max_fee = max(int(prev_max_fee * 115 // 100) + 1, new_base * 2 + bumped_tip)`
    """
    eff_bps = max(1500, int(gas_bump_bps))
    bumped_tip = max(
        int(prev_tip * 115 // 100) + 1,
        ((int(prev_tip) * (10_000 + eff_bps)) // 10_000) + 1 if int(prev_tip) > 0 else 0,
        ((max(0, int(live_tip)) * (10_000 + eff_bps) + 9_999) // 10_000) + 1,
        1_000_000,
    )
    bumped_max_fee = max(
        int(prev_max_fee * 115 // 100) + 1,
        ((int(prev_max_fee) * (10_000 + eff_bps)) // 10_000) + 1 if int(prev_max_fee) > 0 else 0,
        max(0, int(new_base)) * 2 + bumped_tip,
        bumped_tip,
    )
    if max_fee_cap_wei > 0:
        min_req_max = max(
            (int(prev_max_fee * 110 // 100) + 1) if prev_max_fee > 0 else 0,
            max(0, int(new_base)),
        )
        if min_req_max > max_fee_cap_wei:
            raise RuntimeError(
                f"EIP-1559 replacement fee ({min_req_max} wei) exceeds max_fee_cap ({max_fee_cap_wei} wei)"
            )
        bumped_max_fee = min(bumped_max_fee, int(max_fee_cap_wei))
        max_allowed_tip = bumped_max_fee
        if prev_tip > 0 and (int(prev_tip * 110 // 100) + 1) > max_allowed_tip:
            raise RuntimeError(
                f"EIP-1559 replacement priority fee exceeds max_fee_cap ({max_fee_cap_wei} wei)"
            )
        bumped_tip = min(bumped_tip, max_allowed_tip)
    return bumped_max_fee, bumped_tip


_MAX_SDK_HTTP_RESPONSE_BYTES = 64 * 1024 * 1024
_DEFAULT_USER_AGENT = "ArenaSDK/4.9"
_DEFAULT_SSL_CONTEXT_LOCK = threading.Lock()
_DEFAULT_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _default_ssl_context() -> ssl.SSLContext:
    global _DEFAULT_SSL_CONTEXT
    with _DEFAULT_SSL_CONTEXT_LOCK:
        if _DEFAULT_SSL_CONTEXT is not None:
            return _DEFAULT_SSL_CONTEXT
        ctx = ssl.create_default_context()
        try:
            import certifi  # type: ignore[import-not-found]

            cafile = str(certifi.where() or "").strip()
            if cafile and os.path.isfile(cafile):
                ctx.load_verify_locations(cafile=cafile)
        except Exception as cert_exc:
            _ = cert_exc
        _DEFAULT_SSL_CONTEXT = ctx
        return ctx


def _close_http_conn(conn: http.client.HTTPConnection) -> None:
    try:
        conn.close()
    except OSError as close_err:
        _ = close_err


def _has_http_proxy_env() -> bool:
    return any(
        bool(os.environ.get(k))
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        _ = (req, fp, code, msg, headers, newurl)
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _sanitize_http_url_for_error(parsed: urllib.parse.SplitResult, host: str) -> str:
    netloc = (
        f"[{host}]:{parsed.port}"
        if ":" in host and parsed.port
        else (f"[{host}]" if ":" in host else (f"{host}:{parsed.port}" if parsed.port else host))
    )
    redacted_q = "redacted=1" if parsed.query else ""
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, redacted_q, ""))


class _KeepAliveHttpPool:
    """Thread-safe zero-dependency HTTP/1.1 Keep-Alive connection pool with deterministic cleanup."""

    def __init__(self, max_idle: int = 4, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self._max_idle = max(1, int(max_idle))
        self._ssl_context = ssl_context
        self._lock = threading.Lock()
        self._idle: List[tuple[tuple[str, str, int], http.client.HTTPConnection, weakref.finalize]] = []
        self._in_use: int = 0

    def close(self) -> None:
        with self._lock:
            items = list(self._idle)
            self._idle.clear()
        for _, _, fin in items:
            fin()

    @staticmethod
    def _sanitize_timeout(timeout: float) -> float:
        raw_t = float(timeout)
        if not math.isfinite(raw_t):
            raise ValueError("HTTP timeout must be finite")
        return min(86_400.0, max(0.05, raw_t))

    def _new_conn(
        self, key: tuple[str, str, int], timeout: float
    ) -> tuple[http.client.HTTPConnection, weakref.finalize]:
        scheme, host, port = key
        eff_t = self._sanitize_timeout(timeout)
        if scheme == "https":
            ctx = self._ssl_context if self._ssl_context is not None else _default_ssl_context()
            conn = http.client.HTTPSConnection(
                host, port, timeout=eff_t, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=eff_t)
        fin = weakref.finalize(self, _close_http_conn, conn)
        return conn, fin

    def _checkout(
        self, key: tuple[str, str, int], timeout: float
    ) -> tuple[http.client.HTTPConnection, weakref.finalize, bool]:
        eff_t = self._sanitize_timeout(timeout)
        reused = False
        conn: Optional[http.client.HTTPConnection] = None
        fin: Optional[weakref.finalize] = None
        with self._lock:
            self._in_use += 1
            for idx in range(len(self._idle) - 1, -1, -1):
                k, c_cand, f_cand = self._idle[idx]
                if k == key:
                    self._idle.pop(idx)
                    conn, fin = c_cand, f_cand
                    reused = True
                    break
        if conn is None or fin is None:
            try:
                conn, fin = self._new_conn(key, eff_t)
            except BaseException:
                with self._lock:
                    self._in_use = max(0, self._in_use - 1)
                raise
        else:
            try:
                conn.timeout = eff_t
                if conn.sock is not None:
                    try:
                        conn.sock.settimeout(eff_t)
                    except OSError as to_err:
                        _ = to_err
            except BaseException:
                self._release_discard(fin)
                raise
        return conn, fin, reused

    def _release_discard(self, fin: weakref.finalize) -> None:
        with self._lock:
            self._in_use = max(0, self._in_use - 1)
        fin()

    def _checkin(
        self,
        key: tuple[str, str, int],
        conn: http.client.HTTPConnection,
        fin: weakref.finalize,
    ) -> None:
        evicted: List[weakref.finalize] = []
        with self._lock:
            self._in_use = max(0, self._in_use - 1)
            while len(self._idle) >= self._max_idle:
                _, _, old_fin = self._idle.pop(0)
                evicted.append(old_fin)
            self._idle.append((key, conn, fin))
        for old_fin in evicted:
            old_fin()

    def request(
        self,
        method: str,
        url: str,
        body: Optional[bytes],
        headers: Dict[str, str],
        timeout: float,
        max_bytes: int,
        retry_post: bool = False,
    ) -> tuple[int, bytes]:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        raw_host = parsed.hostname
        host = urllib.parse.unquote(raw_host) if raw_host else ""
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        req_headers = dict(headers)
        low_hdr_keys = {k.lower() for k in req_headers}
        if "user-agent" not in low_hdr_keys:
            req_headers["User-Agent"] = _DEFAULT_USER_AGENT
        if (parsed.username is not None or parsed.password is not None) and "authorization" not in low_hdr_keys:
            u_str = urllib.parse.unquote(parsed.username or "")
            p_str = urllib.parse.unquote(parsed.password or "")
            b64_cred = base64.b64encode(f"{u_str}:{p_str}".encode("utf-8")).decode("ascii")
            req_headers["Authorization"] = f"Basic {b64_cred}"

        eff_timeout = self._sanitize_timeout(timeout)
        if scheme not in ("http", "https") or not host:
            raise ValueError(f"Unsupported HTTP URL scheme or empty host: {scheme!r}")
        err_url = _sanitize_http_url_for_error(parsed, host)
        if _has_http_proxy_env():
            clean_url = urllib.parse.urlunsplit(
                (
                    parsed.scheme,
                    (f"[{host}]:{parsed.port}" if ":" in host and parsed.port else (f"[{host}]" if ":" in host else (f"{host}:{parsed.port}" if parsed.port else host))),
                    parsed.path,
                    parsed.query,
                    parsed.fragment,
                )
            )
            req = urllib.request.Request(clean_url, data=body, headers=req_headers, method=method)
            proxy_deadline = time.monotonic() + eff_timeout

            def _read_bounded_body(stream_obj: object, deadline_val: float) -> bytes:
                fp_lvl1 = getattr(stream_obj, "fp", None)
                fp_lvl2 = getattr(fp_lvl1, "fp", None)
                raw_obj = getattr(fp_lvl1, "raw", None) or getattr(fp_lvl2, "raw", None)
                b_sock = getattr(raw_obj, "_sock", None)
                r_fn = (
                    getattr(stream_obj, "read1", None)
                    or getattr(fp_lvl1, "read1", None)
                    or getattr(stream_obj, "read")
                )
                out_chunks: List[bytes] = []
                tot = 0
                lim = max_bytes + 1
                while tot < lim:
                    rem_b = deadline_val - time.monotonic()
                    if rem_b <= 0.0:
                        raise TimeoutError("HTTP response body read exceeded wall-clock deadline")
                    if b_sock is not None:
                        try:
                            b_sock.settimeout(max(0.01, rem_b))
                        except OSError as to_err:
                            _ = to_err
                    piece_b = r_fn(min(65_536, lim - tot))
                    if not piece_b:
                        break
                    out_chunks.append(piece_b)
                    tot += len(piece_b)
                return b"".join(out_chunks)

            try:
                with _NO_REDIRECT_OPENER.open(req, timeout=eff_timeout) as resp:
                    raw_bytes = _read_bounded_body(resp, proxy_deadline)
                    status = int(getattr(resp, "status", 200))
                    return status, raw_bytes
            except urllib.error.HTTPError as http_err:
                try:
                    err_bytes = _read_bounded_body(http_err, proxy_deadline) if http_err.fp is not None else b""
                finally:
                    try:
                        http_err.close()
                    except OSError as close_err:
                        _ = close_err
                raise urllib.error.HTTPError(
                    err_url,
                    int(http_err.code),
                    str(http_err.reason),
                    http_err.headers,
                    io.BytesIO(err_bytes[:max_bytes]),
                ) from None

        port = parsed.port or (443 if scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"
        key = (scheme, host, int(port))
        host_hdr_base = f"[{host}]" if ":" in host else host
        if "host" not in {k.lower() for k in req_headers}:
            default_port = 443 if scheme == "https" else 80
            req_headers["Host"] = host_hdr_base if int(port) == default_port else f"{host_hdr_base}:{int(port)}"
        req_headers.setdefault("Connection", "keep-alive")
        req_headers.setdefault("Accept-Encoding", "identity")
        can_retry = method.upper() in ("GET", "HEAD", "OPTIONS") or bool(retry_post)

        for attempt in range(2):
            conn, fin, reused = self._checkout(key, eff_timeout)
            try:
                stale_drained_exhausted = True
                for _ in range(self._max_idle + 1):
                    if not reused or conn.sock is None:
                        stale_drained_exhausted = False
                        break
                    try:
                        rdy, _, _ = select.select([conn.sock], [], [], 0.0)
                    except (OSError, ValueError):
                        rdy = [conn.sock]
                    if not rdy:
                        stale_drained_exhausted = False
                        break
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                    conn, fin, reused = self._checkout(key, eff_timeout)
                if stale_drained_exhausted and reused and conn.sock is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                    with self._lock:
                        self._in_use += 1
                    try:
                        conn, fin = self._new_conn(key, eff_timeout)
                    except BaseException:
                        with self._lock:
                            self._in_use = max(0, self._in_use - 1)
                        raise
                    reused = False
                deadline_mono = time.monotonic() + eff_timeout
                resp: Optional[http.client.HTTPResponse] = None
                try:
                    if conn.sock is None:
                        conn.connect()
                        if conn.sock is not None:
                            try:
                                conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            except OSError as tcp_err:
                                _ = tcp_err
                    if conn.sock is not None:
                        rem_req = deadline_mono - time.monotonic()
                        if rem_req <= 0.0:
                            raise TimeoutError("HTTP request exceeded wall-clock deadline")
                        try:
                            conn.sock.settimeout(max(0.01, rem_req))
                        except OSError as to_err:
                            _ = to_err
                    conn.request(method, target, body=body, headers=req_headers)
                    if conn.sock is not None:
                        rem_hdr = deadline_mono - time.monotonic()
                        if rem_hdr <= 0.0:
                            raise TimeoutError("HTTP response header exceeded wall-clock deadline")
                        try:
                            conn.sock.settimeout(max(0.01, rem_hdr))
                        except OSError as to_err:
                            _ = to_err
                    resp = conn.getresponse()
                    status = int(resp.status)
                    body_sock = conn.sock or getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
                    read_fn = getattr(resp, "read1", resp.read)
                    chunks: List[bytes] = []
                    total_len = 0
                    cap = max_bytes + 1
                    while total_len < cap:
                        rem = deadline_mono - time.monotonic()
                        if rem <= 0.0:
                            raise TimeoutError("HTTP response body read exceeded wall-clock deadline")
                        if body_sock is not None:
                            try:
                                body_sock.settimeout(max(0.01, rem))
                            except OSError as to_err:
                                _ = to_err
                        piece = read_fn(min(65_536, cap - total_len))
                        if not piece:
                            break
                        chunks.append(piece)
                        total_len += len(piece)
                    raw_bytes = b"".join(chunks)
                    will_close = bool(resp.will_close) or len(raw_bytes) > max_bytes or status >= 500
                finally:
                    if resp is not None:
                        try:
                            resp.close()
                        except OSError as resp_err:
                            _ = resp_err
            except (
                http.client.RemoteDisconnected,
                http.client.CannotSendRequest,
                http.client.BadStatusLine,
                http.client.IncompleteRead,
                http.client.HTTPException,
                BrokenPipeError,
                ConnectionAbortedError,
            ) as stale_exc:
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                if reused and can_retry and attempt == 0:
                    continue
                raise ConnectionResetError(str(stale_exc)) from stale_exc
            except ConnectionResetError:
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                if reused and can_retry and attempt == 0:
                    continue
                raise
            except (TimeoutError, socket.timeout):
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                raise
            except ConnectionRefusedError as ref_exc:
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                raise urllib.error.URLError(ref_exc) from ref_exc
            except OSError as os_exc:
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                if reused and can_retry and attempt == 0:
                    continue
                raise urllib.error.URLError(os_exc) from os_exc
            except BaseException:
                if fin is not None:
                    old_fin = fin
                    fin = None
                    self._release_discard(old_fin)
                raise

            if will_close:
                self._release_discard(fin)
            else:
                self._checkin(key, conn, fin)

            if 200 <= status < 300:
                return status, raw_bytes
            raise urllib.error.HTTPError(
                err_url,
                status,
                resp.reason,
                resp.headers,
                io.BytesIO(raw_bytes[:max_bytes]),
            )
        raise RuntimeError("Unreachable HTTP keep-alive retry state")


_SAFE_READONLY_RPC_METHODS = frozenset(
    {
        "eth_call",
        "eth_getLogs",
        "eth_blockNumber",
        "eth_chainId",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_feeHistory",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_estimateGas",
        "eth_getCode",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "net_version",
    }
)


@contextlib.contextmanager
def _acquire_tx_file_lock(lock_path: str, timeout_sec: float = 30.0) -> Iterator[None]:
    """Zero-dependency cross-process exclusive file lock for EVM nonce allocation & tx broadcast."""
    norm_path = str(lock_path or "").strip()
    if not norm_path:
        yield
        return
    p = Path(norm_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0.05, float(timeout_sec))
    fp = p.open("a+b")
    try:
        fp.seek(0, os.SEEK_END)
        if fp.tell() == 0:
            fp.write(b"\x00")
            fp.flush()
        if os.name == "nt":
            import msvcrt

            locked = False
            while True:
                try:
                    fp.seek(0)
                    msvcrt.locking(fp.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Timed out acquiring EVM tx file lock ({timeout_sec:.2f}s): {norm_path}"
                        ) from exc
                    time.sleep(0.02)
            try:
                yield
            finally:
                if locked:
                    try:
                        fp.seek(0)
                        msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        locked = False
        else:
            import fcntl

            locked = False
            while True:
                try:
                    fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Timed out acquiring EVM tx file lock ({timeout_sec:.2f}s): {norm_path}"
                        ) from exc
                    time.sleep(0.02)
            try:
                yield
            finally:
                if locked:
                    try:
                        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        locked = False
    finally:
        fp.close()


class EvmJsonRpcClient:
    """Zero-dependency Ethereum JSON-RPC 2.0 client (`eth_call`, `eth_getLogs`, `eth_sendRawTransaction`)."""

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        timeout: float = 10.0,
        max_fee_gwei: float = 0.0,
        tx_lock_file: str = "",
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        urls = [u.strip() for u in str(rpc_url or "").split(",") if u.strip()]
        self._rpc_urls: List[str] = urls or ["http://127.0.0.1:8545"]
        self.rpc_url = self._rpc_urls[0]
        self.timeout = timeout
        self.max_fee_cap_wei = (
            max(1, int(round(float(max_fee_gwei) * 1_000_000_000.0)))
            if float(max_fee_gwei) > 0.0
            else 0
        )
        self.tx_lock_file = str(tx_lock_file or "").strip()
        self._tx_lock_local = threading.local()
        self._rpc_id = 0
        self._cached_chain_id: Optional[int] = None
        self._nonce_lock = threading.Lock()
        self._next_nonce_by_addr: Dict[str, int] = {}
        self._sent_fees_by_addr_nonce: Dict[tuple[str, int], tuple[int, int]] = {}
        self._http_pool = _KeepAliveHttpPool(ssl_context=ssl_context)

    def close(self) -> None:
        self._http_pool.close()

    @contextlib.contextmanager
    def acquire_tx_lock(self, timeout_sec: float = 30.0) -> Iterator[None]:
        tl = getattr(self, "_tx_lock_local", None)
        if tl is None:
            self._tx_lock_local = threading.local()
            tl = self._tx_lock_local
        cur_depth = int(getattr(tl, "depth", 0))
        if cur_depth > 0:
            tl.depth = cur_depth + 1
            try:
                yield
            finally:
                tl.depth = cur_depth
            return
        with _acquire_tx_file_lock(self.tx_lock_file, timeout_sec=timeout_sec):
            tl.depth = 1
            try:
                yield
            finally:
                tl.depth = 0

    def rpc(
        self,
        method: str,
        params: List[Any],
        *,
        max_response_bytes: int = _MAX_SDK_HTTP_RESPONSE_BYTES,
    ) -> Any:
        eff_max_bytes = max(1024, int(max_response_bytes))
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params,
        }
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        urls = list(getattr(self, "_rpc_urls", []) or [])
        if not urls or (len(urls) == 1 and self.rpc_url and self.rpc_url != urls[0]):
            urls = [u.strip() for u in str(self.rpc_url or "").split(",") if u.strip()] or ["http://127.0.0.1:8545"]
        is_readonly = method in _SAFE_READONLY_RPC_METHODS
        last_exc: Optional[BaseException] = None
        parsed: Any = None
        got_response = False
        for url_idx, cur_url in enumerate(urls):
            has_next_url = (url_idx + 1) < len(urls)
            backoff_s = 0.1
            max_attempts = 2 if has_next_url else 4
            for attempt in range(max_attempts):
                try:
                    _, raw_bytes = self._http_pool.request(
                        "POST",
                        cur_url,
                        raw_body,
                        {"Content-Type": "application/json"},
                        self.timeout,
                        eff_max_bytes,
                        retry_post=is_readonly,
                    )
                    if len(raw_bytes) > eff_max_bytes:
                        if eff_max_bytes >= (1024 * 1024):
                            raise RuntimeError(
                                f"EVM JSON-RPC response exceeded {eff_max_bytes // (1024 * 1024)} MiB limit"
                            )
                        raise RuntimeError(
                            f"EVM JSON-RPC response exceeded {eff_max_bytes} byte limit"
                        )
                    parsed = json.loads(raw_bytes.decode("utf-8"))
                    if not isinstance(parsed, dict):
                        raise RuntimeError(f"EVM JSON-RPC {method} returned non-object payload")
                    got_response = True
                    break
                except urllib.error.HTTPError as exc:
                    last_exc = exc
                    if exc.code in (429, 502, 503, 504):
                        if attempt + 1 < max_attempts:
                            time.sleep(backoff_s)
                            backoff_s = min(1.0, backoff_s * 2.0)
                            continue
                        if has_next_url:
                            break
                    err_body = ""
                    try:
                        err_body = exc.read(_MAX_SDK_HTTP_RESPONSE_BYTES).decode("utf-8", errors="replace")
                    except Exception:
                        err_body = ""
                    if err_body:
                        try:
                            err_json = json.loads(err_body)
                        except json.JSONDecodeError:
                            err_json = None
                        if isinstance(err_json, dict) and err_json.get("error") is not None:
                            raise RuntimeError(
                                f"EVM JSON-RPC {method} HTTP {exc.code} error: {err_json['error']}"
                            ) from exc
                        raise RuntimeError(
                            f"EVM JSON-RPC {method} HTTP {exc.code}: {err_body[:512]}"
                        ) from exc
                    raise
                except (TimeoutError, socket.timeout, ConnectionResetError) as exc:
                    last_exc = exc
                    if attempt + 1 < max_attempts:
                        time.sleep(backoff_s)
                        backoff_s = min(1.0, backoff_s * 2.0)
                        continue
                    if has_next_url:
                        break
                    raise exc
                except urllib.error.URLError as exc:
                    last_exc = exc
                    reason = getattr(exc, "reason", None)
                    if isinstance(reason, ConnectionRefusedError):
                        if has_next_url:
                            break
                        raise
                    if attempt + 1 < max_attempts:
                        time.sleep(backoff_s)
                        backoff_s = min(1.0, backoff_s * 2.0)
                        continue
                    if has_next_url:
                        break
                    raise
            if got_response:
                if has_next_url or url_idx > 0:
                    self.rpc_url = cur_url
                break
        if not got_response:
            if last_exc is not None:
                raise last_exc
            raise RuntimeError(f"EVM JSON-RPC {method} failed across all RPC URLs")
        if "error" in parsed and parsed["error"] is not None:
            raise RuntimeError(f"EVM JSON-RPC {method} error: {parsed['error']}")
        return parsed.get("result")

    def chain_id(self) -> int:
        res = int(str(self.rpc("eth_chainId", [])), 16)
        self._cached_chain_id = res
        return res

    def block_number(self) -> int:
        return int(str(self.rpc("eth_blockNumber", [])), 16)

    def get_nonce(self, address: str, block_tag: str = "latest") -> int:
        return int(str(self.rpc("eth_getTransactionCount", [address, block_tag])), 16)

    def gas_price(self) -> int:
        return max(1, int(str(self.rpc("eth_gasPrice", [])), 16))

    def _allocate_nonce(self, address: str) -> int:
        addr_key = address.lower()
        with self._nonce_lock:
            if addr_key not in self._next_nonce_by_addr:
                try:
                    self._next_nonce_by_addr[addr_key] = self.get_nonce(address, "pending")
                except Exception:
                    self._next_nonce_by_addr[addr_key] = self.get_nonce(address, "latest")
            nonce = self._next_nonce_by_addr[addr_key]
            self._next_nonce_by_addr[addr_key] = nonce + 1
            return nonce

    def _resync_nonce_after_error(self, address: str, failed_nonce: int, err_msg_lc: str) -> int:
        _ = (failed_nonce, err_msg_lc)
        addr_key = address.lower()
        with self._nonce_lock:
            latest_nonce = self.get_nonce(address, "latest")
            try:
                pending_nonce = self.get_nonce(address, "pending")
                synced = max(latest_nonce, pending_nonce)
            except Exception:
                synced = latest_nonce
            self._next_nonce_by_addr[addr_key] = synced + 1
            return synced

    @staticmethod
    def _is_nonce_error(exc: BaseException) -> bool:
        msg = str(exc).lower()
        if "max_fee_cap" in msg or "max_fee_gwei" in msg:
            return False
        return any(
            tok in msg
            for tok in ("nonce", "replacement", "underpriced", "already known", "known transaction")
        )

    def clear_sent_fee_cache(self, signer_addr: str, nonce: int) -> None:
        with self._nonce_lock:
            self._sent_fees_by_addr_nonce.pop((signer_addr.lower(), int(nonce)), None)

    def reset_nonce_cache(self, signer_addr: str) -> None:
        with self._nonce_lock:
            self._next_nonce_by_addr.pop(signer_addr.strip().lower(), None)

    def _build_signed_tx(
        self,
        signer: EthWalletSigner,
        nonce: int,
        to_addr: str,
        data: bytes | str,
        value: int,
        gas_limit: int,
        cid: int,
        max_priority_fee_per_gas: Optional[int] = None,
        max_fee_per_gas: Optional[int] = None,
        gas_bump_bps: int = 0,
        prev_max_fee_per_gas: Optional[int] = None,
        prev_priority_fee_per_gas: Optional[int] = None,
    ) -> str:
        gp = self.gas_price()
        base_fee: Optional[int] = None
        try:
            blk = self.rpc("eth_getBlockByNumber", ["latest", False])
            if isinstance(blk, dict) and blk.get("baseFeePerGas") is not None:
                base_fee = int(str(blk["baseFeePerGas"]), 16)
        except Exception:
            base_fee = None

        addr_nonce_key = (signer.address.lower(), int(nonce))
        with self._nonce_lock:
            recorded_prev = self._sent_fees_by_addr_nonce.get(addr_nonce_key)
        eff_prev_max = (
            int(prev_max_fee_per_gas)
            if prev_max_fee_per_gas is not None
            else (recorded_prev[0] if recorded_prev is not None else 0)
        )
        eff_prev_tip = (
            int(prev_priority_fee_per_gas)
            if prev_priority_fee_per_gas is not None
            else (recorded_prev[1] if recorded_prev is not None else 0)
        )

        if base_fee is not None and cid > 0:
            if self.max_fee_cap_wei > 0 and base_fee > self.max_fee_cap_wei:
                raise RuntimeError(
                    f"Current block baseFeePerGas ({base_fee} wei) exceeds max_fee_gwei cap ({self.max_fee_cap_wei} wei)"
                )
            if max_priority_fee_per_gas is not None:
                prio_fee = max(0, int(max_priority_fee_per_gas))
            else:
                try:
                    mp_raw = self.rpc("eth_maxPriorityFeePerGas", [])
                    prio_fee = max(0, int(str(mp_raw), 16)) if mp_raw is not None else max(0, gp - base_fee)
                except Exception:
                    prio_fee = max(0, gp - base_fee) if gp > base_fee else min(gp, 1_000_000_000)
            if max_fee_per_gas is not None:
                max_fee = max(int(max_fee_per_gas), prio_fee)
            else:
                max_fee = max(base_fee * 2 + prio_fee, gp)
            if gas_bump_bps > 0 or eff_prev_max > 0:
                max_fee, prio_fee = compute_rbf_eip1559_fees(
                    prev_max_fee=eff_prev_max if eff_prev_max > 0 else max_fee,
                    prev_tip=eff_prev_tip if eff_prev_tip > 0 else prio_fee,
                    new_base=base_fee,
                    live_tip=prio_fee,
                    gas_bump_bps=max(1500, int(gas_bump_bps)),
                    max_fee_cap_wei=self.max_fee_cap_wei,
                )
            elif self.max_fee_cap_wei > 0 and max_fee > self.max_fee_cap_wei:
                max_fee = self.max_fee_cap_wei
                prio_fee = min(prio_fee, max(0, max_fee - base_fee))
            with self._nonce_lock:
                if (
                    addr_nonce_key not in self._sent_fees_by_addr_nonce
                    and len(self._sent_fees_by_addr_nonce) >= 256
                ):
                    self._sent_fees_by_addr_nonce.pop(next(iter(self._sent_fees_by_addr_nonce)))
                self._sent_fees_by_addr_nonce[addr_nonce_key] = (int(max_fee), int(prio_fee))
            return signer.sign_eip1559_transaction(
                nonce=nonce,
                max_priority_fee_per_gas=prio_fee,
                max_fee_per_gas=max_fee,
                gas_limit=gas_limit,
                to_addr=to_addr,
                value=value,
                data=data,
                chain_id=cid,
            )

        if gas_bump_bps > 0 or eff_prev_max > 0:
            base_gp = max(gp, eff_prev_max)
            eff_bps = max(1500, int(gas_bump_bps))
            gp = max(
                int(eff_prev_max * 115 // 100) + 1 if eff_prev_max > 0 else 0,
                ((base_gp * (10_000 + eff_bps) + 9_999) // 10_000) + 1,
            )
        if self.max_fee_cap_wei > 0 and gp > self.max_fee_cap_wei:
            raise RuntimeError(
                f"Legacy gas_price ({gp} wei) exceeds max_fee_gwei cap ({self.max_fee_cap_wei} wei)"
            )
        with self._nonce_lock:
            if (
                addr_nonce_key not in self._sent_fees_by_addr_nonce
                and len(self._sent_fees_by_addr_nonce) >= 256
            ):
                self._sent_fees_by_addr_nonce.pop(next(iter(self._sent_fees_by_addr_nonce)))
            self._sent_fees_by_addr_nonce[addr_nonce_key] = (int(gp), int(gp))
        return signer.sign_legacy_transaction(
            nonce=nonce,
            gas_price=gp,
            gas_limit=gas_limit,
            to_addr=to_addr,
            value=value,
            data=data,
            chain_id=cid,
        )

    def eth_call(
        self,
        to_addr: str,
        data_hex: str,
        from_addr: str = "",
        block_tag: str = "latest",
    ) -> str:
        call_obj: Dict[str, Any] = {"to": to_addr, "data": data_hex}
        if from_addr:
            call_obj["from"] = from_addr
        return str(self.rpc("eth_call", [call_obj, block_tag]))

    def get_logs(
        self,
        address: str,
        topics: Optional[List[Optional[str]]] = None,
        from_block: int | str = 0,
        to_block: int | str = "latest",
    ) -> List[Dict[str, Any]]:
        fb = hex(from_block) if isinstance(from_block, int) else from_block
        tb = hex(to_block) if isinstance(to_block, int) else to_block
        flt: Dict[str, Any] = {"address": address, "fromBlock": fb, "toBlock": tb}
        if topics is not None:
            flt["topics"] = topics
        res = self.rpc("eth_getLogs", [flt])
        return list(res) if res is not None else []

    def send_raw_transaction(self, raw_tx_hex: str) -> str:
        return str(self.rpc("eth_sendRawTransaction", [raw_tx_hex]))

    def wait_for_receipt(
        self,
        tx_hash: str,
        timeout: float = 120.0,
        require_success: bool = True,
    ) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        poll_idx = 0
        sleep_s = 0.02
        while True:
            rec = self.rpc("eth_getTransactionReceipt", [tx_hash])
            if rec is not None:
                status_hex = str(rec.get("status", "0x0"))
                if require_success and int(status_hex, 16) != 1:
                    raise RuntimeError(f"EVM transaction reverted: tx={tx_hash} receipt={rec}")
                return dict(rec)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for EVM tx receipt: {tx_hash}")
            time.sleep(sleep_s)
            poll_idx += 1
            if poll_idx >= 5:
                sleep_s = min(0.5, sleep_s * 1.5)

    def send_transaction(
        self,
        signer: EthWalletSigner,
        to_addr: str = "",
        data: bytes | str = b"",
        value: int = 0,
        gas_limit: int = 3_000_000,
        chain_id: Optional[int] = None,
        max_priority_fee_per_gas: Optional[int] = None,
        max_fee_per_gas: Optional[int] = None,
        nonce: Optional[int] = None,
        gas_bump_bps: int = 0,
        prev_max_fee_per_gas: Optional[int] = None,
        prev_priority_fee_per_gas: Optional[int] = None,
    ) -> str:
        with self.acquire_tx_lock():
            cid = chain_id if chain_id is not None else (self._cached_chain_id or self.chain_id())
            addr_key = signer.address.lower()
            explicit_nonce = nonce is not None
            if self.tx_lock_file and not explicit_nonce:
                with self._nonce_lock:
                    self._next_nonce_by_addr.pop(addr_key, None)
            if explicit_nonce:
                tx_nonce = int(nonce)
                if tx_nonce < 0:
                    raise ValueError(f"nonce must be >= 0, got {tx_nonce}")
            else:
                tx_nonce = self._allocate_nonce(signer.address)
            eff_bump_bps = max(0, int(gas_bump_bps))
            expected_tx_hash = ""
            with self._nonce_lock:
                prev_fee_entry = self._sent_fees_by_addr_nonce.get((addr_key, tx_nonce))

            def _record_explicit_nonce_sent(sent_nonce: int) -> None:
                if not explicit_nonce:
                    return
                with self._nonce_lock:
                    self._next_nonce_by_addr[addr_key] = max(
                        self._next_nonce_by_addr.get(addr_key, sent_nonce + 1),
                        sent_nonce + 1,
                    )

            def _restore_fee_entry(target_nonce: int) -> None:
                with self._nonce_lock:
                    if target_nonce == tx_nonce and prev_fee_entry is not None:
                        self._sent_fees_by_addr_nonce[(addr_key, target_nonce)] = prev_fee_entry
                    else:
                        self._sent_fees_by_addr_nonce.pop((addr_key, target_nonce), None)

            try:
                raw_tx = self._build_signed_tx(
                    signer=signer,
                    nonce=tx_nonce,
                    to_addr=to_addr,
                    data=data,
                    value=value,
                    gas_limit=gas_limit,
                    cid=cid,
                    max_priority_fee_per_gas=max_priority_fee_per_gas,
                    max_fee_per_gas=max_fee_per_gas,
                    gas_bump_bps=eff_bump_bps,
                    prev_max_fee_per_gas=prev_max_fee_per_gas,
                    prev_priority_fee_per_gas=prev_priority_fee_per_gas,
                )
                try:
                    raw_hex = raw_tx[2:] if raw_tx.startswith(("0x", "0X")) else raw_tx
                    if raw_hex:
                        expected_tx_hash = "0x" + keccak256(bytes.fromhex(raw_hex)).hex()
                except ValueError:
                    expected_tx_hash = ""
                res_hash = self.send_raw_transaction(raw_tx)
                _record_explicit_nonce_sent(tx_nonce)
                return res_hash
            except Exception as exc:
                err_lc = str(exc).lower()
                if expected_tx_hash and any(
                    tok in err_lc for tok in ("already known", "known transaction")
                ):
                    _record_explicit_nonce_sent(tx_nonce)
                    return expected_tx_hash
                if self._is_nonce_error(exc):
                    if explicit_nonce and eff_bump_bps > 0 and any(
                        tok in err_lc for tok in ("replacement", "underpriced")
                    ):
                        retry_nonce = tx_nonce
                        retry_bump_bps = max(2000, eff_bump_bps + 2000)
                    elif explicit_nonce:
                        _restore_fee_entry(tx_nonce)
                        raise
                    else:
                        retry_nonce = self._resync_nonce_after_error(
                            signer.address, tx_nonce, err_lc
                        )
                        if retry_nonce == tx_nonce:
                            self.clear_sent_fee_cache(signer.address, tx_nonce)
                        retry_bump_bps = eff_bump_bps
                    retry_expected_hash = ""
                    try:
                        raw_tx = self._build_signed_tx(
                            signer=signer,
                            nonce=retry_nonce,
                            to_addr=to_addr,
                            data=data,
                            value=value,
                            gas_limit=gas_limit,
                            cid=cid,
                            max_priority_fee_per_gas=max_priority_fee_per_gas,
                            max_fee_per_gas=max_fee_per_gas,
                            gas_bump_bps=retry_bump_bps,
                        )
                        try:
                            raw_hex = raw_tx[2:] if raw_tx.startswith(("0x", "0X")) else raw_tx
                            if raw_hex:
                                retry_expected_hash = "0x" + keccak256(bytes.fromhex(raw_hex)).hex()
                        except ValueError:
                            retry_expected_hash = ""
                        retry_hash = self.send_raw_transaction(raw_tx)
                        _record_explicit_nonce_sent(retry_nonce)
                        return retry_hash
                    except Exception as retry_exc:
                        retry_lc = str(retry_exc).lower()
                        if retry_expected_hash and any(
                            tok in retry_lc for tok in ("already known", "known transaction")
                        ):
                            _record_explicit_nonce_sent(retry_nonce)
                            return retry_expected_hash
                        _restore_fee_entry(retry_nonce)
                        if not explicit_nonce:
                            with self._nonce_lock:
                                self._next_nonce_by_addr.pop(addr_key, None)
                        raise
                _restore_fee_entry(tx_nonce)
                if not explicit_nonce:
                    with self._nonce_lock:
                        self._next_nonce_by_addr.pop(addr_key, None)
                raise

    def send_and_confirm(
        self,
        signer: EthWalletSigner,
        to_addr: str,
        data: bytes | str = b"",
        value: int = 0,
        gas_limit: int = 3_000_000,
        chain_id: Optional[int] = None,
        require_success: bool = True,
        timeout: float = 120.0,
    ) -> Dict[str, Any]:
        try:
            tx_hash = self.send_transaction(
                signer=signer,
                to_addr=to_addr,
                data=data,
                value=value,
                gas_limit=gas_limit,
                chain_id=chain_id,
            )
            return self.wait_for_receipt(tx_hash, timeout=timeout, require_success=require_success)
        except Exception:
            with self._nonce_lock:
                self._next_nonce_by_addr.pop(signer.address.lower(), None)
            raise

    def deploy_contract(
        self,
        signer: EthWalletSigner,
        init_bytecode: bytes | str,
        constructor_args_abi: bytes = b"",
        gas_limit: int = 8_000_000,
        chain_id: Optional[int] = None,
        timeout: float = 120.0,
    ) -> tuple[str, Dict[str, Any]]:
        if isinstance(init_bytecode, str):
            clean = init_bytecode[2:] if init_bytecode.startswith(("0x", "0X")) else init_bytecode
            code_bytes = bytes.fromhex(clean)
        else:
            code_bytes = bytes(init_bytecode)
        rec = self.send_and_confirm(
            signer=signer,
            to_addr="",
            data=code_bytes + constructor_args_abi,
            value=0,
            gas_limit=gas_limit,
            chain_id=chain_id,
            require_success=True,
            timeout=timeout,
        )
        caddr = str(rec.get("contractAddress", ""))
        if not caddr:
            raise RuntimeError(f"Contract deployment missing contractAddress: {rec}")
        clean_addr = caddr[2:] if caddr.startswith(("0x", "0X")) else caddr
        return format_eip55_address(bytes.fromhex(clean_addr)), rec


_HMAC_TS_LOCK = threading.Lock()
_LAST_HMAC_TS_MS = 0
_LAST_HMAC_TS_BY_REQ: Dict[tuple[str, str, str, str], int] = {}
_HMAC_NONCE_SEQ = 0


def _next_hmac_timestamp_and_nonce(
    api_key: str = "",
    method: str = "",
    path_and_query: str = "",
    body_str: str = "",
) -> tuple[int, str]:
    global _LAST_HMAC_TS_MS, _HMAC_NONCE_SEQ
    with _HMAC_TS_LOCK:
        now_ms = time.time_ns() // 1_000_000
        if api_key or method or path_and_query or body_str:
            body_key = (
                hashlib.sha256(body_str.encode("utf-8")).hexdigest()
                if len(body_str) > 128
                else body_str
            )
            req_key = (api_key, method, path_and_query, body_key)
            prev_ts = _LAST_HMAC_TS_BY_REQ.get(req_key, 0)
            if now_ms <= prev_ts:
                deadline = time.monotonic() + 0.002
                while now_ms <= prev_ts and time.monotonic() < deadline:
                    time.sleep(0)
                    now_ms = time.time_ns() // 1_000_000
                if now_ms <= prev_ts:
                    now_ms = prev_ts + 1
            _LAST_HMAC_TS_BY_REQ[req_key] = now_ms
            if len(_LAST_HMAC_TS_BY_REQ) > 2048:
                cutoff = now_ms - 60_000
                stale = [k for k, v in _LAST_HMAC_TS_BY_REQ.items() if v < cutoff]
                for k in stale:
                    _LAST_HMAC_TS_BY_REQ.pop(k, None)
                if len(_LAST_HMAC_TS_BY_REQ) > 2048:
                    _LAST_HMAC_TS_BY_REQ.clear()
                    _LAST_HMAC_TS_BY_REQ[req_key] = now_ms
        else:
            if now_ms <= _LAST_HMAC_TS_MS:
                deadline = time.monotonic() + 0.002
                while now_ms <= _LAST_HMAC_TS_MS and time.monotonic() < deadline:
                    time.sleep(0)
                    now_ms = time.time_ns() // 1_000_000
                if now_ms <= _LAST_HMAC_TS_MS:
                    now_ms = _LAST_HMAC_TS_MS + 1
            _LAST_HMAC_TS_MS = now_ms
        _HMAC_NONCE_SEQ += 1
        seq = _HMAC_NONCE_SEQ
    return now_ms, f"{now_ms}_{seq}"


def _build_hmac_auth_headers(
    api_key: str,
    api_secret: str,
    method: str,
    path_and_query: str,
    body_str: str = "",
) -> Dict[str, str]:
    now_ms, nonce = _next_hmac_timestamp_and_nonce(api_key, method, path_and_query, body_str)
    ts_ms = str(now_ms)
    sig = compute_hmac_signature(api_secret, ts_ms, method, path_and_query, body_str)
    return {
        "X-Arena-API-Key": api_key,
        "X-Arena-Timestamp": ts_ms,
        "X-Arena-Nonce": nonce,
        "X-Arena-Signature": sig,
    }


def compute_hmac_signature(
    api_secret: str,
    timestamp_ms: int | str,
    method: str,
    path_and_query: str,
    body: str = "",
) -> str:
    canonical = f"{timestamp_ms}\n{method}\n{path_and_query}\n{body}"
    return hmac.new(
        api_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()


KNOWN_PUBLIC_RPC_BY_CHAIN_ID: Dict[int, str] = {
    84532: "https://sepolia.base.org",
    8453: "https://mainnet.base.org",
    421614: "https://sepolia-rollup.arbitrum.io/rpc",
    42161: "https://arb1.arbitrum.io/rpc",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
    1: "https://ethereum-rpc.publicnode.com",
}

_ERC20_DECIMALS_SELECTOR = keccak256(b"decimals()")[:4]
_ERC20_BALANCE_OF_SELECTOR = keccak256(b"balanceOf(address)")[:4]
_ERC20_ALLOWANCE_SELECTOR = keccak256(b"allowance(address,address)")[:4]
_ERC20_APPROVE_SELECTOR = keccak256(b"approve(address,uint256)")[:4]
_DEPOSIT_TRADER_MARGIN_SELECTOR = keccak256(b"depositTraderMargin(uint32,uint16,uint256)")[:4]
_DEPOSIT_TRADER_MARGIN_ALIGNED_SELECTOR = keccak256(b"depositTraderMarginAligned(uint32,uint16,uint256)")[:4]
_CLAIM_WITHDRAWAL_VOUCHER_SELECTOR = keccak256(
    b"claimWithdrawalVoucher(uint64,uint64,uint32,uint16,uint64,address,bytes32,bytes)"
)[:4]


def _sdk_abi_hex_bytes(h: str) -> bytes:
    clean = str(h).strip()
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]
    return bytes.fromhex(clean) if clean else b""


def _sdk_abi_uint256(v: int) -> bytes:
    iv = int(v)
    if iv < 0 or iv >= (1 << 256):
        raise ValueError(f"uint256 out of range: {v}")
    return iv.to_bytes(32, "big")


def _sdk_abi_address(addr: str) -> bytes:
    raw = _sdk_abi_hex_bytes(addr)
    if len(raw) != 20:
        raise ValueError(f"Expected 20-byte Ethereum address, got {len(raw)} bytes: {addr!r}")
    return (b"\x00" * 12) + raw


def _sdk_abi_bytes32(h: str) -> bytes:
    raw = _sdk_abi_hex_bytes(h)
    if len(raw) != 32:
        raise ValueError(f"Expected 32-byte hex value, got {len(raw)} bytes")
    return raw


def _sdk_abi_bytes(payload: bytes) -> bytes:
    pad_len = (32 - (len(payload) % 32)) % 32
    return _sdk_abi_uint256(len(payload)) + payload + (b"\x00" * pad_len)


def encode_erc20_decimals_calldata() -> str:
    return "0x" + _ERC20_DECIMALS_SELECTOR.hex()


def encode_erc20_balance_of_calldata(account: str) -> str:
    return "0x" + (_ERC20_BALANCE_OF_SELECTOR + _sdk_abi_address(account)).hex()


def encode_erc20_allowance_calldata(owner: str, spender: str) -> str:
    return "0x" + (_ERC20_ALLOWANCE_SELECTOR + _sdk_abi_address(owner) + _sdk_abi_address(spender)).hex()


def encode_erc20_approve_calldata(spender: str, raw_amount: int) -> str:
    return "0x" + (_ERC20_APPROVE_SELECTOR + _sdk_abi_address(spender) + _sdk_abi_uint256(raw_amount)).hex()


def encode_deposit_trader_margin_calldata(account_id: int, asset_id: int, raw_amount: int) -> str:
    if not (1 <= int(account_id) <= 0xFFFF_FFFF):
        raise ValueError(f"account_id {account_id} out of uint32 [1, 4294967295]")
    if not (0 <= int(asset_id) <= 0xFFFF):
        raise ValueError(f"asset_id {asset_id} out of uint16 [0, 65535]")
    if int(raw_amount) <= 0:
        raise ValueError(f"raw_amount must be > 0, got {raw_amount}")
    body = (
        _sdk_abi_uint256(int(account_id))
        + _sdk_abi_uint256(int(asset_id))
        + _sdk_abi_uint256(int(raw_amount))
    )
    return "0x" + (_DEPOSIT_TRADER_MARGIN_SELECTOR + body).hex()


def encode_deposit_trader_margin_aligned_calldata(
    account_id: int, asset_id: int, max_raw_amount: int
) -> str:
    if not (1 <= int(account_id) <= 0xFFFF_FFFF):
        raise ValueError(f"account_id {account_id} out of uint32 [1, 4294967295]")
    if not (0 <= int(asset_id) <= 0xFFFF):
        raise ValueError(f"asset_id {asset_id} out of uint16 [0, 65535]")
    if int(max_raw_amount) <= 0:
        raise ValueError(f"max_raw_amount must be > 0, got {max_raw_amount}")
    body = (
        _sdk_abi_uint256(int(account_id))
        + _sdk_abi_uint256(int(asset_id))
        + _sdk_abi_uint256(int(max_raw_amount))
    )
    return "0x" + (_DEPOSIT_TRADER_MARGIN_ALIGNED_SELECTOR + body).hex()


def encode_claim_withdrawal_voucher_calldata(voucher: Dict[str, Any]) -> str:
    sig_bytes = _sdk_abi_hex_bytes(str(voucher["operator_signature"]))
    if len(sig_bytes) != 65:
        raise ValueError(f"Expected 65-byte operator_signature, got {len(sig_bytes)}")
    amt_u64 = int(voucher["amount"]) & 0xFFFF_FFFF_FFFF_FFFF
    head = (
        _sdk_abi_uint256(int(voucher["withdrawal_id"]))
        + _sdk_abi_uint256(int(voucher["wal_seq"]))
        + _sdk_abi_uint256(int(voucher["account_id"]))
        + _sdk_abi_uint256(int(voucher["asset_id"]))
        + _sdk_abi_uint256(amt_u64)
        + _sdk_abi_address(str(voucher["recipient_eth_address"]))
        + _sdk_abi_bytes32(str(voucher["state_root"]))
        + _sdk_abi_uint256(8 * 32)
    )
    tail = _sdk_abi_bytes(sig_bytes)
    return "0x" + (_CLAIM_WITHDRAWAL_VOUCHER_SELECTOR + head + tail).hex()


class ArenaHttpClient:
    """HTTP/1.1 JSON REST, Wallet Auth, Settlement & Market-Data client."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        timeout: float = 5.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.timeout = max(0.1, float(timeout))
        self._ssl_context = ssl_context
        self._creds_path: Optional[Path] = None
        self._creds_role: str = "operator"
        self._creds_fallback_role: Optional[str] = None
        self._creds_mtime_ns: Optional[int] = None
        self._http_pool = _KeepAliveHttpPool(ssl_context=ssl_context)

    def close(self) -> None:
        self._http_pool.close()

    def set_credentials(self, api_key: Optional[str], api_secret: Optional[str]) -> None:
        self.api_key = api_key
        self.api_secret = api_secret
        self._creds_path = None
        self._creds_mtime_ns = None

    def set_creds_file(
        self,
        creds_path: str | Path,
        role: str = "operator",
        fallback_role: Optional[str] = None,
    ) -> bool:
        self._creds_path = Path(creds_path)
        self._creds_role = str(role)
        self._creds_fallback_role = str(fallback_role) if fallback_role else None
        self._creds_mtime_ns = None
        return self._reload_creds_file(force=True, raise_on_error=True)

    def _reload_creds_file(self, force: bool = False, raise_on_error: bool = False) -> bool:
        if self._creds_path is None:
            return False
        try:
            st = self._creds_path.stat()
            if not force and self._creds_mtime_ns is not None and st.st_mtime_ns == self._creds_mtime_ns:
                return False
            data = json.loads(self._creds_path.read_text(encoding="utf-8"))
            if self._creds_role in data and isinstance(data[self._creds_role], dict):
                sec = data[self._creds_role]
            elif (
                self._creds_fallback_role
                and self._creds_fallback_role in data
                and isinstance(data[self._creds_fallback_role], dict)
            ):
                sec = data[self._creds_fallback_role]
            elif "api_key" in data and "api_secret" in data:
                sec = data
            else:
                sec = data[self._creds_role]
            new_key = str(sec["api_key"])
            new_sec = str(sec["api_secret"])
        except Exception:
            if raise_on_error:
                raise
            return False
        changed = (new_key != self.api_key) or (new_sec != self.api_secret)
        self.api_key = new_key
        self.api_secret = new_sec
        self._creds_mtime_ns = st.st_mtime_ns
        return changed

    @classmethod
    def from_creds_file(
        cls,
        base_url: str,
        creds_path: str | Path,
        role: str = "operator",
        timeout: float = 5.0,
        fallback_role: Optional[str] = None,
    ) -> "ArenaHttpClient":
        cli = cls(base_url=base_url, timeout=timeout)
        cli.set_creds_file(creds_path, role=role, fallback_role=fallback_role)
        return cli

    @classmethod
    def testnet(
        cls,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        timeout: float = 10.0,
        ssl_context: Optional[ssl.SSLContext] = None,
        base_url: str = PUBLIC_TESTNET_URL,
    ) -> "ArenaHttpClient":
        """Connect in 1 line to the live public Base Sepolia testnet (`https://testnet.feraterra.app`)."""
        return cls(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            timeout=timeout,
            ssl_context=ssl_context,
        )

    @property
    def ws_url(self) -> str:
        return http_url_to_ws_url(self.base_url)

    def _auth_headers(self, method: str, path_and_query: str, body_str: str = "") -> Dict[str, str]:
        if not self.api_key or not self.api_secret:
            return {}
        return _build_hmac_auth_headers(self.api_key, self.api_secret, method, path_and_query, body_str)

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        _retried_401: bool = False,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        self._reload_creds_file(force=False)
        eff_timeout = self.timeout if timeout is None else max(0.1, float(timeout))
        pq = path
        if params:
            pq += "?" + urllib.parse.urlencode(params)
        url = f"{self.base_url}{pq}"
        try:
            status_code, raw_bytes = self._http_pool.request(
                "GET",
                url,
                None,
                self._auth_headers("GET", pq, ""),
                eff_timeout,
                _MAX_SDK_HTTP_RESPONSE_BYTES,
            )
            if len(raw_bytes) > _MAX_SDK_HTTP_RESPONSE_BYTES:
                return {"ok": False, "error": "http_response_too_large"}
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            try:
                parsed_ok = json.loads(raw_text)
            except json.JSONDecodeError:
                return {
                    "ok": False,
                    "http_status": status_code,
                    "error": "invalid_json_response",
                    "raw_body": raw_text,
                }
            return parsed_ok if isinstance(parsed_ok, dict) else {"ok": False, "error": "invalid_json_root"}
        except urllib.error.HTTPError as exc:
            body = exc.read(_MAX_SDK_HTTP_RESPONSE_BYTES).decode("utf-8", errors="replace")
            if exc.code == 401 and not _retried_401 and self._reload_creds_file(force=True):
                return self._get(path, params=params, _retried_401=True, timeout=timeout)
            if body:
                try:
                    loaded = json.loads(body)
                    parsed: Dict[str, Any] = loaded if isinstance(loaded, dict) else {"ok": False, "raw_body": body}
                except json.JSONDecodeError:
                    parsed = {"ok": False, "error": "invalid_json_response", "raw_body": body}
            else:
                parsed = {"ok": False}
            parsed.setdefault("http_status", exc.code)
            return parsed

    def _post(
        self,
        path: str,
        payload: Dict[str, Any],
        _retried_401: bool = False,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        self._reload_creds_file(force=False)
        eff_timeout = self.timeout if timeout is None else max(0.1, float(timeout))
        url = f"{self.base_url}{path}"
        body_str = json.dumps(payload, separators=(",", ":"))
        raw = body_str.encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_headers("POST", path, body_str))
        try:
            status_code, raw_bytes = self._http_pool.request(
                "POST",
                url,
                raw,
                headers,
                eff_timeout,
                _MAX_SDK_HTTP_RESPONSE_BYTES,
            )
            if len(raw_bytes) > _MAX_SDK_HTTP_RESPONSE_BYTES:
                return {"ok": False, "error": "http_response_too_large"}
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            try:
                parsed_ok = json.loads(raw_text)
            except json.JSONDecodeError:
                return {
                    "ok": False,
                    "http_status": status_code,
                    "error": "invalid_json_response",
                    "raw_body": raw_text,
                }
            return parsed_ok if isinstance(parsed_ok, dict) else {"ok": False, "error": "invalid_json_root"}
        except urllib.error.HTTPError as exc:
            body = exc.read(_MAX_SDK_HTTP_RESPONSE_BYTES).decode("utf-8", errors="replace")
            if exc.code == 401 and not _retried_401 and self._reload_creds_file(force=True):
                return self._post(path, payload, _retried_401=True, timeout=timeout)
            if body:
                try:
                    loaded = json.loads(body)
                    parsed = loaded if isinstance(loaded, dict) else {"ok": False, "raw_body": body}
                except json.JSONDecodeError:
                    parsed = {"ok": False, "error": "invalid_json_response", "raw_body": body}
            else:
                parsed = {"ok": False}
            parsed.setdefault("http_status", exc.code)
            return parsed

    def auth_challenge(self, eth_address: str) -> Dict[str, Any]:
        return self._post("/auth/challenge", {"eth_address": eth_address})

    def auth_wallet(self, eth_address: str, signature: str, nonce: str = "") -> Dict[str, Any]:
        payload: Dict[str, Any] = {"eth_address": eth_address, "signature": signature}
        if nonce:
            payload["nonce"] = str(nonce)
        return self._post("/auth/wallet", payload)

    def login_with_wallet(self, signer: EthWalletSigner) -> Dict[str, Any]:
        ch = self.auth_challenge(signer.address)
        if not ch.get("ok"):
            return ch
        sig = signer.personal_sign(str(ch["message"]))
        res = self.auth_wallet(signer.address, sig, nonce=str(ch.get("nonce") or ""))
        if res.get("ok"):
            self.set_credentials(str(res["api_key"]), str(res["api_secret"]))
        return res

    def create_session(self, account_id: int = 0) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"account_id": account_id} if account_id > 0 else {}
        res = self._post("/auth/session", payload)
        if res.get("ok"):
            self.set_credentials(str(res["api_key"]), str(res["api_secret"]))
        return res

    def create_service_key(self, role: str) -> Dict[str, Any]:
        return self._post("/auth/create_service_key", {"role": str(role)})

    def withdrawals(
        self, account_id: int = 0, limit: int = 0, offset: int = 0
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if account_id > 0:
            params["account_id"] = int(account_id)
        if limit > 0:
            params["limit"] = int(limit)
        if offset > 0:
            params["offset"] = int(offset)
        return self._get("/withdrawals", params or None)

    def settlement_config(self) -> Dict[str, Any]:
        return self._get("/settlement/config")

    def settlement_status(self) -> Dict[str, Any]:
        res = self._get("/settlement/status")
        if int(res.get("http_status", 200)) == 404 and not res.get("ok"):
            return self._get("/settlement/config")
        return res

    def set_settlement_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/settlement/config", config)

    def settlement_batch(
        self, freeze: bool = False, settlement_nonce: Optional[int] = None
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if freeze:
            params["freeze"] = 1
        if settlement_nonce is not None:
            params["settlement_nonce"] = int(settlement_nonce)
        return self._get("/settlement/batch", params or None)

    def sign_settlement_heartbeat(
        self,
        settlement_nonce: int,
        batch_seq_id: Optional[int] = None,
        state_root: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"settlement_nonce": int(settlement_nonce)}
        if batch_seq_id is not None:
            body["batch_seq_id"] = int(batch_seq_id)
        if state_root is not None:
            body["state_root"] = str(state_root)
        return self._post("/settlement/sign_heartbeat", body)

    def sign_settlement_bind_wallet(
        self,
        account_id: int,
        wallet: str,
        settlement_nonce: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/settlement/sign_bind_wallet",
            {
                "account_id": int(account_id),
                "wallet": str(wallet),
                "settlement_nonce": int(settlement_nonce),
            },
        )

    def sign_settlement_rebalance_vault(
        self,
        vault: str,
        deploy_raw: int,
        withdraw_raw: int,
        settlement_nonce: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/settlement/sign_rebalance_vault",
            {
                "vault": str(vault),
                "deploy_raw": str(int(deploy_raw)),
                "withdraw_raw": str(int(withdraw_raw)),
                "settlement_nonce": int(settlement_nonce),
            },
        )

    def sign_settlement_harvest_yield(
        self,
        vault: str,
        max_yield_raw: int,
        protocol_recipient: str,
        protocol_spread_bps: int,
        admin_nonce: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/settlement/sign_harvest_yield",
            {
                "vault": str(vault),
                "max_yield_raw": str(int(max_yield_raw)),
                "protocol_recipient": str(protocol_recipient),
                "protocol_spread_bps": int(protocol_spread_bps),
                "admin_nonce": int(admin_nonce),
            },
        )

    def process_forced_withdrawal(
        self,
        request_id: int,
        account_id: int,
        asset_id: int,
        exchange_units: int,
        requester_eth_address: str,
        event_ref: str = "",
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "request_id": int(request_id),
            "account_id": int(account_id),
            "asset_id": int(asset_id),
            "exchange_units": int(exchange_units),
            "requester_eth_address": str(requester_eth_address),
        }
        if event_ref:
            body["event_ref"] = str(event_ref)
        return self._post("/settlement/forced_withdrawal", body)

    def settlement_escape_proof(
        self, account_id: int, asset_id: int = 0, pending: bool = False
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "account_id": int(account_id),
            "asset_id": int(asset_id),
        }
        if pending:
            params["pending"] = 1
        return self._get("/settlement/escape_proof", params)

    escape_proof = settlement_escape_proof

    def commit_settlement_batch(
        self,
        batch_seq_id: int,
        to_wal_seq: Optional[int] = None,
        new_state_root: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"batch_seq_id": int(batch_seq_id)}
        if to_wal_seq is not None:
            body["to_wal_seq"] = int(to_wal_seq)
        if new_state_root is not None:
            body["new_state_root"] = str(new_state_root)
        return self._post("/settlement/commit", body)

    settlement_commit = commit_settlement_batch

    def rotate_operator_key(self, new_operator_privkey_hex: str) -> Dict[str, Any]:
        return self._post(
            "/auth/rotate_operator_key",
            {"new_operator_privkey_hex": str(new_operator_privkey_hex)},
        )

    def revoke_api_key(self, api_key: str = "") -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if api_key:
            body["api_key"] = str(api_key)
        elif self.api_key:
            body["api_key"] = str(self.api_key)
        return self._post("/auth/revoke_key", body)

    def refund_voided_withdrawal(
        self,
        withdrawal_id: int,
        account_id: int = 0,
        asset_id: Optional[int] = None,
        amount: int = 0,
        tx_hash: str = "",
        deposit_seq: int = 0,
        event_ref: str = "",
    ) -> Dict[str, Any]:
        wid_i = int(withdrawal_id)
        if wid_i <= 0:
            raise ValueError("withdrawal_id must be > 0")
        acct_i = int(account_id)
        if acct_i < 0 or acct_i > 0xFFFFFFFF:
            raise ValueError("account_id must be in [0, 2^32 - 1]")
        amt_i = int(amount)
        if amt_i < 0:
            raise ValueError("amount must be >= 0")
        dep_seq_i = int(deposit_seq)
        if dep_seq_i < 0:
            raise ValueError("deposit_seq must be >= 0")
        body: Dict[str, Any] = {"withdrawal_id": wid_i}
        if acct_i > 0:
            body["account_id"] = acct_i
        if asset_id is not None:
            aid_i = int(asset_id)
            if not (0 <= aid_i <= 255):
                raise ValueError("asset_id must be in [0, 255]")
            body["asset_id"] = aid_i
        if amt_i > 0:
            body["amount"] = amt_i
        if dep_seq_i > 0:
            body["deposit_seq"] = dep_seq_i
        if tx_hash:
            body["tx_hash"] = str(tx_hash)
        if event_ref:
            body["event_ref"] = str(event_ref)
        return self._post("/withdraw/refund_voided", body)

    def credit_onchain_insurance(
        self,
        amount: Optional[int] = None,
        funder: str = "",
        event_ref: str = "",
        *,
        amount_micro: Optional[int] = None,
    ) -> Dict[str, Any]:
        eff_amt = amount_micro if amount is None else amount
        if eff_amt is None:
            raise ValueError("credit_onchain_insurance requires amount or amount_micro")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        body: Dict[str, Any] = {"amount": amt_i}
        if funder:
            body["funder"] = str(funder)
        if event_ref:
            body["event_ref"] = str(event_ref)
        return self._post("/insurance/credit_onchain", body)

    def absorb_onchain_custody_loss(
        self,
        amount: Optional[int] = None,
        pool: str = "trader_margin",
        event_ref: str = "",
        *,
        amount_micro: Optional[int] = None,
    ) -> Dict[str, Any]:
        eff_amt = amount_micro if amount is None else amount
        if eff_amt is None:
            raise ValueError("absorb_onchain_custody_loss requires amount or amount_micro")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        pool_s = str(pool) if str(pool) else "trader_margin"
        if pool_s not in ("trader_margin", "insurance"):
            raise ValueError("pool must be 'trader_margin' or 'insurance'")
        body: Dict[str, Any] = {"amount": amt_i, "pool": pool_s}
        if event_ref:
            body["event_ref"] = str(event_ref)
        return self._post("/custody/absorb_loss", body)

    def recover_custody_loss(
        self,
        amount_micro: Optional[int] = None,
        event_ref: str = "",
        *,
        amount: Optional[int] = None,
    ) -> Dict[str, Any]:
        eff_amt = amount if amount_micro is None else amount_micro
        if eff_amt is None:
            raise ValueError("recover_custody_loss requires amount_micro or amount")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        body: Dict[str, Any] = {"amount": amt_i}
        if event_ref:
            body["event_ref"] = str(event_ref)
        return self._post("/custody/recover_loss", body)

    recover_onchain_custody_loss = recover_custody_loss

    def register_spot_asset(
        self,
        asset_id: int,
        symbol: str,
        decimals: int = 18,
        lot_decimals: int = 4,
        max_supply_lots: int = 0,
    ) -> Dict[str, Any]:
        aid_i = int(asset_id)
        max_sup_i = int(max_supply_lots)
        if not (1 <= aid_i <= 255):
            raise ValueError("asset_id must be in [1, 255]")
        if not (0 <= max_sup_i <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("max_supply_lots must be in [0, 2^64 - 1]")
        return self._post(
            "/markets/register_spot_asset",
            {
                "asset_id": aid_i,
                "symbol": str(symbol),
                "decimals": int(decimals),
                "lot_decimals": int(lot_decimals),
                "max_supply_lots": max_sup_i,
            },
        )

    def health(self) -> Dict[str, Any]:
        return self._get("/health")

    def protocol_info(self) -> Dict[str, Any]:
        return self._get("/")

    def ledger_tip(self) -> Dict[str, Any]:
        return self._get("/ledger/tip")

    def execute_spread(
        self,
        account_id: int,
        leg1_market_id: int,
        leg1_side: str,
        leg1_price_ticks: int,
        leg1_qty_lots: int,
        leg2_market_id: int,
        leg2_side: str,
        leg2_price_ticks: int,
        leg2_qty_lots: int,
        leg1_reduce_only: bool = False,
        leg1_is_market: bool = False,
        leg2_reduce_only: bool = False,
        leg2_is_market: bool = False,
        stp: str = "cancel_resting",
        margin_spot: bool = False,
        express_surplus_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "leg1_market_id": leg1_market_id,
            "leg1_side": leg1_side,
            "leg1_price_ticks": leg1_price_ticks,
            "leg1_qty_lots": leg1_qty_lots,
            "leg1_reduce_only": leg1_reduce_only,
            "leg1_is_market": leg1_is_market,
            "leg2_market_id": leg2_market_id,
            "leg2_side": leg2_side,
            "leg2_price_ticks": leg2_price_ticks,
            "leg2_qty_lots": leg2_qty_lots,
            "leg2_reduce_only": leg2_reduce_only,
            "leg2_is_market": leg2_is_market,
            "stp": stp,
        }
        if margin_spot:
            payload["margin_spot"] = True
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        return self._post("/spread", payload)

    def execute_basket(
        self,
        account_id: int,
        legs: List[Dict[str, Any]],
        stp: str = "cancel_resting",
        margin_spot: bool = False,
        client_tag: int = 0,
        express_surplus_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "legs": legs,
            "stp": stp,
        }
        if margin_spot:
            payload["margin_spot"] = True
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        return self._post("/basket", payload)

    basket = execute_basket

    def distribute_yield(self, reward_usd_micro: int, sponsor_account_id: int = 0) -> Dict[str, Any]:
        return self._post(
            "/yield/distribute",
            {"reward_usd_micro": reward_usd_micro, "sponsor_account_id": sponsor_account_id},
        )

    def get_protocol_config(self) -> Dict[str, Any]:
        return self._get("/protocol/config")

    def set_protocol_account(self, protocol_fee_account_id: int) -> Dict[str, Any]:
        return self._post("/protocol/config", {"protocol_fee_account_id": int(protocol_fee_account_id)})

    set_protocol_config = set_protocol_account

    def resolve_claim(self, market_id: int, payout_ticks: int) -> Dict[str, Any]:
        return self._post("/claim/resolve", {"market_id": market_id, "payout_ticks": payout_ticks})

    def create_market(
        self,
        account_id: int,
        symbol: str,
        kind: str = "spot",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        opts = dict(kwargs)
        eff_aid = opts.pop("creator_account_id", account_id)
        payload: Dict[str, Any] = {
            "account_id": eff_aid,
            "symbol": symbol,
            "kind": kind,
        }
        payload.update(opts)
        return self._post("/markets/create", payload)

    def mint_redeem(
        self,
        account_id: int,
        market_id: int,
        side: str,
        qty_lots: int,
        limit_cost_or_payout_micro: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/mint_redeem",
            {
                "account_id": account_id,
                "market_id": market_id,
                "side": side,
                "qty_lots": qty_lots,
                "limit_cost_or_payout_micro": limit_cost_or_payout_micro,
            },
        )

    def flash_arbitrage(
        self,
        account_id: int,
        market_id: int,
        side: str,
        qty_lots: int,
        limit_price_ticks: int = 0,
        min_profit_micro: int = 0,
        is_market: bool = False,
        stp: str = "cancel_resting",
        express_surplus_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "qty_lots": qty_lots,
            "limit_price_ticks": limit_price_ticks,
            "min_profit_micro": min_profit_micro,
            "is_market": is_market,
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        return self._post("/flash_arb", payload)

    def markets(self) -> Dict[str, Any]:
        return self._get("/markets")

    def ticker(self, market_id: int = 0) -> Dict[str, Any]:
        params = {"market_id": market_id} if market_id > 0 else None
        return self._get("/ticker", params)

    def candles(self, market_id: int = 1, interval: str = "tick", limit: int = 120) -> Dict[str, Any]:
        return self._get("/candles", {"market_id": market_id, "interval": interval, "limit": limit})

    def book(self, market_id: int = 1, depth: int = 20, include_l3: bool = True) -> Dict[str, Any]:
        _ = include_l3
        return self._get("/book", {"market_id": market_id, "depth": depth})

    def trades(self, market_id: int = 1, limit: int = 50) -> Dict[str, Any]:
        return self._get("/trades", {"market_id": market_id, "limit": limit})

    def get_leaderboard(
        self,
        limit: int = 50,
        sort: str = "equity",
        *,
        sort_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        lim_i = int(limit)
        if lim_i < 1:
            raise ValueError(f"limit must be >= 1, got {limit!r}")
        params: Dict[str, Any] = {"limit": lim_i}
        eff_sort = str(sort_by if sort_by is not None else sort).strip().lower()
        if eff_sort:
            params["sort"] = eff_sort
        return self._get("/leaderboard", params)

    leaderboard = get_leaderboard

    def account(self, account_id: int) -> Dict[str, Any]:
        return self._get("/account", {"account_id": account_id})

    def deposit(
        self,
        account_id: int = 0,
        amount: int = 0,
        asset_id: int = 0,
        eth_address: str = "",
        deposit_ref: str = "",
        deposit_seq: int = 0,
        yield_float: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"account_id": account_id, "asset_id": asset_id, "amount": amount}
        if eth_address:
            payload["eth_address"] = eth_address
        if deposit_ref:
            payload["deposit_ref"] = deposit_ref
        if deposit_seq > 0:
            payload["deposit_seq"] = int(deposit_seq)
        if yield_float:
            payload["yield_float"] = True
        return self._post("/deposit", payload)

    def place_order(
        self,
        account_id: int,
        market_id: int,
        side: str,
        price_ticks: int,
        qty_lots: int,
        tif: str = "gtc",
        reduce_only: bool = False,
        is_market: bool = False,
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        client_tag: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp: str = "cancel_resting",
        stp_decrement_and_cancel: bool = False,
        priority_fee_ppm: int = 0,
    ) -> Dict[str, Any]:
        prio_ppm_i = _validate_priority_fee_ppm(priority_fee_ppm)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "tif": tif,
            "stp": stp,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
            "reduce_only": reduce_only,
            "is_market": is_market,
        }
        if stp_decrement_and_cancel:
            payload["stp_decrement_and_cancel"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if primary_peg:
            payload["primary_peg"] = True
        if midpoint_peg:
            payload["midpoint_peg"] = True
        if mark_peg:
            payload["mark_peg"] = True
        if trailing_peg:
            payload["trailing_peg"] = True
        if dark_midpoint:
            payload["dark_midpoint"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if min_qty_lots > 0:
            payload["min_qty_lots"] = min_qty_lots
        if display_qty_lots > 0:
            payload["display_qty_lots"] = display_qty_lots
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if prio_ppm_i > 0:
            payload["priority_fee_ppm"] = prio_ppm_i
        return self._post("/order", payload)

    submit_order = place_order

    def preview_order(
        self,
        account_id: int,
        market_id: int,
        side: str,
        price_ticks: int,
        qty_lots: int,
        tif: str = "gtc",
        reduce_only: bool = False,
        is_market: bool = False,
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        client_tag: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp: str = "cancel_resting",
        stp_decrement_and_cancel: bool = False,
        priority_fee_ppm: int = 0,
    ) -> Dict[str, Any]:
        prio_ppm_i = _validate_priority_fee_ppm(priority_fee_ppm)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "tif": tif,
            "stp": stp,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
            "reduce_only": reduce_only,
            "is_market": is_market,
        }
        if stp_decrement_and_cancel:
            payload["stp_decrement_and_cancel"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if primary_peg:
            payload["primary_peg"] = True
        if midpoint_peg:
            payload["midpoint_peg"] = True
        if mark_peg:
            payload["mark_peg"] = True
        if trailing_peg:
            payload["trailing_peg"] = True
        if dark_midpoint:
            payload["dark_midpoint"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if min_qty_lots > 0:
            payload["min_qty_lots"] = min_qty_lots
        if display_qty_lots > 0:
            payload["display_qty_lots"] = display_qty_lots
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if prio_ppm_i > 0:
            payload["priority_fee_ppm"] = prio_ppm_i
        return self._post("/order/preview", payload)

    def llms_txt(self) -> str:
        self._reload_creds_file(force=False)
        pq = "/llms.txt"
        url = f"{self.base_url}{pq}"
        status_code, raw_bytes = self._http_pool.request(
            "GET",
            url,
            None,
            self._auth_headers("GET", pq, ""),
            self.timeout,
            _MAX_SDK_HTTP_RESPONSE_BYTES,
        )
        if status_code != 200:
            raise RuntimeError(f"GET /llms.txt returned HTTP {status_code}")
        return raw_bytes.decode("utf-8", errors="replace")

    def openapi_spec(self) -> Dict[str, Any]:
        return self._get("/openapi.json")

    def request_testnet_faucet(
        self,
        recipient: str,
        amount: int | float | str | Decimal = "10000",
        asset: str = "USD",
        drip_gas: bool = True,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        _ = _sdk_abi_address(str(recipient))
        amt_d = _parse_exact_decimal(amount, "amount")
        if amt_d <= 0:
            raise ValueError(f"faucet amount must be > 0, got {amount!r}")
        eff_timeout = max(45.0, self.timeout) if timeout is None else max(0.1, float(timeout))
        return self._post(
            "/faucet",
            {
                "recipient": str(recipient),
                "amount": format(amt_d, "f"),
                "asset": str(asset or "USD").strip().upper(),
                "drip_gas": bool(drip_gas),
            },
            timeout=eff_timeout,
        )

    def deposit_onchain_margin(
        self,
        signer: EthWalletSigner,
        amount: int | float | str | Decimal,
        *,
        account_id: int = 0,
        asset_symbol: str = "USD",
        rpc_url: str = "",
        clearinghouse_address: str = "",
        token_address: str = "",
        wait_for_credit: bool = False,
        poll_timeout_sec: float = 30.0,
    ) -> Dict[str, Any]:
        eff_aid = int(account_id)
        if eff_aid <= 0:
            login_res = self.login_with_wallet(signer)
            if not login_res.get("ok"):
                raise RuntimeError(f"Wallet login failed before deposit_onchain_margin: {login_res}")
            eff_aid = int(login_res["account_id"])

        st = self.settlement_status()
        chain_obj = st.get("chain") if isinstance(st.get("chain"), dict) else {}
        chain_id = int(st.get("chain_id") or chain_obj.get("chain_id") or 0)
        eff_ch = str(
            clearinghouse_address
            or st.get("clearinghouse_address")
            or chain_obj.get("clearinghouse_address")
            or ""
        ).strip()
        if not eff_ch:
            raise ValueError("Clearinghouse address not configured on server; pass clearinghouse_address=...")

        sym_up = str(asset_symbol or "USD").strip().upper()
        asset_id = 0 if sym_up in ("USD", "USDC", "MUSDC") else -1
        eff_tok = str(token_address or "").strip()
        decimals: Optional[int] = None
        assets_list = chain_obj.get("assets") if isinstance(chain_obj.get("assets"), list) else []
        for entry in assets_list:
            if not isinstance(entry, dict):
                continue
            esym = str(entry.get("symbol", "")).strip().upper()
            eaid = int(entry.get("asset_id", -1))
            if esym == sym_up or (asset_id == 0 and eaid == 0):
                asset_id = eaid
                if not eff_tok and entry.get("token_address"):
                    eff_tok = str(entry["token_address"]).strip()
                if entry.get("decimals") is not None:
                    decimals = int(entry["decimals"])
                break
        if asset_id == 0 and not eff_tok and chain_obj.get("collateral_token"):
            eff_tok = str(chain_obj["collateral_token"]).strip()
        if asset_id < 0 or not eff_tok:
            raise ValueError(
                f"Could not resolve on-chain token metadata for asset {sym_up!r}; pass token_address=... or check /settlement/status"
            )

        eff_rpc = str(rpc_url or KNOWN_PUBLIC_RPC_BY_CHAIN_ID.get(chain_id, "")).strip()
        if not eff_rpc:
            raise ValueError(
                f"No RPC URL provided and chain_id={chain_id} is not in KNOWN_PUBLIC_RPC_BY_CHAIN_ID; pass rpc_url=..."
            )

        pre_free_usd = 0
        pre_base_lots = 0
        if wait_for_credit:
            pre_acct = self.account(eff_aid)
            if pre_acct.get("ok"):
                pre_free_usd = int(pre_acct.get("free_usd_micro", 0))
                for b_ent in list(pre_acct.get("base_balances", [])):
                    if int(b_ent.get("asset_id", -1)) == asset_id:
                        pre_base_lots = int(b_ent.get("free_lots", 0))

        evm = EvmJsonRpcClient(
            eff_rpc,
            timeout=max(10.0, self.timeout),
            ssl_context=self._ssl_context,
        )
        try:
            if decimals is None:
                dec_hex = evm.eth_call(eff_tok, encode_erc20_decimals_calldata())
                dec_raw = _sdk_abi_hex_bytes(dec_hex)
                if len(dec_raw) < 32:
                    raise RuntimeError(f"ERC-20 decimals() returned {len(dec_raw)} bytes")
                decimals = int.from_bytes(dec_raw[:32], "big")
            amt_dec = _parse_exact_decimal(amount, "amount")
            scaled_raw = amt_dec * (Decimal(10) ** int(decimals))
            if scaled_raw % 1 != 0 or scaled_raw <= 0:
                raise ValueError(f"amount {amount!r} invalid for {decimals}-decimal token")
            raw_amount = int(scaled_raw)

            allow_hex = evm.eth_call(
                eff_tok, encode_erc20_allowance_calldata(signer.address, eff_ch)
            )
            allow_raw = _sdk_abi_hex_bytes(allow_hex)
            cur_allow = int.from_bytes(allow_raw[:32], "big") if len(allow_raw) >= 32 else 0
            approve_tx_hash = ""
            if cur_allow < raw_amount:
                approve_tx_hash = evm.send_transaction(
                    signer=signer,
                    to_addr=eff_tok,
                    data=encode_erc20_approve_calldata(eff_ch, raw_amount),
                    gas_limit=150_000,
                )
                evm.wait_for_receipt(approve_tx_hash, timeout=max(30.0, self.timeout * 4.0))

            dep_calldata = encode_deposit_trader_margin_calldata(eff_aid, asset_id, raw_amount)
            dep_gas = 650_000
            try:
                est_hex = str(
                    evm.rpc(
                        "eth_estimateGas",
                        [{"from": signer.address, "to": eff_ch, "data": dep_calldata}],
                    )
                )
                dep_gas = max(350_000, (int(est_hex, 16) * 135) // 100)
            except Exception as est_exc:
                _ = est_exc
            dep_tx_hash = evm.send_transaction(
                signer=signer,
                to_addr=eff_ch,
                data=dep_calldata,
                gas_limit=dep_gas,
            )
            receipt = evm.wait_for_receipt(dep_tx_hash, timeout=max(30.0, self.timeout * 4.0))
        finally:
            evm.close()

        credited = False
        post_acct: Optional[Dict[str, Any]] = None
        if wait_for_credit:
            deadline = time.monotonic() + max(0.5, float(poll_timeout_sec))
            while time.monotonic() < deadline:
                cur_a = self.account(eff_aid)
                if cur_a.get("ok"):
                    post_acct = cur_a
                    if asset_id == 0 and int(cur_a.get("free_usd_micro", 0)) > pre_free_usd:
                        credited = True
                        break
                    if asset_id > 0:
                        cur_b = 0
                        for b_ent in list(cur_a.get("base_balances", [])):
                            if int(b_ent.get("asset_id", -1)) == asset_id:
                                cur_b = int(b_ent.get("free_lots", 0))
                        if cur_b > pre_base_lots:
                            credited = True
                            break
                time.sleep(0.25)

        return {
            "ok": True,
            "account_id": eff_aid,
            "asset_id": asset_id,
            "asset_symbol": sym_up,
            "token_address": eff_tok,
            "clearinghouse_address": eff_ch,
            "chain_id": chain_id,
            "raw_amount": raw_amount,
            "approve_tx_hash": approve_tx_hash,
            "deposit_tx_hash": dep_tx_hash,
            "block_number": int(str(receipt.get("blockNumber", "0x0")), 16),
            "credited": credited,
            "account": post_acct,
        }

    def claim_withdrawal_voucher_onchain(
        self,
        signer: EthWalletSigner,
        voucher: Dict[str, Any],
        *,
        rpc_url: str = "",
        clearinghouse_address: str = "",
    ) -> Dict[str, Any]:
        chain_id = int(voucher.get("chain_id") or 0)
        eff_ch = str(clearinghouse_address or voucher.get("clearinghouse_address") or "").strip()
        if not eff_ch or chain_id <= 0:
            st = self.settlement_status()
            if not eff_ch:
                eff_ch = str(st.get("clearinghouse_address") or "").strip()
            if chain_id <= 0:
                chain_id = int(st.get("chain_id") or 0)
        if not eff_ch:
            raise ValueError("Missing clearinghouse_address in voucher and /settlement/status")
        eff_rpc = str(rpc_url or KNOWN_PUBLIC_RPC_BY_CHAIN_ID.get(chain_id, "")).strip()
        if not eff_rpc:
            raise ValueError(
                f"No RPC URL provided and chain_id={chain_id} is not in KNOWN_PUBLIC_RPC_BY_CHAIN_ID; pass rpc_url=..."
            )
        calldata = encode_claim_withdrawal_voucher_calldata(voucher)
        evm = EvmJsonRpcClient(
            eff_rpc,
            timeout=max(10.0, self.timeout),
            ssl_context=self._ssl_context,
        )
        try:
            claim_gas = 750_000
            try:
                est_hex = str(
                    evm.rpc(
                        "eth_estimateGas",
                        [{"from": signer.address, "to": eff_ch, "data": calldata}],
                    )
                )
                claim_gas = max(400_000, (int(est_hex, 16) * 135) // 100)
            except Exception as est_exc:
                _ = est_exc
            tx_hash = evm.send_transaction(
                signer=signer,
                to_addr=eff_ch,
                data=calldata,
                gas_limit=claim_gas,
            )
            receipt = evm.wait_for_receipt(tx_hash, timeout=max(30.0, self.timeout * 4.0))
        finally:
            evm.close()
        return {
            "ok": True,
            "withdrawal_id": int(voucher["withdrawal_id"]),
            "clearinghouse_address": eff_ch,
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "receipt": receipt,
        }

    def cancel_order(self, account_id: int, market_id: int, order_id: int) -> Dict[str, Any]:
        return self._post("/cancel", {"account_id": account_id, "market_id": market_id, "order_id": order_id})

    def cancel_all(
        self,
        account_id: int,
        market_id: int = 0,
        client_tag_filter: int = 0,
        market_bitmask: int = 0,
        side_filter: int | str = 0,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "cancel_all": True,
        }
        if client_tag_filter > 0:
            payload["client_tag_filter"] = client_tag_filter
        if market_bitmask > 0:
            payload["market_bitmask"] = market_bitmask
        if isinstance(side_filter, str) and side_filter:
            payload["side"] = side_filter
        elif isinstance(side_filter, int) and side_filter > 0:
            payload["side_filter"] = int(side_filter)
        return self._post("/cancel_all", payload)

    def withdraw(
        self,
        account_id: int,
        amount: int,
        asset_id: int = 0,
        recipient_eth_address: str = "",
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"account_id": account_id, "asset_id": asset_id, "amount": amount}
        if recipient_eth_address:
            payload["recipient_eth_address"] = recipient_eth_address
        return self._post("/withdraw", payload)

    def modify_order(
        self,
        account_id: int,
        market_id: int,
        order_id: int,
        price_ticks: int,
        qty_lots: int,
        keep_priority: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "order_id": order_id,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
        }
        if keep_priority:
            payload["keep_priority"] = True
        return self._post("/modify", payload)

    def register_wild_west_markets(self, creator_account_id: int = 0) -> Dict[str, Any]:
        return self._post("/markets/wild_west", {"creator_account_id": int(creator_account_id)})

    def create_market_suite(
        self,
        creator_account_id: int,
        base_symbol: str,
        initial_mark_ticks: int = 10_000,
        eigen_factor_idx: int = 3,
        isolated_solvency_cell: bool = False,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/create_suite",
            {
                "creator_account_id": int(creator_account_id),
                "base_symbol": str(base_symbol),
                "initial_mark_ticks": int(initial_mark_ticks),
                "eigen_factor_idx": int(eigen_factor_idx),
                "isolated_solvency_cell": bool(isolated_solvency_cell),
            },
        )

    def set_market_session_regime(
        self,
        market_id: int,
        regime: int | str = 0,
        target_or_anchor_ticks: int = 0,
        collar_bps: int = 500,
        imr_floor_bps: int = 200,
        convergence_rate_bps: int = 25,
        impact_notional_micro: int = 25_000_000_000,
        step_only: bool = False,
        funding_delta_phi: int = 0,
    ) -> Dict[str, Any]:
        if isinstance(regime, str):
            reg_map = {"continuous": 0, "off_hours": 1, "reopen_auction": 2}
            reg_val = reg_map.get(regime.strip().lower(), 0)
        else:
            reg_val = int(regime)
        return self._post(
            "/markets/session_regime",
            {
                "market_id": int(market_id),
                "regime": reg_val,
                "target_or_anchor_ticks": int(target_or_anchor_ticks),
                "collar_bps": int(collar_bps),
                "imr_floor_bps": int(imr_floor_bps),
                "convergence_rate_bps": int(convergence_rate_bps),
                "impact_notional_micro": int(impact_notional_micro),
                "step_only": bool(step_only),
                "funding_delta_phi": int(funding_delta_phi),
            },
        )

    set_session_regime = set_market_session_regime

    def step_off_hours_or_reopen_mark(
        self,
        market_id: int,
        funding_delta_phi: int = 0,
    ) -> Dict[str, Any]:
        return self.set_market_session_regime(
            market_id=market_id,
            step_only=True,
            funding_delta_phi=funding_delta_phi,
        )

    def execute_corporate_action(
        self,
        market_id: int,
        action_kind: int,
        split_factor: int = 1,
        dividend_ticks: int = 0,
        treasury_account_id: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/corporate_action",
            {
                "market_id": int(market_id),
                "action_kind": int(action_kind),
                "split_factor": int(split_factor),
                "dividend_ticks": int(dividend_ticks),
                "treasury_account_id": int(treasury_account_id),
            },
        )

    def execute_synthetic_cross(
        self,
        account_id: int,
        leg1_market_id: int,
        leg2_market_id: int,
        side: str,
        leg1_qty_lots: int,
        leg2_qty_lots: int = 0,
        limit_ratio_ticks: int = 0,
        margin_spot: bool = False,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/synthetic_cross",
            {
                "account_id": int(account_id),
                "leg1_market_id": int(leg1_market_id),
                "leg2_market_id": int(leg2_market_id),
                "side": str(side),
                "leg1_qty_lots": int(leg1_qty_lots),
                "leg2_qty_lots": int(leg2_qty_lots),
                "limit_ratio_ticks": int(limit_ratio_ticks),
                "margin_spot": bool(margin_spot),
            },
        )

    def set_asset_risk_profile(
        self,
        asset_id: int,
        eigen_factor_idx: int = 0,
        pc0_beta_centi: int = 0,
        collateral_weight_bps: int = 9000,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/risk_profile",
            {
                "asset_id": int(asset_id),
                "eigen_factor_idx": int(eigen_factor_idx),
                "pc0_beta_centi": int(pc0_beta_centi),
                "collateral_weight_bps": int(collateral_weight_bps),
            },
        )

    def set_claim_collateral_weight_bps(self, weight_bps: int = 9500) -> Dict[str, Any]:
        return self._post(
            "/markets/risk_profile",
            {"claim_collateral_weight_bps": int(weight_bps)},
        )

    def fund_isolated_market_insurance(
        self,
        sponsor_account_id: int,
        market_id: int,
        amount_usd_micro: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/isolated_insurance",
            {
                "sponsor_account_id": int(sponsor_account_id),
                "market_id": int(market_id),
                "amount_usd_micro": int(amount_usd_micro),
            },
        )

    def fund_global_insurance_fund(
        self,
        sponsor_account_id: int,
        amount_usd_micro: int,
    ) -> Dict[str, Any]:
        return self.fund_isolated_market_insurance(sponsor_account_id, 0, amount_usd_micro)

    def set_min_insurance_reserve_usd_micro(self, min_insurance_reserve_usd_micro: int) -> Dict[str, Any]:
        return self._post(
            "/insurance/fund",
            {
                "market_id": 0,
                "min_insurance_reserve_usd_micro": int(min_insurance_reserve_usd_micro),
            },
        )

    def set_market_max_open_interest(
        self,
        market_id: int,
        max_oi_notional_micro: int,
        isolated_solvency_cell: bool = True,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/isolated_insurance",
            {
                "market_id": int(market_id),
                "max_oi_notional_micro": int(max_oi_notional_micro),
                "isolated_solvency_cell": bool(isolated_solvency_cell),
            },
        )

    def graduate_bonding_curve_to_l3_spot(self, market_id: int) -> Dict[str, Any]:
        return self._post(
            "/markets/notional_bbo_yield",
            {"market_id": int(market_id), "graduate_curve": True},
        )

    def set_notional_bbo_yield_weighting(
        self,
        enabled: bool = True,
        market_id: int = 0,
        launch_boost_bps: int = 10000,
        two_sided_bbo_bonus_bps: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "enabled": bool(enabled),
            "market_id": int(market_id),
            "launch_boost_bps": int(launch_boost_bps),
        }
        if two_sided_bbo_bonus_bps is not None:
            payload["two_sided_bbo_bonus_bps"] = int(two_sided_bbo_bonus_bps)
        return self._post("/markets/notional_bbo_yield", payload)

    def bind_builder_code(
        self,
        trader_account_id: int,
        builder_account_id: int,
        builder_fee_share_bps: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/account/builder",
            {
                "trader_account_id": int(trader_account_id),
                "builder_account_id": int(builder_account_id),
                "builder_fee_share_bps": int(builder_fee_share_bps),
            },
        )

    def configure_mmp(
        self,
        account_id: int,
        window_wal_seqs: int,
        max_fill_lots: int,
        max_delta_lots: int = 0,
        cooldown_wal_seqs: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/account/mmp",
            {
                "account_id": int(account_id),
                "window_wal_seqs": int(window_wal_seqs),
                "max_fill_lots": int(max_fill_lots),
                "max_delta_lots": int(max_delta_lots),
                "cooldown_wal_seqs": int(cooldown_wal_seqs),
            },
        )

    def set_itch_privacy(
        self,
        anonymize_accounts: bool = True,
        two_sided_bbo_bonus_bps: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"anonymize_accounts": bool(anonymize_accounts)}
        if two_sided_bbo_bonus_bps is not None:
            payload["two_sided_bbo_bonus_bps"] = int(two_sided_bbo_bonus_bps)
        return self._post("/admin/itch_privacy", payload)

    def quote_replace(
        self,
        account_id: int,
        market_id: int,
        bid_price_ticks: int,
        bid_qty_lots: int,
        ask_price_ticks: int,
        ask_qty_lots: int,
        tif: str = "gtc",
        stp: str = "cancel_resting",
        post_only_slide: bool = False,
        margin_spot: bool = False,
        client_tag: int = 0,
        auto_skew_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        auto_flip_ticks: int = 0,
        quote_peg_mode: int = 0,
        peg_offset_ticks: int = 0,
        ladder_by_tag: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "market_id": market_id,
            "bid_price_ticks": bid_price_ticks,
            "bid_qty_lots": bid_qty_lots,
            "ask_price_ticks": ask_price_ticks,
            "ask_qty_lots": ask_qty_lots,
            "tif": tif,
            "stp": stp,
        }
        if ladder_by_tag:
            payload["ladder_by_tag"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if quote_peg_mode > 0:
            payload["quote_peg_mode"] = quote_peg_mode
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        return self._post("/quote", payload)

    two_sided_quote_replace = quote_replace

    def auto_delta_hedge(
        self,
        account_id: int,
        base_asset_id: int = 0,
        preferred_market_id: int = 0,
        max_slippage_bps: int = 200,
        max_qty_lots: int = 0,
        margin_spot: bool = False,
        stp: str = "cancel_resting",
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "base_asset_id": base_asset_id,
            "preferred_market_id": preferred_market_id,
            "max_slippage_bps": max_slippage_bps,
            "max_qty_lots": max_qty_lots,
            "margin_spot": margin_spot,
            "stp": stp,
        }
        return self._post("/auto_delta_hedge", payload)

    delta_hedge = auto_delta_hedge

    def link_sub_account(
        self,
        master_account_id: int,
        sub_account_id: int,
        max_guaranty_usd_micro: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/prime/link_sub",
            {
                "master_account_id": master_account_id,
                "sub_account_id": sub_account_id,
                "max_guaranty_usd_micro": max_guaranty_usd_micro,
            },
        )

    def prime_internal_transfer(
        self,
        from_account_id: int,
        to_account_id: int,
        amount: int,
        asset_id: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/prime/transfer",
            {
                "from_account_id": from_account_id,
                "to_account_id": to_account_id,
                "asset_id": asset_id,
                "amount": amount,
            },
        )

    prime_transfer = prime_internal_transfer

    def auto_cross_arb(
        self,
        account_id: int,
        primary_market_id: int,
        secondary_market_id: int = 0,
        max_qty_lots: int = 0,
        min_profit_micro: int = 0,
        margin_spot: bool = False,
        stp: str = "cancel_resting",
        express_surplus_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        payload: Dict[str, Any] = {
            "account_id": account_id,
            "primary_market_id": primary_market_id,
            "secondary_market_id": secondary_market_id,
            "max_qty_lots": max_qty_lots,
            "min_profit_micro": min_profit_micro,
            "margin_spot": margin_spot,
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        return self._post("/auto_cross_arb", payload)

    def update_mark(self, market_id: int, mark_price_ticks: int, funding_delta_phi: int = 0) -> Dict[str, Any]:
        return self._post(
            "/mark",
            {
                "market_id": market_id,
                "mark_price_ticks": mark_price_ticks,
                "funding_delta_phi": funding_delta_phi,
            },
        )

    def liquidate(
        self,
        liquidator_account_id: int,
        target_account_id: int,
        market_id: int,
        partial_lots: int = 0,
        allow_l3_offload: bool = True,
        hedge_margin_spot: bool = False,
        stp: str = "cancel_resting",
        bounty_rebate_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if bid_bps_i > 0 and int(liquidator_account_id) == int(target_account_id):
            raise ValueError("bounty_rebate_bid_bps > 0 cannot be used with self-knockout")
        payload: Dict[str, Any] = {
            "liquidator_account_id": liquidator_account_id,
            "target_account_id": target_account_id,
            "market_id": market_id,
            "allow_l3_offload": bool(allow_l3_offload),
            "hedge_margin_spot": bool(hedge_margin_spot),
            "stp": str(stp),
        }
        if partial_lots > 0:
            payload["partial_lots"] = partial_lots
        if bid_bps_i > 0:
            payload["bounty_rebate_bid_bps"] = bid_bps_i
        return self._post("/liquidate", payload)

    def set_knockout(self, account_id: int, market_id: int, knockout_price_ticks: int) -> Dict[str, Any]:
        return self._post(
            "/knockout",
            {
                "account_id": account_id,
                "market_id": market_id,
                "knockout_price_ticks": knockout_price_ticks,
            },
        )

    def set_drawdown_stop(self, account_id: int, stop_equity_usd_micro: int) -> Dict[str, Any]:
        return self._post(
            "/drawdown_stop",
            {
                "account_id": account_id,
                "stop_equity_usd_micro": stop_equity_usd_micro,
            },
        )

    def auto_liquidate(
        self,
        liquidator_account_id: int,
        market_id: int = 0,
        target_account_id: int = 0,
        max_lots: int = 0,
        min_bounty_micro: int = 0,
        flash_offload_to_book: bool = True,
        stp: str = "cancel_resting",
        hedge_margin_spot: bool = False,
        bounty_rebate_bid_bps: int = 0,
    ) -> Dict[str, Any]:
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if bid_bps_i > 0 and int(target_account_id) != 0 and int(target_account_id) == int(liquidator_account_id):
            raise ValueError("Cannot submit bounty_rebate_bid_bps against own account_id")
        payload: Dict[str, Any] = {
            "liquidator_account_id": liquidator_account_id,
            "market_id": market_id,
            "target_account_id": target_account_id,
            "max_qty_lots": max_lots,
            "min_bounty_micro": min_bounty_micro,
            "auto_offload_to_book": flash_offload_to_book,
            "hedge_margin_spot": bool(hedge_margin_spot),
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["bounty_rebate_bid_bps"] = bid_bps_i
        return self._post("/auto_liquidate", payload)

    auto_liquidation_sweep = auto_liquidate

    def get_wal_snapshot(self) -> Dict[str, Any]:
        return self._get("/wal/snapshot")

    def save_wal_snapshot(self, snapshot_path: str = "") -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if snapshot_path:
            payload["snapshot_path"] = snapshot_path
        return self._post("/wal/snapshot", payload)

    def sweep_excess_insurance_fund(
        self,
        reserve_floor_usd_micro: int = 0,
        max_sweep_usd_micro: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/insurance/sweep",
            {
                "reserve_floor_usd_micro": max(0, int(reserve_floor_usd_micro)),
                "max_sweep_usd_micro": max(0, int(max_sweep_usd_micro)),
            },
        )

    sweep_insurance = sweep_excess_insurance_fund

    def enable_macro_markets(self) -> Dict[str, Any]:
        return self._post("/markets/enable-macro", {})

    register_macro_markets = enable_macro_markets

    def enable_basis_spread_markets(self) -> Dict[str, Any]:
        return self._post("/markets/enable-basis-spreads", {})

    enable_basis_spreads = enable_basis_spread_markets

    def supercharge_volume(
        self,
        maker_fee_bps: int = 0,
        taker_fee_bps: int = 0,
        organic_turnover_velocity_mult: int = 1000000,
        auto_yield_drip_on_mark: bool = True,
        enable_macro_and_basis: bool = True,
    ) -> Dict[str, Any]:
        return self._post(
            "/volume/supercharge",
            {
                "maker_fee_bps": int(maker_fee_bps),
                "taker_fee_bps": int(taker_fee_bps),
                "organic_turnover_velocity_mult": int(organic_turnover_velocity_mult),
                "auto_yield_drip_on_mark": bool(auto_yield_drip_on_mark),
                "enable_macro_and_basis": bool(enable_macro_and_basis),
            },
        )

    enable_supercharged_volume_engine = supercharge_volume

    def set_auto_yield_drip(self, enabled: bool = True) -> Dict[str, Any]:
        return self._post("/yield/auto-drip", {"enabled": bool(enabled)})

    def harvest_custody_float_yield(
        self,
        yield_rate_bps: int = 1,
        protocol_spread_share_bps: int = -1,
        protocol_spread_bps: Optional[int] = None,
    ) -> Dict[str, Any]:
        eff_spread = int(protocol_spread_bps) if protocol_spread_bps is not None else int(protocol_spread_share_bps)
        return self._post(
            "/yield/harvest_float",
            {
                "yield_rate_bps": int(yield_rate_bps),
                "protocol_spread_share_bps": eff_spread,
            },
        )

    def harvest_overnight_spot_repo(
        self,
        base_asset_id: int = 1,
        override_rate_bps: int = 0,
        base_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        eff_base = int(base_id) if base_id is not None else int(base_asset_id)
        return self._post(
            "/yield/harvest_spot_repo",
            {
                "base_asset_id": eff_base,
                "override_rate_bps": int(override_rate_bps),
            },
        )

    def harvest_negative_usd_repo(
        self,
        override_rate_bps: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/yield/harvest_usd_repo",
            {
                "override_rate_bps": int(override_rate_bps),
            },
        )

    def set_market_status(
        self,
        market_id: int,
        status: int | str,
        cancel_resting_orders: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "market_id": int(market_id),
            "status": status if isinstance(status, str) else int(status),
            "cancel_resting_orders": bool(cancel_resting_orders),
        }
        return self._post("/markets/status", payload)

    set_market_trading_status = set_market_status

    def update_market_config(
        self,
        market_id: int = 0,
        maker_fee_bps: Optional[int] = None,
        taker_fee_bps: Optional[int] = None,
        imr_bps: Optional[int] = None,
        mmr_bps: Optional[int] = None,
        liq_penalty_bps: Optional[int] = None,
        max_order_lots: Optional[int] = None,
        max_open_interest_notional_micro: Optional[int] = None,
        all_markets: bool = False,
        reset_to_segmented: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"market_id": int(market_id)}
        if all_markets:
            payload["all_markets"] = True
        if reset_to_segmented:
            payload["reset_to_segmented"] = True
        if maker_fee_bps is not None:
            payload["maker_fee_bps"] = int(maker_fee_bps)
        if taker_fee_bps is not None:
            payload["taker_fee_bps"] = int(taker_fee_bps)
        if imr_bps is not None:
            payload["imr_bps"] = int(imr_bps)
        if mmr_bps is not None:
            payload["mmr_bps"] = int(mmr_bps)
        if liq_penalty_bps is not None:
            payload["liq_penalty_bps"] = int(liq_penalty_bps)
        if max_order_lots is not None:
            payload["max_order_lots"] = int(max_order_lots)
        if max_open_interest_notional_micro is not None:
            payload["max_open_interest_notional_micro"] = int(max_open_interest_notional_micro)
        return self._post("/markets/config", payload)

    update_market_parameters = update_market_config

    def set_market_fees(
        self,
        market_id: int = 0,
        maker_fee_bps: Optional[int] = None,
        taker_fee_bps: Optional[int] = None,
        all_markets: bool = False,
        reset_to_segmented: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"market_id": int(market_id)}
        if all_markets:
            payload["all_markets"] = True
        if reset_to_segmented:
            payload["reset_to_segmented"] = True
        if maker_fee_bps is not None:
            payload["maker_fee_bps"] = int(maker_fee_bps)
        if taker_fee_bps is not None:
            payload["taker_fee_bps"] = int(taker_fee_bps)
        return self._post("/markets/fees", payload)

    def get_eigen_factor_bank(self) -> Dict[str, Any]:
        return self._get("/risk/eigen_bank")

    def stage_eigen_factor_bank(
        self,
        factor_shock_bps: List[int],
        idiosyncratic_residual_rate_bps: int = 500,
        activate_immediately: bool = False,
    ) -> Dict[str, Any]:
        return self._post(
            "/risk/eigen_bank",
            {
                "factor_shock_bps": [int(x) for x in factor_shock_bps],
                "idiosyncratic_residual_rate_bps": int(idiosyncratic_residual_rate_bps),
                "activate_immediately": bool(activate_immediately),
            },
        )

    def configure_payout_preferences(
        self,
        account_id: int,
        payout_asset_id: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> Dict[str, Any]:
        return self._post(
            "/account/payout_preferences",
            {
                "account_id": int(account_id),
                "payout_asset_id": int(payout_asset_id),
                "payout_mode_flags": int(payout_mode_flags),
                "payout_target_account_id": int(payout_target_account_id),
                "auto_repay_borrow": bool(auto_repay_borrow),
                "compound_bonding_curve": bool(compound_bonding_curve),
                "auto_compound_quotes": bool(auto_compound_quotes),
            },
        )

    def configure_payout_portfolio(
        self,
        account_id: int,
        primary_asset_id: int = 0,
        primary_share_bps: int = 10_000,
        secondary_asset_id: int = 0,
        secondary_share_bps: int = 0,
        tertiary_asset_id: int = 0,
        tertiary_share_bps: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        max_margin_util_bps: int = 0,
        max_price_ticks: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> Dict[str, Any]:
        return self._post(
            "/account/payout_portfolio",
            {
                "account_id": int(account_id),
                "primary_asset_id": int(primary_asset_id),
                "primary_share_bps": int(primary_share_bps),
                "secondary_asset_id": int(secondary_asset_id),
                "secondary_share_bps": int(secondary_share_bps),
                "tertiary_asset_id": int(tertiary_asset_id),
                "tertiary_share_bps": int(tertiary_share_bps),
                "payout_mode_flags": int(payout_mode_flags),
                "payout_target_account_id": int(payout_target_account_id),
                "max_margin_util_bps": int(max_margin_util_bps),
                "max_price_ticks": int(max_price_ticks),
                "auto_repay_borrow": bool(auto_repay_borrow),
                "compound_bonding_curve": bool(compound_bonding_curve),
                "auto_compound_quotes": bool(auto_compound_quotes),
            },
        )

    def configure_auto_repo_scheduler(
        self,
        epoch_marks: int,
        clock_market_id: int = 0,
    ) -> Dict[str, Any]:
        return self._post(
            "/yield/auto_repo_config",
            {
                "epoch_marks": int(epoch_marks),
                "clock_market_id": int(clock_market_id),
            },
        )

    def configure_war_hardening(
        self,
        strict_zero_trading_fee_lock: Optional[bool] = None,
        zero_fee_skim_elimination: Optional[bool] = None,
        max_live_mark_step_bps: Optional[int] = None,
        knockout_confirm_marks: Optional[int] = None,
        enforce_collateral_order_cap: Optional[bool] = None,
        rotate_itch_salt_on_repo_epoch: Optional[bool] = None,
        bbo_uptime_seniority_enabled: Optional[bool] = None,
        segmented_public_fee_schedule: Optional[bool] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if strict_zero_trading_fee_lock is not None:
            payload["strict_zero_trading_fee_lock"] = bool(strict_zero_trading_fee_lock)
        if zero_fee_skim_elimination is not None:
            payload["zero_fee_skim_elimination"] = bool(zero_fee_skim_elimination)
        if max_live_mark_step_bps is not None:
            payload["max_live_mark_step_bps"] = int(max_live_mark_step_bps)
        if knockout_confirm_marks is not None:
            payload["knockout_confirm_marks"] = int(knockout_confirm_marks)
        if enforce_collateral_order_cap is not None:
            payload["enforce_collateral_order_cap"] = bool(enforce_collateral_order_cap)
        if rotate_itch_salt_on_repo_epoch is not None:
            payload["rotate_itch_salt_on_repo_epoch"] = bool(rotate_itch_salt_on_repo_epoch)
        if bbo_uptime_seniority_enabled is not None:
            payload["bbo_uptime_seniority_enabled"] = bool(bbo_uptime_seniority_enabled)
        if segmented_public_fee_schedule is not None:
            payload["segmented_public_fee_schedule"] = bool(segmented_public_fee_schedule)
        return self._post("/protocol/war_hardening", payload)

    def fund_market_liquidity_vault(
        self,
        sponsor_account_id: int,
        market_id: int,
        asset_id: int,
        amount: int,
        duration_marks: int,
        maker_share_bps: int = 7_500,
    ) -> Dict[str, Any]:
        return self._post(
            "/markets/fund_vault",
            {
                "sponsor_account_id": int(sponsor_account_id),
                "market_id": int(market_id),
                "asset_id": int(asset_id),
                "amount": int(amount),
                "duration_marks": int(duration_marks),
                "maker_share_bps": int(maker_share_bps),
            },
        )

    def configure_default_trader_incentives(
        self,
        enabled: Optional[bool] = None,
        pillar_mask: Optional[int] = None,
        supercharge_volume: Optional[bool] = None,
        auto_yield_drip: Optional[bool] = None,
        auto_repo: Optional[bool] = None,
        notional_bbo_yield: Optional[bool] = None,
        two_sided_bonus: Optional[bool] = None,
        claim_collateral: Optional[bool] = None,
        itch_anonymize_accounts: Optional[bool] = None,
        enable_macro_and_basis: Optional[bool] = None,
        repo_auto_epoch_marks: Optional[int] = None,
        two_sided_bbo_bonus_bps: Optional[int] = None,
        claim_collateral_weight_bps: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if enabled is not None:
            payload["enabled"] = bool(enabled)
        if pillar_mask is not None:
            payload["pillar_mask"] = int(pillar_mask)
        if supercharge_volume is not None:
            payload["supercharge_volume"] = bool(supercharge_volume)
        if auto_yield_drip is not None:
            payload["auto_yield_drip"] = bool(auto_yield_drip)
        if auto_repo is not None:
            payload["auto_repo"] = bool(auto_repo)
        if notional_bbo_yield is not None:
            payload["notional_bbo_yield"] = bool(notional_bbo_yield)
        if two_sided_bonus is not None:
            payload["two_sided_bonus"] = bool(two_sided_bonus)
        if claim_collateral is not None:
            payload["claim_collateral"] = bool(claim_collateral)
        if itch_anonymize_accounts is not None:
            payload["itch_anonymize_accounts"] = bool(itch_anonymize_accounts)
        if enable_macro_and_basis is not None:
            payload["enable_macro_and_basis"] = bool(enable_macro_and_basis)
        if repo_auto_epoch_marks is not None:
            payload["repo_auto_epoch_marks"] = int(repo_auto_epoch_marks)
        if two_sided_bbo_bonus_bps is not None:
            payload["two_sided_bbo_bonus_bps"] = int(two_sided_bbo_bonus_bps)
        if claim_collateral_weight_bps is not None:
            payload["claim_collateral_weight_bps"] = int(claim_collateral_weight_bps)
        return self._post("/protocol/default_incentives", payload)

    def distribute_base_asset_yield(
        self,
        sponsor_account_id: int,
        base_asset_id: int,
        total_lots: int,
    ) -> Dict[str, Any]:
        return self._post(
            "/yield/distribute_base",
            {
                "sponsor_account_id": int(sponsor_account_id),
                "base_asset_id": int(base_asset_id),
                "total_lots": int(total_lots),
            },
        )

    def subscribe_express_port(
        self,
        account_id: int,
        duration_epochs: int = 1,
        max_fee_usd_micro: int = 0,
    ) -> Dict[str, Any]:
        dur_i = int(duration_epochs)
        max_fee_i = int(max_fee_usd_micro)
        if not (1 <= dur_i <= MAX_EXPRESS_PORT_LEASE_EPOCHS):
            raise ValueError(
                f"duration_epochs {dur_i} out of [1, {MAX_EXPRESS_PORT_LEASE_EPOCHS}]"
            )
        if max_fee_i < 0:
            raise ValueError("max_fee_usd_micro must be >= 0")
        return self._post(
            "/account/express_port",
            {
                "account_id": int(account_id),
                "duration_epochs": dur_i,
                "max_fee_usd_micro": max_fee_i,
            },
        )

    def set_express_port_fee_per_epoch(
        self,
        fee_per_epoch_usd_micro: int,
    ) -> Dict[str, Any]:
        fee_i = int(fee_per_epoch_usd_micro)
        if not (
            MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
            <= fee_i
            <= MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
        ):
            raise ValueError(
                f"fee_per_epoch_usd_micro {fee_i} out of "
                f"[{MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}, {MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}]"
            )
        return self._post(
            "/protocol/express_port_fee",
            {"fee_per_epoch_usd_micro": fee_i},
        )

    def wind_down_pools(self) -> Dict[str, Any]:
        return self._post("/admin/wind_down_pools", {})


_RFC6455_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def compute_websocket_accept(sec_websocket_key: str) -> str:
    digest = hashlib.sha1((sec_websocket_key.strip() + _RFC6455_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


class ArenaWebSocketClient:
    """
    Zero-dependency RFC-6455 WebSocket client for real-time Arena Exchange
    market-data streaming (`snapshot`, `book`, `trade`, `candle`), private
    account/fill updates (`account`), and low-overhead JSON order entry.
    """

    def __init__(
        self,
        ws_url: str = "ws://127.0.0.1:8080/ws",
        market_id: int = 1,
        account_id: int = 0,
        timeout: float = 3.0,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        parsed = urllib.parse.urlparse(ws_url)
        if parsed.scheme not in ("ws", "wss", "http", "https"):
            raise ValueError(f"Unsupported WebSocket URL scheme: {parsed.scheme!r}")
        self.use_tls = parsed.scheme in ("wss", "https")
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port if parsed.port is not None else (443 if self.use_tls else 80)
        base_path = "/ws" if (not parsed.path or parsed.path == "/") else parsed.path
        q_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        q_dict = dict(q_items)
        q_dict.setdefault("market_id", str(market_id))
        q_dict.setdefault("account_id", str(account_id))
        self.resource = f"{base_path}?{urllib.parse.urlencode(q_dict)}"
        self.timeout = timeout
        self.api_key = api_key
        self.api_secret = api_secret
        self._ssl_context = ssl_context
        self._rx_buf = bytearray()
        self._frag_buf = bytearray()
        self._in_frag = False
        self._req_id = 0
        self._tx_lock = threading.RLock()
        self._sock: Optional[socket.socket] = None
        self._connect_and_handshake()

    @classmethod
    def testnet(
        cls,
        market_id: int = 1,
        account_id: int = 0,
        timeout: float = 10.0,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        ws_url: str = PUBLIC_TESTNET_WS_URL,
    ) -> "ArenaWebSocketClient":
        """Connect & upgrade in 1 line to the live public Base Sepolia WebSocket (`wss://testnet.feraterra.app/ws`)."""
        return cls(
            ws_url=ws_url,
            market_id=market_id,
            account_id=account_id,
            timeout=timeout,
            api_key=api_key,
            api_secret=api_secret,
            ssl_context=ssl_context,
        )

    def __enter__(self) -> "ArenaWebSocketClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _connect_and_handshake(self) -> None:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock: socket.socket = raw_sock
        try:
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.use_tls:
                ctx = self._ssl_context if self._ssl_context is not None else _default_ssl_context()
                sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                sock.settimeout(self.timeout)
            nonce_key = base64.b64encode(os.urandom(16)).decode("ascii")
            expected_accept = compute_websocket_accept(nonce_key)
            host_base = (
                f"[{self.host}]"
                if ":" in self.host and not self.host.startswith("[")
                else self.host
            )
            default_port = 443 if self.use_tls else 80
            host_hdr = host_base if self.port == default_port else f"{host_base}:{self.port}"
            req_lines = [
                f"GET {self.resource} HTTP/1.1",
                f"Host: {host_hdr}",
                f"User-Agent: {_DEFAULT_USER_AGENT}",
                "Upgrade: websocket",
                "Connection: Upgrade",
                f"Sec-WebSocket-Key: {nonce_key}",
                "Sec-WebSocket-Version: 13",
            ]
            if self.api_key and self.api_secret:
                for hk, hv in _build_hmac_auth_headers(
                    self.api_key, self.api_secret, "GET", self.resource, ""
                ).items():
                    req_lines.append(f"{hk}: {hv}")
            req_lines.extend(["", ""])
            sock.sendall("\r\n".join(req_lines).encode("ascii"))

            hdr_buf = bytearray()
            handshake_deadline = time.monotonic() + max(0.05, float(self.timeout))
            while b"\r\n\r\n" not in hdr_buf:
                remaining = handshake_deadline - time.monotonic()
                if remaining <= 0.0:
                    raise TimeoutError("Timed out during WebSocket HTTP upgrade handshake")
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Connection closed before RFC-6455 handshake completed")
                hdr_buf.extend(chunk)
                if len(hdr_buf) > 32768:
                    raise ConnectionError("Oversized WebSocket HTTP handshake header")

            sep_idx = hdr_buf.index(b"\r\n\r\n")
            raw_hdr = bytes(hdr_buf[:sep_idx]).decode("latin-1")
            # Preserve any trailing WebSocket frame bytes already pushed after \r\n\r\n!
            self._rx_buf.extend(hdr_buf[sep_idx + 4 :])

            lines = raw_hdr.split("\r\n")
            if not lines or " 101 " not in lines[0]:
                raise ConnectionError(f"WebSocket upgrade rejected: {lines[0] if lines else 'empty'}")

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            actual_accept = headers.get("sec-websocket-accept", "")
            if actual_accept != expected_accept:
                raise ConnectionError(
                    f"Invalid Sec-WebSocket-Accept: got {actual_accept!r}, expected {expected_accept!r}"
                )
            sock.settimeout(self.timeout)
            self._sock = sock
        except Exception:
            sock.close()
            if sock is not raw_sock:
                raw_sock.close()
            raise

    @staticmethod
    def _encode_masked_client_frame(opcode: int, payload: bytes) -> bytes:
        out = bytearray()
        out.append(0x80 | (opcode & 0x0F))
        plen = len(payload)
        if plen < 126:
            out.append(0x80 | plen)
        elif plen <= 0xFFFF:
            out.append(0x80 | 126)
            out.extend(struct.pack("!H", plen))
        else:
            out.append(0x80 | 127)
            out.extend(struct.pack("!Q", plen))

        mask_key = os.urandom(4)
        out.extend(mask_key)
        masked = bytearray(plen)
        for i, b in enumerate(payload):
            masked[i] = b ^ mask_key[i & 3]
        out.extend(masked)
        return bytes(out)

    def _try_pop_frame(self) -> Optional[tuple[int, bool, bytes]]:
        buf = self._rx_buf
        if len(buf) < 2:
            return None
        b0 = buf[0]
        b1 = buf[1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        plen = b1 & 0x7F
        idx = 2
        if plen == 126:
            if len(buf) < 4:
                return None
            plen = struct.unpack("!H", buf[2:4])[0]
            idx = 4
        elif plen == 127:
            if len(buf) < 10:
                return None
            plen = struct.unpack("!Q", buf[2:10])[0]
            idx = 10

        if plen > _MAX_SDK_HTTP_RESPONSE_BYTES:
            raise ValueError(f"WebSocket frame payload length {plen} exceeds 64 MiB limit")

        mask_key = b""
        if masked:
            if len(buf) < idx + 4:
                return None
            mask_key = bytes(buf[idx : idx + 4])
            idx += 4

        if len(buf) < idx + plen:
            return None

        payload = bytearray(buf[idx : idx + plen])
        del buf[: idx + plen]
        if masked:
            for i in range(plen):
                payload[i] ^= mask_key[i & 3]
        return opcode, fin, bytes(payload)

    def send_text(self, text: str) -> None:
        with self._tx_lock:
            if self._sock is None:
                raise ConnectionError("WebSocket is closed")
            frame = self._encode_masked_client_frame(0x1, text.encode("utf-8"))
            self._sock.sendall(frame)

    def send_json(self, obj: Dict[str, Any]) -> None:
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def recv_text(self, timeout: Optional[float] = None) -> str:
        if self._sock is None:
            raise ConnectionError("WebSocket is closed")
        eff_timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + eff_timeout

        while True:
            popped = self._try_pop_frame()
            if popped is not None:
                opcode, fin, payload = popped
                if opcode == 0x9:  # Ping -> reply Pong
                    with self._tx_lock:
                        if self._sock is not None:
                            self._sock.sendall(self._encode_masked_client_frame(0xA, payload))
                    continue
                if opcode == 0xA:  # Pong
                    continue
                if opcode == 0x8:  # Close
                    self.close()
                    raise ConnectionError("WebSocket closed by server")
                if opcode in (0x1, 0x2):
                    if fin:
                        return payload.decode("utf-8")
                    self._in_frag = True
                    self._frag_buf = bytearray(payload)
                    continue
                if opcode == 0x0 and self._in_frag:
                    if len(self._frag_buf) + len(payload) > _MAX_SDK_HTTP_RESPONSE_BYTES:
                        raise ValueError("WebSocket fragmented message exceeds 64 MiB limit")
                    self._frag_buf.extend(payload)
                    if fin:
                        self._in_frag = False
                        full = bytes(self._frag_buf)
                        self._frag_buf.clear()
                        return full.decode("utf-8")
                    continue

            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("Timed out waiting for WebSocket message")
            self._sock.settimeout(rem)
            chunk = self._sock.recv(8192)
            if not chunk:
                self.close()
                raise ConnectionError("WebSocket EOF")
            self._rx_buf.extend(chunk)

    def recv_json(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        return json.loads(self.recv_text(timeout=timeout))

    def recv_until_type(
        self, expected_type: str, timeout: float = 3.0, collected: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"Timed out waiting for WebSocket event type={expected_type!r}")
            msg = self.recv_json(timeout=rem)
            if collected is not None:
                collected.append(msg)
            if msg.get("type") == expected_type:
                return msg

    def _next_req_id(self) -> int:
        with self._tx_lock:
            self._req_id += 1
            return self._req_id

    def authenticate(
        self,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        account_id: int = 0,
    ) -> int:
        eff_key = api_key if api_key is not None else self.api_key
        eff_sec = api_secret if api_secret is not None else self.api_secret
        if not eff_key or not eff_sec:
            raise ValueError("authenticate requires api_key and api_secret")
        rid = self._next_req_id()
        ts_ms, nonce = _next_hmac_timestamp_and_nonce(eff_key, "WS", "/ws", "")
        sig = compute_hmac_signature(eff_sec, ts_ms, "WS", "/ws", "")
        msg: Dict[str, Any] = {
            "op": "auth",
            "req_id": rid,
            "api_key": eff_key,
            "timestamp_ms": ts_ms,
            "nonce": nonce,
            "signature": sig,
        }
        if account_id > 0:
            msg["account_id"] = account_id
        self.send_json(msg)
        return rid

    def subscribe(self, market_id: int, account_id: int = 0) -> None:
        self.send_json({"op": "subscribe", "market_id": market_id, "account_id": account_id})

    def ping(self, client_ts: int = 0) -> None:
        self.send_json({"op": "ping", "client_ts": client_ts})

    def withdraw(
        self,
        account_id: int,
        amount: int,
        asset_id: int = 0,
        recipient_eth_address: str = "",
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "withdraw",
            "req_id": rid,
            "account_id": account_id,
            "asset_id": asset_id,
            "amount": amount,
        }
        if recipient_eth_address:
            payload["recipient_eth_address"] = recipient_eth_address
        self.send_json(payload)
        return rid

    def place_order(
        self,
        account_id: int,
        market_id: int,
        side: str,
        price_ticks: int,
        qty_lots: int,
        tif: str = "gtc",
        reduce_only: bool = False,
        is_market: bool = False,
        stp: str = "cancel_resting",
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        client_tag: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp_decrement_and_cancel: bool = False,
        priority_fee_ppm: int = 0,
    ) -> int:
        prio_ppm_i = _validate_priority_fee_ppm(priority_fee_ppm)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "order",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "tif": tif,
            "stp": stp,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
            "reduce_only": reduce_only,
            "is_market": is_market,
        }
        if stp_decrement_and_cancel:
            payload["stp_decrement_and_cancel"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if primary_peg:
            payload["primary_peg"] = True
        if midpoint_peg:
            payload["midpoint_peg"] = True
        if mark_peg:
            payload["mark_peg"] = True
        if trailing_peg:
            payload["trailing_peg"] = True
        if dark_midpoint:
            payload["dark_midpoint"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if min_qty_lots > 0:
            payload["min_qty_lots"] = min_qty_lots
        if display_qty_lots > 0:
            payload["display_qty_lots"] = display_qty_lots
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if prio_ppm_i > 0:
            payload["priority_fee_ppm"] = prio_ppm_i
        self.send_json(payload)
        return rid

    submit_order = place_order

    def preview_order(
        self,
        account_id: int,
        market_id: int,
        side: str,
        price_ticks: int,
        qty_lots: int,
        tif: str = "gtc",
        reduce_only: bool = False,
        is_market: bool = False,
        stp: str = "cancel_resting",
        post_only_slide: bool = False,
        min_qty_lots: int = 0,
        client_tag: int = 0,
        primary_peg: bool = False,
        midpoint_peg: bool = False,
        margin_spot: bool = False,
        display_qty_lots: int = 0,
        dark_midpoint: bool = False,
        auto_skew_ticks: int = 0,
        peg_offset_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        mark_peg: bool = False,
        auto_flip_ticks: int = 0,
        trailing_peg: bool = False,
        stp_decrement_and_cancel: bool = False,
        priority_fee_ppm: int = 0,
    ) -> int:
        prio_ppm_i = _validate_priority_fee_ppm(priority_fee_ppm)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "order_preview",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "tif": tif,
            "stp": stp,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
            "reduce_only": reduce_only,
            "is_market": is_market,
        }
        if stp_decrement_and_cancel:
            payload["stp_decrement_and_cancel"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if primary_peg:
            payload["primary_peg"] = True
        if midpoint_peg:
            payload["midpoint_peg"] = True
        if mark_peg:
            payload["mark_peg"] = True
        if trailing_peg:
            payload["trailing_peg"] = True
        if dark_midpoint:
            payload["dark_midpoint"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if min_qty_lots > 0:
            payload["min_qty_lots"] = min_qty_lots
        if display_qty_lots > 0:
            payload["display_qty_lots"] = display_qty_lots
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if prio_ppm_i > 0:
            payload["priority_fee_ppm"] = prio_ppm_i
        self.send_json(payload)
        return rid

    def modify_order(
        self,
        account_id: int,
        market_id: int,
        order_id: int,
        price_ticks: int,
        qty_lots: int,
        keep_priority: bool = False,
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "modify",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
            "order_id": order_id,
            "price_ticks": price_ticks,
            "qty_lots": qty_lots,
        }
        if keep_priority:
            payload["keep_priority"] = True
        self.send_json(payload)
        return rid

    def cancel_order(self, account_id: int, market_id: int, order_id: int) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "cancel",
                "req_id": rid,
                "account_id": account_id,
                "market_id": market_id,
                "order_id": order_id,
            }
        )
        return rid

    def cancel_all(
        self,
        account_id: int,
        market_id: int = 0,
        client_tag_filter: int = 0,
        market_bitmask: int = 0,
        side_filter: str = "",
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "cancel_all",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
        }
        if client_tag_filter > 0:
            payload["client_tag_filter"] = client_tag_filter
        if market_bitmask > 0:
            payload["market_bitmask"] = market_bitmask
        if side_filter:
            payload["side"] = side_filter
        self.send_json(payload)
        return rid

    def quote_replace(
        self,
        account_id: int,
        market_id: int,
        bid_price_ticks: int,
        bid_qty_lots: int,
        ask_price_ticks: int,
        ask_qty_lots: int,
        tif: str = "gtc",
        stp: str = "cancel_resting",
        post_only_slide: bool = False,
        margin_spot: bool = False,
        client_tag: int = 0,
        auto_skew_ticks: int = 0,
        oco_linked: bool = False,
        max_lifetime_wal_seqs: int = 0,
        jit_elastic_mult: int = 0,
        auto_flip_ticks: int = 0,
        quote_peg_mode: int = 0,
        peg_offset_ticks: int = 0,
        ladder_by_tag: bool = False,
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "quote",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
            "bid_price_ticks": bid_price_ticks,
            "bid_qty_lots": bid_qty_lots,
            "ask_price_ticks": ask_price_ticks,
            "ask_qty_lots": ask_qty_lots,
            "tif": tif,
            "stp": stp,
        }
        if ladder_by_tag:
            payload["ladder_by_tag"] = True
        if post_only_slide:
            payload["post_only_slide"] = True
        if margin_spot:
            payload["margin_spot"] = True
        if auto_skew_ticks > 0:
            payload["auto_skew_ticks"] = auto_skew_ticks
        if auto_flip_ticks > 0:
            payload["auto_flip_ticks"] = auto_flip_ticks
        if quote_peg_mode > 0:
            payload["quote_peg_mode"] = quote_peg_mode
        if peg_offset_ticks != 0:
            payload["peg_offset_ticks"] = peg_offset_ticks
        if oco_linked:
            payload["oco_linked"] = True
        if max_lifetime_wal_seqs > 0:
            payload["max_lifetime_wal_seqs"] = max_lifetime_wal_seqs
        if jit_elastic_mult > 1:
            payload["jit_elastic_mult"] = jit_elastic_mult
        if client_tag > 0:
            payload["client_tag"] = client_tag
        self.send_json(payload)
        return rid

    two_sided_quote_replace = quote_replace

    def auto_delta_hedge(
        self,
        account_id: int,
        base_asset_id: int = 0,
        preferred_market_id: int = 0,
        max_slippage_bps: int = 200,
        max_qty_lots: int = 0,
        margin_spot: bool = False,
        stp: str = "cancel_resting",
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "auto_delta_hedge",
            "req_id": rid,
            "account_id": account_id,
            "base_asset_id": base_asset_id,
            "preferred_market_id": preferred_market_id,
            "max_slippage_bps": max_slippage_bps,
            "max_qty_lots": max_qty_lots,
            "margin_spot": margin_spot,
            "stp": stp,
        }
        self.send_json(payload)
        return rid

    delta_hedge = auto_delta_hedge

    def link_sub_account(
        self,
        master_account_id: int,
        sub_account_id: int,
        max_guaranty_usd_micro: int = 0,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "prime_link_sub",
                "req_id": rid,
                "master_account_id": master_account_id,
                "sub_account_id": sub_account_id,
                "max_guaranty_usd_micro": max_guaranty_usd_micro,
            }
        )
        return rid

    def prime_internal_transfer(
        self,
        from_account_id: int,
        to_account_id: int,
        amount: int,
        asset_id: int = 0,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "prime_transfer",
                "req_id": rid,
                "from_account_id": from_account_id,
                "to_account_id": to_account_id,
                "asset_id": asset_id,
                "amount": amount,
            }
        )
        return rid

    prime_transfer = prime_internal_transfer

    def auto_cross_arb(
        self,
        account_id: int,
        primary_market_id: int,
        secondary_market_id: int = 0,
        max_qty_lots: int = 0,
        min_profit_micro: int = 0,
        margin_spot: bool = False,
        stp: str = "cancel_resting",
        express_surplus_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "auto_cross_arb",
            "req_id": rid,
            "account_id": account_id,
            "primary_market_id": primary_market_id,
            "secondary_market_id": secondary_market_id,
            "max_qty_lots": max_qty_lots,
            "min_profit_micro": min_profit_micro,
            "margin_spot": margin_spot,
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    def execute_spread(
        self,
        account_id: int,
        leg1_market_id: int,
        leg1_side: str,
        leg1_price_ticks: int,
        leg1_qty_lots: int,
        leg2_market_id: int,
        leg2_side: str,
        leg2_price_ticks: int,
        leg2_qty_lots: int,
        leg1_reduce_only: bool = False,
        leg1_is_market: bool = False,
        leg2_reduce_only: bool = False,
        leg2_is_market: bool = False,
        stp: str = "cancel_resting",
        margin_spot: bool = False,
        express_surplus_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "spread",
            "req_id": rid,
            "account_id": account_id,
            "leg1_market_id": leg1_market_id,
            "leg1_side": leg1_side,
            "leg1_price_ticks": leg1_price_ticks,
            "leg1_qty_lots": leg1_qty_lots,
            "leg1_reduce_only": leg1_reduce_only,
            "leg1_is_market": leg1_is_market,
            "leg2_market_id": leg2_market_id,
            "leg2_side": leg2_side,
            "leg2_price_ticks": leg2_price_ticks,
            "leg2_qty_lots": leg2_qty_lots,
            "leg2_reduce_only": leg2_reduce_only,
            "leg2_is_market": leg2_is_market,
            "stp": stp,
        }
        if margin_spot:
            payload["margin_spot"] = True
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    def execute_basket(
        self,
        account_id: int,
        legs: List[Dict[str, Any]],
        stp: str = "cancel_resting",
        margin_spot: bool = False,
        client_tag: int = 0,
        express_surplus_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "basket",
            "req_id": rid,
            "account_id": account_id,
            "legs": legs,
            "stp": stp,
        }
        if margin_spot:
            payload["margin_spot"] = True
        if client_tag > 0:
            payload["client_tag"] = client_tag
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    basket = execute_basket

    def distribute_yield(self, reward_usd_micro: int, sponsor_account_id: int = 0) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "distribute_yield",
                "req_id": rid,
                "reward_usd_micro": reward_usd_micro,
                "sponsor_account_id": sponsor_account_id,
            }
        )
        return rid

    def set_protocol_account(self, protocol_fee_account_id: int) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "protocol_config",
                "req_id": rid,
                "protocol_fee_account_id": int(protocol_fee_account_id),
            }
        )
        return rid

    protocol_config = set_protocol_account

    def resolve_claim(self, market_id: int, payout_ticks: int) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "resolve_claim",
                "req_id": rid,
                "market_id": market_id,
                "payout_ticks": payout_ticks,
            }
        )
        return rid

    def create_market(
        self,
        account_id: int,
        symbol: str,
        kind: str = "spot",
        **kwargs: Any,
    ) -> int:
        rid = self._next_req_id()
        opts = dict(kwargs)
        eff_aid = opts.pop("creator_account_id", account_id)
        payload: Dict[str, Any] = {
            "op": "create_market",
            "req_id": rid,
            "account_id": eff_aid,
            "symbol": symbol,
            "kind": kind,
        }
        payload.update(opts)
        self.send_json(payload)
        return rid

    def mint_redeem(
        self,
        account_id: int,
        market_id: int,
        side: str,
        qty_lots: int,
        limit_cost_or_payout_micro: int = 0,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "mint_redeem",
                "req_id": rid,
                "account_id": account_id,
                "market_id": market_id,
                "side": side,
                "qty_lots": qty_lots,
                "limit_cost_or_payout_micro": limit_cost_or_payout_micro,
            }
        )
        return rid

    def flash_arbitrage(
        self,
        account_id: int,
        market_id: int,
        side: str,
        qty_lots: int,
        limit_price_ticks: int = 0,
        min_profit_micro: int = 0,
        is_market: bool = False,
        stp: str = "cancel_resting",
        express_surplus_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_express_surplus_bid_bps(express_surplus_bid_bps)
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "flash_arb",
            "req_id": rid,
            "account_id": account_id,
            "market_id": market_id,
            "side": side,
            "qty_lots": qty_lots,
            "limit_price_ticks": limit_price_ticks,
            "min_profit_micro": min_profit_micro,
            "is_market": is_market,
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["express_surplus_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    def liquidate(
        self,
        liquidator_account_id: int,
        target_account_id: int,
        market_id: int,
        partial_lots: int = 0,
        allow_l3_offload: bool = True,
        hedge_margin_spot: bool = False,
        stp: str = "cancel_resting",
        bounty_rebate_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if bid_bps_i > 0 and int(liquidator_account_id) == int(target_account_id):
            raise ValueError("bounty_rebate_bid_bps > 0 cannot be used with self-knockout")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "liquidate",
            "req_id": rid,
            "liquidator_account_id": liquidator_account_id,
            "target_account_id": target_account_id,
            "market_id": market_id,
            "allow_l3_offload": bool(allow_l3_offload),
            "hedge_margin_spot": bool(hedge_margin_spot),
            "stp": str(stp),
        }
        if partial_lots > 0:
            payload["partial_lots"] = partial_lots
        if bid_bps_i > 0:
            payload["bounty_rebate_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    def set_knockout(
        self,
        account_id: int,
        market_id: int,
        knockout_price_ticks: int,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "knockout",
                "req_id": rid,
                "account_id": account_id,
                "market_id": market_id,
                "knockout_price_ticks": knockout_price_ticks,
            }
        )
        return rid

    def set_drawdown_stop(
        self,
        account_id: int,
        stop_equity_usd_micro: int,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "drawdown_stop",
                "req_id": rid,
                "account_id": account_id,
                "stop_equity_usd_micro": stop_equity_usd_micro,
            }
        )
        return rid

    def auto_liquidate(
        self,
        liquidator_account_id: int,
        market_id: int = 0,
        target_account_id: int = 0,
        max_lots: int = 0,
        min_bounty_micro: int = 0,
        flash_offload_to_book: bool = True,
        stp: str = "cancel_resting",
        hedge_margin_spot: bool = False,
        bounty_rebate_bid_bps: int = 0,
    ) -> int:
        bid_bps_i = _validate_bounty_rebate_bid_bps(bounty_rebate_bid_bps)
        if bid_bps_i > 0 and int(target_account_id) != 0 and int(target_account_id) == int(liquidator_account_id):
            raise ValueError("Cannot submit bounty_rebate_bid_bps against own account_id")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "auto_liquidate",
            "req_id": rid,
            "liquidator_account_id": liquidator_account_id,
            "market_id": market_id,
            "target_account_id": target_account_id,
            "max_qty_lots": max_lots,
            "min_bounty_micro": min_bounty_micro,
            "auto_offload_to_book": flash_offload_to_book,
            "hedge_margin_spot": bool(hedge_margin_spot),
            "stp": stp,
        }
        if bid_bps_i > 0:
            payload["bounty_rebate_bid_bps"] = bid_bps_i
        self.send_json(payload)
        return rid

    auto_liquidation_sweep = auto_liquidate

    def refund_voided_withdrawal(
        self,
        withdrawal_id: int,
        account_id: int = 0,
        asset_id: Optional[int] = None,
        amount: int = 0,
        tx_hash: str = "",
        deposit_seq: int = 0,
        event_ref: str = "",
    ) -> int:
        wid_i = int(withdrawal_id)
        acct_i = int(account_id)
        amt_i = int(amount)
        dseq_i = int(deposit_seq)
        if wid_i <= 0:
            raise ValueError("withdrawal_id must be > 0")
        if acct_i < 0 or acct_i > 0xFFFFFFFF:
            raise ValueError("account_id must be in [0, 2^32 - 1]")
        if amt_i < 0 or dseq_i < 0:
            raise ValueError("amount and deposit_seq must be >= 0")
        aid_i: Optional[int] = None
        if asset_id is not None:
            aid_i = int(asset_id)
            if not (0 <= aid_i <= 255):
                raise ValueError("asset_id must be in [0, 255]")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "refund_voided",
            "req_id": rid,
            "withdrawal_id": wid_i,
        }
        if acct_i > 0:
            payload["account_id"] = acct_i
        if aid_i is not None:
            payload["asset_id"] = aid_i
        if amt_i > 0:
            payload["amount"] = amt_i
        if dseq_i > 0:
            payload["deposit_seq"] = dseq_i
        if tx_hash:
            payload["tx_hash"] = str(tx_hash)
        if event_ref:
            payload["event_ref"] = str(event_ref)
        self.send_json(payload)
        return rid

    def credit_onchain_insurance(
        self,
        amount: Optional[int] = None,
        funder: str = "",
        event_ref: str = "",
        *,
        amount_micro: Optional[int] = None,
    ) -> int:
        eff_amt = amount_micro if amount is None else amount
        if eff_amt is None:
            raise ValueError("credit_onchain_insurance requires amount or amount_micro")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "credit_onchain_insurance",
            "req_id": rid,
            "amount": amt_i,
        }
        if funder:
            payload["funder"] = str(funder)
        if event_ref:
            payload["event_ref"] = str(event_ref)
        self.send_json(payload)
        return rid

    def absorb_onchain_custody_loss(
        self,
        amount: Optional[int] = None,
        pool: str = "trader_margin",
        event_ref: str = "",
        *,
        amount_micro: Optional[int] = None,
    ) -> int:
        eff_amt = amount_micro if amount is None else amount
        if eff_amt is None:
            raise ValueError("absorb_onchain_custody_loss requires amount or amount_micro")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        pool_s = str(pool) if str(pool) else "trader_margin"
        if pool_s not in ("trader_margin", "insurance"):
            raise ValueError("pool must be 'trader_margin' or 'insurance'")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "absorb_custody_loss",
            "req_id": rid,
            "amount": amt_i,
            "pool": pool_s,
        }
        if event_ref:
            payload["event_ref"] = str(event_ref)
        self.send_json(payload)
        return rid

    def recover_custody_loss(
        self,
        amount_micro: Optional[int] = None,
        event_ref: str = "",
        *,
        amount: Optional[int] = None,
    ) -> int:
        eff_amt = amount if amount_micro is None else amount_micro
        if eff_amt is None:
            raise ValueError("recover_custody_loss requires amount_micro or amount")
        amt_i = int(eff_amt)
        if not (1 <= amt_i <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("amount must be in [1, 2^63 - 1]")
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "recover_custody_loss",
            "req_id": rid,
            "amount": amt_i,
        }
        if event_ref:
            payload["event_ref"] = str(event_ref)
        self.send_json(payload)
        return rid

    recover_onchain_custody_loss = recover_custody_loss

    def register_spot_asset(
        self,
        asset_id: int,
        symbol: str,
        decimals: int = 18,
        lot_decimals: int = 4,
        max_supply_lots: int = 0,
    ) -> int:
        aid_i = int(asset_id)
        max_sup_i = int(max_supply_lots)
        if not (1 <= aid_i <= 255):
            raise ValueError("asset_id must be in [1, 255]")
        if not (0 <= max_sup_i <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("max_supply_lots must be in [0, 2^64 - 1]")
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "register_spot_asset",
                "req_id": rid,
                "asset_id": aid_i,
                "symbol": str(symbol),
                "decimals": int(decimals),
                "lot_decimals": int(lot_decimals),
                "max_supply_lots": max_sup_i,
            }
        )
        return rid

    def revoke_api_key(self, api_key: str) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "revoke_key",
                "req_id": rid,
                "api_key": str(api_key),
            }
        )
        return rid

    def save_wal_snapshot(self, snapshot_path: str = "") -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "save_wal_snapshot",
            "req_id": rid,
        }
        if snapshot_path:
            payload["snapshot_path"] = snapshot_path
        self.send_json(payload)
        return rid

    def sweep_excess_insurance_fund(
        self,
        reserve_floor_usd_micro: int = 0,
        max_sweep_usd_micro: int = 0,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "sweep_insurance",
                "req_id": rid,
                "reserve_floor_usd_micro": max(0, int(reserve_floor_usd_micro)),
                "max_sweep_usd_micro": max(0, int(max_sweep_usd_micro)),
            }
        )
        return rid

    sweep_insurance = sweep_excess_insurance_fund

    def enable_macro_markets(self) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "enable_macro_markets",
                "req_id": rid,
            }
        )
        return rid

    def enable_basis_spread_markets(self) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "enable_basis_spread_markets",
                "req_id": rid,
            }
        )
        return rid

    enable_basis_spreads = enable_basis_spread_markets

    def supercharge_volume(
        self,
        maker_fee_bps: int = 0,
        taker_fee_bps: int = 0,
        organic_turnover_velocity_mult: int = 1000000,
        auto_yield_drip_on_mark: bool = True,
        enable_macro_and_basis: bool = True,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "supercharge_volume",
                "req_id": rid,
                "maker_fee_bps": int(maker_fee_bps),
                "taker_fee_bps": int(taker_fee_bps),
                "organic_turnover_velocity_mult": int(organic_turnover_velocity_mult),
                "auto_yield_drip_on_mark": bool(auto_yield_drip_on_mark),
                "enable_macro_and_basis": bool(enable_macro_and_basis),
            }
        )
        return rid

    def set_auto_yield_drip(self, enabled: bool = True) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "auto_yield_drip",
                "req_id": rid,
                "enabled": bool(enabled),
            }
        )
        return rid

    def set_market_status(
        self,
        market_id: int,
        status: int | str,
        cancel_resting_orders: bool = False,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "set_market_status",
                "req_id": rid,
                "market_id": int(market_id),
                "status": status if isinstance(status, str) else int(status),
                "cancel_resting_orders": bool(cancel_resting_orders),
            }
        )
        return rid

    def update_market_config(
        self,
        market_id: int = 0,
        maker_fee_bps: Optional[int] = None,
        taker_fee_bps: Optional[int] = None,
        imr_bps: Optional[int] = None,
        mmr_bps: Optional[int] = None,
        liq_penalty_bps: Optional[int] = None,
        max_order_lots: Optional[int] = None,
        max_open_interest_notional_micro: Optional[int] = None,
        all_markets: bool = False,
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {
            "op": "update_market_config",
            "req_id": rid,
            "market_id": int(market_id),
        }
        if all_markets:
            payload["all_markets"] = True
        if maker_fee_bps is not None:
            payload["maker_fee_bps"] = int(maker_fee_bps)
        if taker_fee_bps is not None:
            payload["taker_fee_bps"] = int(taker_fee_bps)
        if imr_bps is not None:
            payload["imr_bps"] = int(imr_bps)
        if mmr_bps is not None:
            payload["mmr_bps"] = int(mmr_bps)
        if liq_penalty_bps is not None:
            payload["liq_penalty_bps"] = int(liq_penalty_bps)
        if max_order_lots is not None:
            payload["max_order_lots"] = int(max_order_lots)
        if max_open_interest_notional_micro is not None:
            payload["max_open_interest_notional_micro"] = int(max_open_interest_notional_micro)
        self.send_json(payload)
        return rid

    def stage_eigen_factor_bank(
        self,
        factor_shock_bps: List[int],
        idiosyncratic_residual_rate_bps: int = 500,
        activate_immediately: bool = False,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "stage_eigen_bank",
                "req_id": rid,
                "factor_shock_bps": [int(x) for x in factor_shock_bps],
                "idiosyncratic_residual_rate_bps": int(idiosyncratic_residual_rate_bps),
                "activate_immediately": bool(activate_immediately),
            }
        )
        return rid

    def configure_payout_preferences(
        self,
        account_id: int,
        payout_asset_id: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "payout_preferences",
                "req_id": rid,
                "account_id": int(account_id),
                "payout_asset_id": int(payout_asset_id),
                "payout_mode_flags": int(payout_mode_flags),
                "payout_target_account_id": int(payout_target_account_id),
                "auto_repay_borrow": bool(auto_repay_borrow),
                "compound_bonding_curve": bool(compound_bonding_curve),
                "auto_compound_quotes": bool(auto_compound_quotes),
            }
        )
        return rid

    def configure_payout_portfolio(
        self,
        account_id: int,
        primary_asset_id: int = 0,
        primary_share_bps: int = 10_000,
        secondary_asset_id: int = 0,
        secondary_share_bps: int = 0,
        tertiary_asset_id: int = 0,
        tertiary_share_bps: int = 0,
        payout_mode_flags: int = 0,
        payout_target_account_id: int = 0,
        max_margin_util_bps: int = 0,
        max_price_ticks: int = 0,
        auto_repay_borrow: bool = False,
        compound_bonding_curve: bool = False,
        auto_compound_quotes: bool = False,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "payout_portfolio",
                "req_id": rid,
                "account_id": int(account_id),
                "primary_asset_id": int(primary_asset_id),
                "primary_share_bps": int(primary_share_bps),
                "secondary_asset_id": int(secondary_asset_id),
                "secondary_share_bps": int(secondary_share_bps),
                "tertiary_asset_id": int(tertiary_asset_id),
                "tertiary_share_bps": int(tertiary_share_bps),
                "payout_mode_flags": int(payout_mode_flags),
                "payout_target_account_id": int(payout_target_account_id),
                "max_margin_util_bps": int(max_margin_util_bps),
                "max_price_ticks": int(max_price_ticks),
                "auto_repay_borrow": bool(auto_repay_borrow),
                "compound_bonding_curve": bool(compound_bonding_curve),
                "auto_compound_quotes": bool(auto_compound_quotes),
            }
        )
        return rid

    def configure_auto_repo_scheduler(
        self,
        epoch_marks: int,
        clock_market_id: int = 0,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "auto_repo_config",
                "req_id": rid,
                "epoch_marks": int(epoch_marks),
                "clock_market_id": int(clock_market_id),
            }
        )
        return rid

    def configure_war_hardening(
        self,
        strict_zero_trading_fee_lock: Optional[bool] = None,
        zero_fee_skim_elimination: Optional[bool] = None,
        max_live_mark_step_bps: Optional[int] = None,
        knockout_confirm_marks: Optional[int] = None,
        enforce_collateral_order_cap: Optional[bool] = None,
        rotate_itch_salt_on_repo_epoch: Optional[bool] = None,
        bbo_uptime_seniority_enabled: Optional[bool] = None,
        segmented_public_fee_schedule: Optional[bool] = None,
    ) -> int:
        rid = self._next_req_id()
        msg: Dict[str, Any] = {
            "op": "war_hardening",
            "req_id": rid,
        }
        if strict_zero_trading_fee_lock is not None:
            msg["strict_zero_trading_fee_lock"] = bool(strict_zero_trading_fee_lock)
        if zero_fee_skim_elimination is not None:
            msg["zero_fee_skim_elimination"] = bool(zero_fee_skim_elimination)
        if max_live_mark_step_bps is not None:
            msg["max_live_mark_step_bps"] = int(max_live_mark_step_bps)
        if knockout_confirm_marks is not None:
            msg["knockout_confirm_marks"] = int(knockout_confirm_marks)
        if enforce_collateral_order_cap is not None:
            msg["enforce_collateral_order_cap"] = bool(enforce_collateral_order_cap)
        if rotate_itch_salt_on_repo_epoch is not None:
            msg["rotate_itch_salt_on_repo_epoch"] = bool(rotate_itch_salt_on_repo_epoch)
        if bbo_uptime_seniority_enabled is not None:
            msg["bbo_uptime_seniority_enabled"] = bool(bbo_uptime_seniority_enabled)
        if segmented_public_fee_schedule is not None:
            msg["segmented_public_fee_schedule"] = bool(segmented_public_fee_schedule)
        self.send_json(msg)
        return rid

    def fund_market_liquidity_vault(
        self,
        sponsor_account_id: int,
        market_id: int,
        asset_id: int,
        amount: int,
        duration_marks: int,
        maker_share_bps: int = 7_500,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "fund_market_vault",
                "req_id": rid,
                "sponsor_account_id": int(sponsor_account_id),
                "market_id": int(market_id),
                "asset_id": int(asset_id),
                "amount": int(amount),
                "duration_marks": int(duration_marks),
                "maker_share_bps": int(maker_share_bps),
            }
        )
        return rid

    def configure_default_trader_incentives(
        self,
        enabled: Optional[bool] = None,
        pillar_mask: Optional[int] = None,
        supercharge_volume: Optional[bool] = None,
        auto_yield_drip: Optional[bool] = None,
        auto_repo: Optional[bool] = None,
        notional_bbo_yield: Optional[bool] = None,
        two_sided_bonus: Optional[bool] = None,
        claim_collateral: Optional[bool] = None,
        itch_anonymize_accounts: Optional[bool] = None,
        enable_macro_and_basis: Optional[bool] = None,
        repo_auto_epoch_marks: Optional[int] = None,
        two_sided_bbo_bonus_bps: Optional[int] = None,
        claim_collateral_weight_bps: Optional[int] = None,
    ) -> int:
        rid = self._next_req_id()
        payload: Dict[str, Any] = {"op": "default_incentives", "req_id": rid}
        if enabled is not None:
            payload["enabled"] = bool(enabled)
        if pillar_mask is not None:
            payload["pillar_mask"] = int(pillar_mask)
        if supercharge_volume is not None:
            payload["supercharge_volume"] = bool(supercharge_volume)
        if auto_yield_drip is not None:
            payload["auto_yield_drip"] = bool(auto_yield_drip)
        if auto_repo is not None:
            payload["auto_repo"] = bool(auto_repo)
        if notional_bbo_yield is not None:
            payload["notional_bbo_yield"] = bool(notional_bbo_yield)
        if two_sided_bonus is not None:
            payload["two_sided_bonus"] = bool(two_sided_bonus)
        if claim_collateral is not None:
            payload["claim_collateral"] = bool(claim_collateral)
        if itch_anonymize_accounts is not None:
            payload["itch_anonymize_accounts"] = bool(itch_anonymize_accounts)
        if enable_macro_and_basis is not None:
            payload["enable_macro_and_basis"] = bool(enable_macro_and_basis)
        if repo_auto_epoch_marks is not None:
            payload["repo_auto_epoch_marks"] = int(repo_auto_epoch_marks)
        if two_sided_bbo_bonus_bps is not None:
            payload["two_sided_bbo_bonus_bps"] = int(two_sided_bbo_bonus_bps)
        if claim_collateral_weight_bps is not None:
            payload["claim_collateral_weight_bps"] = int(claim_collateral_weight_bps)
        self.send_json(payload)
        return rid

    def subscribe_express_port(
        self,
        account_id: int,
        duration_epochs: int = 1,
        max_fee_usd_micro: int = 0,
    ) -> int:
        dur_i = int(duration_epochs)
        max_fee_i = int(max_fee_usd_micro)
        if not (1 <= dur_i <= MAX_EXPRESS_PORT_LEASE_EPOCHS):
            raise ValueError(
                f"duration_epochs {dur_i} out of [1, {MAX_EXPRESS_PORT_LEASE_EPOCHS}]"
            )
        if max_fee_i < 0:
            raise ValueError("max_fee_usd_micro must be >= 0")
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "subscribe_express_port",
                "req_id": rid,
                "account_id": int(account_id),
                "duration_epochs": dur_i,
                "max_fee_usd_micro": max_fee_i,
            }
        )
        return rid

    def set_express_port_fee_per_epoch(
        self,
        fee_per_epoch_usd_micro: int,
    ) -> int:
        fee_i = int(fee_per_epoch_usd_micro)
        if not (
            MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
            <= fee_i
            <= MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO
        ):
            raise ValueError(
                f"fee_per_epoch_usd_micro {fee_i} out of "
                f"[{MIN_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}, {MAX_EXPRESS_PORT_FEE_PER_EPOCH_USD_MICRO}]"
            )
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "set_express_port_fee",
                "req_id": rid,
                "fee_per_epoch_usd_micro": fee_i,
            }
        )
        return rid

    def distribute_base_asset_yield(
        self,
        sponsor_account_id: int,
        base_asset_id: int,
        total_lots: int,
    ) -> int:
        rid = self._next_req_id()
        self.send_json(
            {
                "op": "distribute_base_yield",
                "req_id": rid,
                "sponsor_account_id": int(sponsor_account_id),
                "base_asset_id": int(base_asset_id),
                "total_lots": int(total_lots),
            }
        )
        return rid

    def send_close_frame(self) -> None:
        with self._tx_lock:
            if self._sock is not None:
                try:
                    if self._sock.fileno() != -1:
                        self._sock.sendall(self._encode_masked_client_frame(0x8, b""))
                except OSError:
                    self.close()

    def close(self) -> None:
        with self._tx_lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None


# =============================================================================
# 64-Byte Binary Tick-by-Tick L3 Market-Data Feed (`ArenaITCH` v1) Client & Book
# =============================================================================
ARENA_ITCH_MAGIC = 0x4149  # "AI"
ARENA_ITCH_VERSION = 0x01
ARENA_ITCH_BYTES = 64
ARENA_ITCH_REQ_MAGIC = 0x41495251  # "AIRQ"
ARENA_ITCH_REQ_BYTES = 16

ITCH_REQ_FLAG_REPLAY_FROM_SEQ = 1 << 0
ITCH_REQ_FLAG_FULL_SNAPSHOT = 1 << 1


class ItchEventType(IntEnum):
    ORDER_ADDED = 0x01
    ORDER_EXECUTED = 0x02
    ORDER_MODIFIED = 0x03
    ORDER_DELETED = 0x04
    MARK_AND_FUNDING = 0x05
    SNAPSHOT_BEGIN = 0x06
    SNAPSHOT_ORDER = 0x07
    SNAPSHOT_END = 0x08
    LEDGER_CHECKPOINT = 0x09
    MARKET_DIRECTORY = 0x0A
    HEARTBEAT = 0x0F


class ItchDeleteReason(IntEnum):
    USER_CANCEL = 0
    SELF_TRADE_PREVENTION = 1
    CANCEL_ALL_OR_DISCONNECT = 2
    LIQUIDATION = 3


def compute_itch_checksum64(raw: bytes | bytearray | memoryview) -> int:
    """Bit-exact SipHash-2-4 over bytes [0..55] of a 64-byte `ArenaITCH` v1 frame."""
    if len(raw) < 56:
        raise ValueError("ArenaITCH frame must have at least 56 header+payload bytes")
    k0 = 0x4152_454E_4149_5443  # "ARENAITC"
    k1 = 0x485F_5631_5F4D_4143  # "H_V1_MAC"
    v0 = (k0 ^ 0x736F6D6570736575) & MASK64
    v1 = (k1 ^ 0x646F72616E646F6D) & MASK64
    v2 = (k0 ^ 0x6C7967656E657261) & MASK64
    v3 = (k1 ^ 0x7465646279746573) & MASK64

    words = struct.unpack_from(">7Q", raw, 0)
    for m in words:
        v3 ^= m
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= m

    len_b = (56 << 56) & MASK64
    v3 ^= len_b
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= len_b

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


@dataclass
class ItchMarketDirectoryEntry:
    market_id: int
    symbol: str
    market_kind: int
    sub_kind: int
    base_asset_id: int
    inst_flags: int
    ref_market_1: int
    ref_market_2: int
    imr_bps: int
    mark_price_ticks: int


@dataclass
class ArenaItchEvent:
    event_type: ItchEventType = ItchEventType.HEARTBEAT
    market_id: int = 0
    side: OrderSide = OrderSide.BID
    flags: int = 0
    itch_seq: int = 0
    wal_seq: int = 0
    order_id: int = 0
    price_ticks: int = 0
    qty_lots: int = 0
    aux_u64: int = 0

    @property
    def reduce_only(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def delete_reason(self) -> ItchDeleteReason:
        return ItchDeleteReason((self.flags >> 2) & 0x3)

    def extract_ledger_checkpoint_hash(self) -> bytes:
        return struct.pack(
            ">QqQQ",
            self.order_id & MASK64,
            self.price_ticks,
            self.qty_lots & MASK64,
            self.aux_u64 & MASK64,
        )

    def extract_ledger_checkpoint_hash_hex(self) -> str:
        return "0x" + self.extract_ledger_checkpoint_hash().hex()

    def unpack_market_directory(self) -> ItchMarketDirectoryEntry:
        market_kind = self.flags & 0x07
        sub_kind = (self.flags >> 3) & 0x1F
        base_asset_id = (self.aux_u64 >> 56) & 0xFF
        inst_flags = (self.aux_u64 >> 48) & 0xFF
        ref_market_1 = (self.aux_u64 >> 32) & 0xFFFF
        ref_market_2 = (self.aux_u64 >> 16) & 0xFFFF
        imr_bps = self.aux_u64 & 0xFFFF
        raw_sym = struct.pack(">QQ", self.order_id & MASK64, self.qty_lots & MASK64)
        nul_pos = raw_sym.find(b"\x00")
        sym_bytes = raw_sym if nul_pos < 0 else raw_sym[:nul_pos]
        symbol = sym_bytes.decode("ascii", errors="replace")
        return ItchMarketDirectoryEntry(
            market_id=self.market_id,
            symbol=symbol,
            market_kind=market_kind,
            sub_kind=sub_kind,
            base_asset_id=base_asset_id,
            inst_flags=inst_flags,
            ref_market_1=ref_market_1,
            ref_market_2=ref_market_2,
            imr_bps=imr_bps,
            mark_price_ticks=self.price_ticks,
        )

    @classmethod
    def make_market_directory(
        cls,
        market_id: int,
        wal_seq: int,
        market_kind: int,
        sub_kind: int,
        base_asset_id: int,
        inst_flags: int,
        ref_market_1: int,
        ref_market_2: int,
        imr_bps: int,
        mark_price_ticks: int,
        symbol: str,
        itch_seq: int = 0,
    ) -> "ArenaItchEvent":
        sym_raw = symbol.encode("ascii")[:16].ljust(16, b"\x00")
        s_hi, s_lo = struct.unpack(">QQ", sym_raw)
        flags = (market_kind & 0x07) | ((sub_kind & 0x1F) << 3)
        aux_u64 = (
            ((base_asset_id & 0xFF) << 56)
            | ((inst_flags & 0xFF) << 48)
            | ((ref_market_1 & 0xFFFF) << 32)
            | ((ref_market_2 & 0xFFFF) << 16)
            | (imr_bps & 0xFFFF)
        )
        return cls(
            event_type=ItchEventType.MARKET_DIRECTORY,
            market_id=market_id & 0xFFFF,
            side=OrderSide.BID,
            flags=flags,
            itch_seq=itch_seq,
            wal_seq=wal_seq,
            order_id=s_hi,
            price_ticks=mark_price_ticks,
            qty_lots=s_lo,
            aux_u64=aux_u64,
        )

    def pack_bytes(self) -> bytes:
        buf = bytearray(ARENA_ITCH_BYTES)
        struct.pack_into(
            ">HBBHBBQQQqQQ",
            buf,
            0,
            ARENA_ITCH_MAGIC,
            ARENA_ITCH_VERSION,
            int(self.event_type) & 0xFF,
            self.market_id & 0xFFFF,
            int(self.side) & 0x1,
            self.flags & 0xFF,
            self.itch_seq & MASK64,
            self.wal_seq & MASK64,
            self.order_id & MASK64,
            self.price_ticks,
            self.qty_lots & MASK64,
            self.aux_u64 & MASK64,
        )
        chk = compute_itch_checksum64(buf)
        struct.pack_into(">Q", buf, 56, chk)
        return bytes(buf)

    @classmethod
    def unpack_and_verify(cls, raw: bytes | bytearray | memoryview) -> "ArenaItchEvent":
        if len(raw) != ARENA_ITCH_BYTES:
            raise ValueError(f"Expected {ARENA_ITCH_BYTES}-byte ArenaITCH frame, got {len(raw)}")
        (
            magic,
            ver,
            ev_raw,
            mkt_id,
            side_raw,
            flags,
            itch_seq,
            wal_seq,
            order_id,
            price_ticks,
            qty_lots,
            aux_u64,
            rx_chk,
        ) = struct.unpack_from(">HBBHBBQQQqQQQ", raw, 0)
        if magic != ARENA_ITCH_MAGIC or ver != ARENA_ITCH_VERSION:
            raise ValueError(f"Invalid ArenaITCH header magic=0x{magic:04x} ver={ver}")
        expected_chk = compute_itch_checksum64(raw)
        if rx_chk != expected_chk:
            raise ValueError("ArenaITCH SipHash-2-4 checksum mismatch")
        return cls(
            event_type=ItchEventType(ev_raw),
            market_id=mkt_id,
            side=OrderSide(side_raw & 0x1),
            flags=flags,
            itch_seq=itch_seq,
            wal_seq=wal_seq,
            order_id=order_id,
            price_ticks=price_ticks,
            qty_lots=qty_lots,
            aux_u64=aux_u64,
        )


def pack_itch_subscribe_req(
    market_id: int = 0,
    req_flags: int = ITCH_REQ_FLAG_FULL_SNAPSHOT,
    from_itch_seq: int = 0,
) -> bytes:
    return struct.pack(
        ">IHHQ",
        ARENA_ITCH_REQ_MAGIC,
        market_id & 0xFFFF,
        req_flags & 0xFFFF,
        from_itch_seq & MASK64,
    )


class ArenaItchClient:
    """Zero-dependency 64-byte binary `ArenaITCH` v1 L3 TCP feed client."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        itch_port: int = 19102,
        market_id: int = 0,
        req_flags: int = ITCH_REQ_FLAG_FULL_SNAPSHOT,
        from_itch_seq: int = 0,
        timeout: float = 3.0,
        auto_connect: bool = True,
    ) -> None:
        self.host = host
        self.itch_port = itch_port
        self.market_id = market_id
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._rx_buf = bytearray()
        self._reconstructor: Optional["ItchOrderBookReconstructor"] = None
        if auto_connect:
            self.connect_and_subscribe(
                market_id=market_id, req_flags=req_flags, from_itch_seq=from_itch_seq
            )

    def __enter__(self) -> "ArenaItchClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def connect_and_subscribe(
        self,
        market_id: Optional[int] = None,
        req_flags: int = ITCH_REQ_FLAG_FULL_SNAPSHOT,
        from_itch_seq: int = 0,
        reconstructor: Optional["ItchOrderBookReconstructor"] = None,
    ) -> None:
        self.close()
        if market_id is not None:
            self.market_id = market_id
        if reconstructor is not None:
            self._reconstructor = reconstructor
            if req_flags & ITCH_REQ_FLAG_FULL_SNAPSHOT:
                reconstructor.reset()
            else:
                reconstructor.clear_gap_flag()
            reconstructor.set_market_filter(self.market_id)
            reconstructor.set_track_sequence_gaps(self.market_id == 0)
        s = socket.create_connection((self.host, self.itch_port), timeout=self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(
            pack_itch_subscribe_req(
                market_id=self.market_id,
                req_flags=req_flags,
                from_itch_seq=from_itch_seq,
            )
        )
        self._sock = s
        self._rx_buf.clear()

    def reconnect_and_replay(self, from_itch_seq: int) -> None:
        self.connect_and_subscribe(
            market_id=self.market_id,
            req_flags=ITCH_REQ_FLAG_REPLAY_FROM_SEQ,
            from_itch_seq=from_itch_seq,
            reconstructor=self._reconstructor,
        )

    def recv_event(self, timeout: Optional[float] = None) -> ArenaItchEvent:
        if self._sock is None:
            raise ConnectionError("ArenaITCH socket is closed")
        eff_timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + eff_timeout
        while True:
            while len(self._rx_buf) < ARENA_ITCH_BYTES:
                if (rem := deadline - time.monotonic()) <= 0:
                    raise TimeoutError("Timed out waiting for 64-byte ArenaITCH frame")
                self._sock.settimeout(rem)
                try:
                    chunk = self._sock.recv(4096)
                except TimeoutError:
                    raise
                except OSError:
                    if self._reconstructor is not None:
                        self._reconstructor.gap_detected = True
                    self.close()
                    raise
                if not chunk:
                    if self._reconstructor is not None:
                        self._reconstructor.gap_detected = True
                    self.close()
                    raise ConnectionError("ArenaITCH feed closed by server")
                if len(self._rx_buf) + len(chunk) > _MAX_SDK_HTTP_RESPONSE_BYTES:
                    if self._reconstructor is not None:
                        self._reconstructor.gap_detected = True
                    self.close()
                    raise ValueError("ArenaITCH RX buffer exceeds 64 MiB limit")
                self._rx_buf.extend(chunk)
            raw64 = bytes(self._rx_buf[:ARENA_ITCH_BYTES])
            del self._rx_buf[:ARENA_ITCH_BYTES]
            try:
                ev = ArenaItchEvent.unpack_and_verify(raw64)
            except Exception:
                if self._reconstructor is not None:
                    self._reconstructor.gap_detected = True
                self.close()
                raise
            if ev.event_type != ItchEventType.HEARTBEAT:
                return ev

    def recv_until_snapshot_end(self, timeout: float = 3.0) -> List[ArenaItchEvent]:
        events: List[ArenaItchEvent] = []
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("Timed out waiting for ArenaITCH SNAPSHOT_END")
            ev = self.recv_event(timeout=rem)
            events.append(ev)
            if self.market_id == 0:
                if ev.event_type == ItchEventType.LEDGER_CHECKPOINT:
                    return events
            elif ev.event_type == ItchEventType.SNAPSHOT_END:
                return events

    def close(self) -> None:
        if self._sock is not None:
            sock = self._sock
            self._sock = None
            sock.close()


@dataclass
class ReconstructedItchOrder:
    order_id: int
    account_id: int
    market_id: int
    side: OrderSide
    price_ticks: int
    remaining_lots: int
    reduce_only: bool


@dataclass
class _ItchMarketBookState:
    mark_price_ticks: int = 0
    open_interest_lots: int = 0
    cumulative_funding_phi: int = 0
    synthetic_supply_lots: int = 0
    synthetic_reserve_escrow_usd_micro: int = 0
    in_snapshot: bool = False
    snapshot_complete: bool = False
    orders_by_id: Dict[int, ReconstructedItchOrder] = field(default_factory=dict)
    bid_queues: Dict[int, Deque[int]] = field(default_factory=dict)
    ask_queues: Dict[int, Deque[int]] = field(default_factory=dict)


class ItchOrderBookReconstructor:
    """Deterministic L3 Price-Time FIFO & L2 Order-Book Reconstructor for `ArenaITCH` v1."""

    def __init__(self, track_sequence_gaps: bool = True, market_filter: int = 0) -> None:
        self.books: Dict[int, _ItchMarketBookState] = {}
        self.directory: Dict[int, ItchMarketDirectoryEntry] = {}
        self.last_itch_seq: int = 0
        self.last_wal_seq: int = 0
        self.market_filter: int = int(market_filter)
        self.track_sequence_gaps: bool = track_sequence_gaps and (self.market_filter == 0)
        self.gap_detected: bool = False
        self.has_ledger_checkpoint: bool = False
        self.last_checkpoint_wal_seq: int = 0
        self.last_ledger_chain_hash: bytes = b"\x00" * 32
        self._active_snapshot_market_id: int = 0

    def reset(self) -> None:
        self.books.clear()
        self.directory.clear()
        self.last_itch_seq = 0
        self.last_wal_seq = 0
        self.gap_detected = False
        self.has_ledger_checkpoint = False
        self.last_checkpoint_wal_seq = 0
        self.last_ledger_chain_hash = b"\x00" * 32
        self._active_snapshot_market_id = 0

    def set_market_filter(self, market_id: int) -> None:
        self.market_filter = int(market_id)

    def set_track_sequence_gaps(self, enabled: bool) -> None:
        self.track_sequence_gaps = bool(enabled)

    @property
    def has_incomplete_snapshot(self) -> bool:
        return self._active_snapshot_market_id != 0

    @property
    def last_ledger_chain_hash_hex(self) -> str:
        return "0x" + self.last_ledger_chain_hash.hex()

    def clear_gap_flag(self) -> None:
        self.gap_detected = False

    def apply(self, ev: ArenaItchEvent) -> None:
        if ev.event_type == ItchEventType.HEARTBEAT:
            return
        if self.market_filter != 0 and ev.market_id != 0 and ev.market_id != self.market_filter:
            self.gap_detected = True
            raise ValueError(
                f"Unexpected market_id={ev.market_id} for market_filter={self.market_filter}"
            )
        if self._active_snapshot_market_id != 0:
            is_active_snap_cont = (
                ev.event_type in (ItchEventType.SNAPSHOT_ORDER, ItchEventType.SNAPSHOT_END)
                and ev.market_id == self._active_snapshot_market_id
            )
            if not is_active_snap_cont:
                ab_mb = self.books.get(self._active_snapshot_market_id)
                if ab_mb is not None:
                    ab_mb.in_snapshot = False
                    ab_mb.snapshot_complete = False
                    ab_mb.orders_by_id.clear()
                    ab_mb.bid_queues.clear()
                    ab_mb.ask_queues.clear()
                self._active_snapshot_market_id = 0
                self.gap_detected = True
                raise ValueError("Incomplete SNAPSHOT interrupted before SNAPSHOT_END")
        if ev.event_type == ItchEventType.MARKET_DIRECTORY:
            if (self.last_itch_seq > 0 and ev.itch_seq < self.last_itch_seq) or (
                self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq
            ):
                self.gap_detected = True
                raise ValueError("Regressive itch_seq or wal_seq on MARKET_DIRECTORY")
            if ev.itch_seq > self.last_itch_seq:
                if self.last_itch_seq > 0 and ev.itch_seq > self.last_itch_seq + 1 and self.track_sequence_gaps:
                    self.gap_detected = True
                self.last_itch_seq = ev.itch_seq
            if ev.wal_seq > self.last_wal_seq:
                self.last_wal_seq = ev.wal_seq
            entry = ev.unpack_market_directory()
            self.directory[ev.market_id] = entry
            mb = self.books.setdefault(ev.market_id, _ItchMarketBookState())
            mb.mark_price_ticks = ev.price_ticks
            return
        if ev.event_type == ItchEventType.LEDGER_CHECKPOINT:
            if self.last_itch_seq > 0 and ev.itch_seq < self.last_itch_seq:
                self.gap_detected = True
                raise ValueError("Regressive itch_seq on LEDGER_CHECKPOINT")
            if (self.last_checkpoint_wal_seq > 0 and ev.wal_seq < self.last_checkpoint_wal_seq) or (
                self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq
            ):
                self.gap_detected = True
                raise ValueError("Regressive wal_seq on LEDGER_CHECKPOINT")
            if ev.itch_seq > self.last_itch_seq:
                if self.last_itch_seq > 0 and ev.itch_seq > self.last_itch_seq + 1 and self.track_sequence_gaps:
                    self.gap_detected = True
                self.last_itch_seq = ev.itch_seq
            if ev.wal_seq > self.last_wal_seq:
                self.last_wal_seq = ev.wal_seq
            self.last_checkpoint_wal_seq = ev.wal_seq
            self.last_ledger_chain_hash = ev.extract_ledger_checkpoint_hash()
            self.has_ledger_checkpoint = True
            return
        mb = self.books.setdefault(ev.market_id, _ItchMarketBookState())
        dir_entry = self.directory.get(ev.market_id)
        is_spot_mk = dir_entry is not None and dir_entry.market_kind == 0
        is_spread_mk = dir_entry is not None and dir_entry.market_kind == 4
        aux_i64 = struct.unpack(">q", struct.pack(">Q", ev.aux_u64 & MASK64))[0]

        if ev.event_type == ItchEventType.SNAPSHOT_BEGIN:
            if (
                ev.market_id <= 0
                or (self.last_itch_seq > 0 and ev.itch_seq < self.last_itch_seq)
                or (self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq)
            ):
                self.gap_detected = True
                raise ValueError("Invalid or regressive SNAPSHOT_BEGIN")
            if self.last_itch_seq > 0 and ev.itch_seq > self.last_itch_seq + 1 and self.track_sequence_gaps:
                self.gap_detected = True
            mb.orders_by_id.clear()
            mb.bid_queues.clear()
            mb.ask_queues.clear()
            mb.mark_price_ticks = ev.price_ticks
            if is_spot_mk:
                mb.open_interest_lots = 0
                mb.cumulative_funding_phi = 0
                mb.synthetic_supply_lots = ev.order_id
                mb.synthetic_reserve_escrow_usd_micro = aux_i64
            else:
                mb.open_interest_lots = ev.order_id
                mb.cumulative_funding_phi = aux_i64
                mb.synthetic_supply_lots = 0
                mb.synthetic_reserve_escrow_usd_micro = 0
            mb.in_snapshot = True
            mb.snapshot_complete = False
            self._active_snapshot_market_id = ev.market_id
            self.last_itch_seq = ev.itch_seq
            if ev.wal_seq > self.last_wal_seq:
                self.last_wal_seq = ev.wal_seq
            return

        if ev.event_type == ItchEventType.SNAPSHOT_ORDER:
            if (
                not mb.in_snapshot
                or ev.itch_seq != self.last_itch_seq
                or (self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq)
                or ev.qty_lots <= 0
                or not self._is_valid_itch_price(is_spread_mk, ev.price_ticks)
            ):
                mb.in_snapshot = False
                mb.snapshot_complete = False
                mb.orders_by_id.clear()
                mb.bid_queues.clear()
                mb.ask_queues.clear()
                self._active_snapshot_market_id = 0
                self.gap_detected = True
                raise ValueError("Invalid or out-of-sequence SNAPSHOT_ORDER")
            self._insert_order(mb, ev, allow_non_positive=is_spread_mk)
            return

        if ev.event_type == ItchEventType.SNAPSHOT_END:
            if (
                not mb.in_snapshot
                or ev.itch_seq != self.last_itch_seq
                or (self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq)
                or len(mb.orders_by_id) != ev.order_id
            ):
                got_cnt = len(mb.orders_by_id)
                mb.in_snapshot = False
                mb.snapshot_complete = False
                mb.orders_by_id.clear()
                mb.bid_queues.clear()
                mb.ask_queues.clear()
                self._active_snapshot_market_id = 0
                self.gap_detected = True
                raise ValueError(
                    f"SNAPSHOT_END mismatch: got {got_cnt}, expected {ev.order_id}"
                )
            mb.in_snapshot = False
            mb.snapshot_complete = True
            self._active_snapshot_market_id = 0
            self.last_itch_seq = ev.itch_seq
            if ev.wal_seq > self.last_wal_seq:
                self.last_wal_seq = ev.wal_seq
            return

        if mb.in_snapshot:
            mb.in_snapshot = False
            mb.snapshot_complete = False
            mb.orders_by_id.clear()
            mb.bid_queues.clear()
            mb.ask_queues.clear()
            self.gap_detected = True
            raise ValueError("Incremental ITCH event arrived before SNAPSHOT_END")

        if self.last_itch_seq > 0:
            if ev.itch_seq <= self.last_itch_seq:
                self.gap_detected = True
                raise ValueError(
                    f"Non-advancing itch_seq={ev.itch_seq} <= last_itch_seq={self.last_itch_seq}"
                )
            if ev.itch_seq > self.last_itch_seq + 1 and self.track_sequence_gaps:
                self.gap_detected = True
        if self.last_wal_seq > 0 and ev.wal_seq < self.last_wal_seq:
            self.gap_detected = True
            raise ValueError(
                f"Regressive wal_seq={ev.wal_seq} < last_wal_seq={self.last_wal_seq}"
            )
        self.last_itch_seq = ev.itch_seq
        if ev.wal_seq > self.last_wal_seq:
            self.last_wal_seq = ev.wal_seq

        if ev.event_type == ItchEventType.ORDER_ADDED:
            self._insert_order(mb, ev, allow_non_positive=is_spread_mk)
        elif ev.event_type == ItchEventType.ORDER_EXECUTED:
            ro = mb.orders_by_id.get(ev.order_id)
            if ro is None:
                # Valid post-trade fill print against a dark-midpoint order
                return
            if ev.qty_lots >= ro.remaining_lots:
                self._erase_order(mb, ro)
            else:
                ro.remaining_lots -= ev.qty_lots
        elif ev.event_type == ItchEventType.ORDER_MODIFIED:
            ro = mb.orders_by_id.get(ev.order_id)
            if ro is None or ev.qty_lots <= 0:
                if ro is None and mb.snapshot_complete:
                    self.gap_detected = True
                raise KeyError(f"ORDER_MODIFIED invalid for order_id={ev.order_id}")
            if ev.price_ticks != 0 and not self._is_valid_itch_price(is_spread_mk, ev.price_ticks):
                raise ValueError(f"Invalid price_ticks {ev.price_ticks} in ORDER_MODIFIED")
            if self._is_valid_itch_price(is_spread_mk, ev.price_ticks) and ev.price_ticks != ro.price_ticks:
                queues = mb.bid_queues if ro.side == OrderSide.BID else mb.ask_queues
                old_q = queues.get(ro.price_ticks)
                if old_q is not None:
                    old_q.remove(ro.order_id)
                    if not old_q:
                        del queues[ro.price_ticks]
                new_q = queues.get(ev.price_ticks)
                if new_q is None:
                    new_q = deque()
                    queues[ev.price_ticks] = new_q
                new_q.append(ro.order_id)
                ro.price_ticks = ev.price_ticks
            ro.remaining_lots = ev.qty_lots
        elif ev.event_type == ItchEventType.ORDER_DELETED:
            ro = mb.orders_by_id.get(ev.order_id)
            if ro is None:
                if mb.snapshot_complete:
                    self.gap_detected = True
                raise KeyError(f"ORDER_DELETED for unknown resting order_id={ev.order_id}")
            self._erase_order(mb, ro)
        elif ev.event_type == ItchEventType.MARK_AND_FUNDING:
            mb.mark_price_ticks = ev.price_ticks
            if is_spot_mk:
                mb.open_interest_lots = 0
                mb.cumulative_funding_phi = 0
                mb.synthetic_supply_lots = ev.order_id
                mb.synthetic_reserve_escrow_usd_micro = aux_i64
            else:
                mb.open_interest_lots = ev.order_id
                mb.cumulative_funding_phi = aux_i64
        else:
            raise ValueError(f"Unknown ItchEventType: {ev.event_type!r}")

    @staticmethod
    def _is_valid_itch_price(allow_non_positive: bool, price_ticks: int) -> bool:
        px = int(price_ticks)
        if allow_non_positive:
            return MIN_WIRE_PRICE_TICKS_48 <= px <= MAX_WIRE_PRICE_TICKS_48
        return 0 < px <= MAX_WIRE_PRICE_TICKS_48

    @staticmethod
    def _insert_order(
        mb: _ItchMarketBookState,
        ev: ArenaItchEvent,
        allow_non_positive: bool = False,
    ) -> None:
        if ev.qty_lots <= 0 or not ItchOrderBookReconstructor._is_valid_itch_price(
            allow_non_positive, ev.price_ticks
        ):
            return
        existing = mb.orders_by_id.get(ev.order_id)
        if existing is not None:
            ItchOrderBookReconstructor._erase_order(mb, existing)
        ro = ReconstructedItchOrder(
            order_id=ev.order_id,
            account_id=ev.aux_u64,
            market_id=ev.market_id,
            side=ev.side,
            price_ticks=ev.price_ticks,
            remaining_lots=ev.qty_lots,
            reduce_only=ev.reduce_only,
        )
        mb.orders_by_id[ro.order_id] = ro
        queues = mb.bid_queues if ro.side == OrderSide.BID else mb.ask_queues
        q = queues.get(ro.price_ticks)
        if q is None:
            q = deque()
            queues[ro.price_ticks] = q
        q.append(ro.order_id)

    @staticmethod
    def _erase_order(mb: _ItchMarketBookState, ro: ReconstructedItchOrder) -> None:
        queues = mb.bid_queues if ro.side == OrderSide.BID else mb.ask_queues
        q = queues.get(ro.price_ticks)
        if q is not None:
            q.remove(ro.order_id)
            if not q:
                del queues[ro.price_ticks]
        mb.orders_by_id.pop(ro.order_id, None)

    def snapshot_l2(self, market_id: int, depth: int = 20) -> Dict[str, List[List[int]]]:
        mb = self.books.get(market_id)
        if mb is None:
            return {"bids": [], "asks": []}
        bids: List[List[int]] = []
        for px in sorted(mb.bid_queues.keys(), reverse=True):
            q = mb.bid_queues[px]
            if not q:
                continue
            total = sum(mb.orders_by_id[oid].remaining_lots for oid in q if oid in mb.orders_by_id)
            bids.append([px, total, len(q)])
            if len(bids) >= depth:
                break
        asks: List[List[int]] = []
        for px in sorted(mb.ask_queues.keys()):
            q = mb.ask_queues[px]
            if not q:
                continue
            total = sum(mb.orders_by_id[oid].remaining_lots for oid in q if oid in mb.orders_by_id)
            asks.append([px, total, len(q)])
            if len(asks) >= depth:
                break
        return {"bids": bids, "asks": asks}

    def snapshot_l3(self, market_id: int) -> Dict[str, List[ReconstructedItchOrder]]:
        mb = self.books.get(market_id)
        if mb is None:
            return {"bids": [], "asks": []}
        bids: List[ReconstructedItchOrder] = []
        for px in sorted(mb.bid_queues.keys(), reverse=True):
            for oid in mb.bid_queues[px]:
                if oid in mb.orders_by_id:
                    bids.append(mb.orders_by_id[oid])
        asks: List[ReconstructedItchOrder] = []
        for px in sorted(mb.ask_queues.keys()):
            for oid in mb.ask_queues[px]:
                if oid in mb.orders_by_id:
                    asks.append(mb.orders_by_id[oid])
        return {"bids": bids, "asks": asks}


def _parse_exact_decimal(value: int | float | str | Decimal, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must not be bool")
    try:
        if isinstance(value, Decimal):
            d = value
        else:
            s = str(value).strip()
            if not s:
                raise ValueError(f"{field_name} must not be empty")
            d = Decimal(s)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"Invalid decimal for {field_name}: {value!r}") from exc
    if not d.is_finite():
        raise ValueError(f"{field_name} must be finite: {value!r}")
    return d


def usd_to_price_ticks(
    price_usd: int | float | str | Decimal,
    *,
    allow_zero: bool = False,
    allow_negative: bool = False,
) -> int:
    """Convert exact USD/unit Decimal into $0.01 price ticks without rounding."""
    d = _parse_exact_decimal(price_usd, "price_usd")
    scaled = d * PRICE_TICKS_PER_USD
    if scaled % 1 != 0:
        raise ValueError(
            f"price_usd {price_usd!r} must be an exact multiple of $0.01 (1 tick)"
        )
    ticks = int(scaled)
    if not allow_negative and ticks < 0:
        raise ValueError(f"price_usd {price_usd!r} must be non-negative")
    if not allow_zero and not allow_negative and ticks <= 0:
        raise ValueError(f"price_usd {price_usd!r} must be > 0")
    return _validate_price_ticks_48(ticks, "price_usd")


def price_ticks_to_usd_str(price_ticks: int) -> str:
    return format(Decimal(int(price_ticks)) / PRICE_TICKS_PER_USD, "f")


def price_ticks_to_float(price_ticks: int) -> float:
    return float(Decimal(int(price_ticks)) / PRICE_TICKS_PER_USD)


def base_to_qty_lots(
    amount_base: int | float | str | Decimal,
    *,
    allow_zero: bool = False,
) -> int:
    """Convert exact base units into 10^-4 lot integers without rounding."""
    d = _parse_exact_decimal(amount_base, "amount_base")
    scaled = d * LOTS_PER_BASE_UNIT
    if scaled % 1 != 0:
        raise ValueError(
            f"amount_base {amount_base!r} must be an exact multiple of 0.0001 (1 lot)"
        )
    lots = int(scaled)
    min_lots = 0 if allow_zero else 1
    if lots < min_lots or lots > MAX_WIRE_HEADER_QTY_LOTS:
        raise ValueError(
            f"amount_base {amount_base!r} ({lots} lots) out of range [{min_lots}, {MAX_WIRE_HEADER_QTY_LOTS}]"
        )
    return lots


def qty_lots_to_base_str(qty_lots: int) -> str:
    return format(Decimal(int(qty_lots)) / LOTS_PER_BASE_UNIT, "f")


def qty_lots_to_float(qty_lots: int) -> float:
    return float(Decimal(int(qty_lots)) / LOTS_PER_BASE_UNIT)


def usd_to_micro(
    amount_usd: int | float | str | Decimal,
    *,
    allow_zero: bool = False,
    allow_negative: bool = False,
) -> int:
    """Convert exact USD into 10^-6 micro-USD integers without rounding."""
    d = _parse_exact_decimal(amount_usd, "amount_usd")
    scaled = d * MICRO_USD_PER_DOLLAR
    if scaled % 1 != 0:
        raise ValueError(
            f"amount_usd {amount_usd!r} must be an exact multiple of $0.000001 (1 micro-USD)"
        )
    micro = int(scaled)
    if not allow_negative and micro < 0:
        raise ValueError(f"amount_usd {amount_usd!r} must be non-negative")
    if not allow_zero and not allow_negative and micro <= 0:
        raise ValueError(f"amount_usd {amount_usd!r} must be > 0")
    return micro


def micro_to_usd_str(amount_micro: int) -> str:
    return format(Decimal(int(amount_micro)) / MICRO_USD_PER_DOLLAR, "f")


def micro_to_float(amount_micro: int) -> float:
    return float(Decimal(int(amount_micro)) / MICRO_USD_PER_DOLLAR)


def _wire_status_from_order_res(status_str: str, filled_lots: int, resting_lots: int) -> str:
    norm = str(status_str or "").strip().lower()
    if norm in ("filled",):
        return "closed"
    if norm in ("partial", "partially_filled", "resting", "open"):
        return "open"
    if norm in ("canceled", "cancelled"):
        return "canceled"
    if filled_lots > 0 and resting_lots == 0:
        return "closed"
    if resting_lots > 0:
        return "open"
    return norm or "open"


def _client_order_id_to_tag62(client_order_id: str) -> int:
    """Deterministically hash a non-empty string `clientOrderId` into a positive 62-bit `client_tag`."""
    cleaned = str(client_order_id or "").strip()
    if not cleaned:
        return 0
    digest_u64 = int.from_bytes(hashlib.sha256(cleaned.encode("utf-8")).digest()[:8], "big")
    tag62 = digest_u64 & CANCEL_ALL_TAG_MASK
    return tag62 if tag62 > 0 else 1


class ArenaCcxtAdapter:
    """Zero-dependency CCXT-compatible synchronous exchange adapter over Arena Exchange REST & 64B TCP wire."""

    id = "arena"
    name = "Arena Exchange"
    precisionMode: int = TICK_SIZE
    has: Dict[str, bool] = {
        "loadMarkets": True,
        "fetchMarkets": True,
        "fetchTicker": True,
        "fetchTickers": True,
        "fetchOrderBook": True,
        "fetchL2OrderBook": True,
        "fetchTrades": True,
        "fetchMyTrades": True,
        "fetchOHLCV": True,
        "fetchFundingRate": True,
        "fetchBalance": True,
        "fetchPositions": True,
        "fetchOpenOrders": True,
        "createOrder": True,
        "createLimitOrder": True,
        "createMarketOrder": True,
        "previewOrder": True,
        "editOrder": True,
        "cancelOrder": True,
        "cancelAllOrders": True,
        "setLeverage": True,
        "setMarginMode": True,
        "withdraw": True,
        "loginWithWallet": True,
        "setSandboxMode": True,
        "fetchLeaderboard": True,
    }
    timeframes: Dict[str, str] = {"tick": "tick", "1s": "1s", "1m": "1m"}

    @staticmethod
    def _extract_ccxt_url_entry(val: Any) -> Optional[str]:
        if isinstance(val, dict):
            cand = val.get("private") or val.get("public") or val.get("rest")
            return str(cand).strip() if cand else None
        if isinstance(val, str) and val.strip():
            return val.strip()
        return None

    def __init__(
        self,
        base_url: Optional[str | Dict[str, Any] | ArenaHttpClient] = None,
        *,
        sandbox: bool = False,
        account_id: int = 0,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        creds_file: Optional[str | Path] = None,
        wallet_privkey_hex: Optional[str] = None,
        tcp_host: Optional[str] = None,
        tcp_port: int = 0,
        udp_port: int = 19101,
        wire_key_lo64: Optional[int] = None,
        wire_key_hi64: Optional[int] = None,
        timeout: float = 5.0,
    ) -> None:
        src_http: Optional[ArenaHttpClient] = None
        if base_url is None:
            self._has_custom_url = False
            self._has_custom_test_url = False
            self._api_base_url = DEFAULT_LOCAL_HTTP_URL
            self._test_base_url = PUBLIC_TESTNET_URL
            is_sandbox = bool(sandbox)
            eff_url = self._test_base_url if is_sandbox else self._api_base_url
        elif isinstance(base_url, ArenaHttpClient):
            src_http = base_url
            self._has_custom_url = True
            self._has_custom_test_url = False
            self._api_base_url = src_http.base_url
            self._test_base_url = PUBLIC_TESTNET_URL
            is_sandbox = bool(sandbox) or (src_http.base_url.rstrip("/") == PUBLIC_TESTNET_URL)
            eff_url = src_http.base_url
            if api_key is None:
                api_key = src_http.api_key
            if api_secret is None:
                api_secret = src_http.api_secret
            if timeout == 5.0:
                timeout = src_http.timeout
        elif isinstance(base_url, dict):
            cfg = base_url
            opts = cfg.get("options") if isinstance(cfg.get("options"), dict) else {}
            urls = cfg.get("urls") if isinstance(cfg.get("urls"), dict) else {}
            api_u = self._extract_ccxt_url_entry(urls.get("api"))
            test_u = self._extract_ccxt_url_entry(urls.get("test"))
            explicit_u = (
                api_u
                or cfg.get("url")
                or cfg.get("baseUrl")
                or cfg.get("base_url")
                or cfg.get("arenaUrl")
                or cfg.get("arena_url")
                or opts.get("url")
                or opts.get("baseUrl")
                or opts.get("base_url")
                or opts.get("arenaUrl")
                or opts.get("arena_url")
            )
            is_sandbox = bool(
                sandbox
                or cfg.get("sandbox")
                or cfg.get("testnet")
                or opts.get("sandboxMode")
                or opts.get("sandbox")
                or opts.get("testnet")
            )
            self._has_custom_url = bool(explicit_u)
            self._has_custom_test_url = bool(test_u)
            self._api_base_url = str(explicit_u).rstrip("/") if explicit_u else DEFAULT_LOCAL_HTTP_URL
            self._test_base_url = str(test_u).rstrip("/") if test_u else PUBLIC_TESTNET_URL
            if is_sandbox:
                eff_url = (
                    self._api_base_url
                    if (self._has_custom_url and not self._has_custom_test_url)
                    else self._test_base_url
                )
            else:
                eff_url = self._api_base_url
            if api_key is None:
                k_cand = cfg.get("apiKey") or cfg.get("api_key") or opts.get("apiKey") or opts.get("api_key")
                api_key = str(k_cand) if k_cand else None
            if api_secret is None:
                s_cand = cfg.get("secret") or cfg.get("api_secret") or opts.get("secret") or opts.get("api_secret")
                api_secret = str(s_cand) if s_cand else None
            if wallet_privkey_hex is None:
                pk_cand = cfg.get("privateKey") or cfg.get("wallet_privkey_hex") or opts.get("privateKey") or opts.get("wallet_privkey_hex")
                wallet_privkey_hex = str(pk_cand) if pk_cand else None
            if creds_file is None:
                cf_cand = cfg.get("creds_file") or opts.get("creds_file")
                creds_file = str(cf_cand) if cf_cand else None
            if account_id == 0:
                aid_cand = cfg.get("accountId") or cfg.get("account_id") or opts.get("accountId") or opts.get("account_id")
                if aid_cand is not None:
                    account_id = int(aid_cand)
            if tcp_host is None:
                th_cand = cfg.get("tcpHost") or cfg.get("tcp_host") or opts.get("tcpHost") or opts.get("tcp_host")
                tcp_host = str(th_cand) if th_cand else None
            if tcp_port == 0:
                tp_cand = cfg.get("tcpPort") or cfg.get("tcp_port") or opts.get("tcpPort") or opts.get("tcp_port")
                if tp_cand is not None:
                    tcp_port = int(tp_cand)
            up_cand = cfg.get("udpPort") or cfg.get("udp_port") or opts.get("udpPort") or opts.get("udp_port")
            if up_cand is not None:
                udp_port = int(up_cand)
            if wire_key_lo64 is None and (cfg.get("wire_key_lo64") is not None or opts.get("wire_key_lo64") is not None):
                wire_key_lo64 = int(cfg.get("wire_key_lo64") if cfg.get("wire_key_lo64") is not None else opts["wire_key_lo64"])
            if wire_key_hi64 is None and (cfg.get("wire_key_hi64") is not None or opts.get("wire_key_hi64") is not None):
                wire_key_hi64 = int(cfg.get("wire_key_hi64") if cfg.get("wire_key_hi64") is not None else opts["wire_key_hi64"])
            if cfg.get("timeout") is not None:
                raw_to = float(cfg["timeout"])
                timeout = (raw_to / 1000.0) if raw_to > 100.0 else raw_to
        else:
            clean_u = str(base_url).strip().rstrip("/") or DEFAULT_LOCAL_HTTP_URL
            self._has_custom_url = True
            self._has_custom_test_url = False
            self._api_base_url = clean_u
            self._test_base_url = PUBLIC_TESTNET_URL
            is_sandbox = bool(sandbox)
            eff_url = clean_u

        self.base_url = str(eff_url).rstrip("/")
        self.sandbox: bool = bool(is_sandbox)
        self._explicit_tcp_host: Optional[str] = tcp_host
        self.urls: Dict[str, Any] = {
            "api": {
                "public": self.base_url,
                "private": self.base_url,
                "rest": self.base_url,
                "ws": http_url_to_ws_url(self.base_url),
            },
            "test": {
                "public": self._test_base_url,
                "private": self._test_base_url,
                "rest": self._test_base_url,
                "ws": http_url_to_ws_url(self._test_base_url),
            },
            "www": f"https://{PUBLIC_DOMAIN}",
            "doc": f"{PUBLIC_TESTNET_URL}/llms.txt",
        }
        self.account_id = int(account_id)
        self.timeout = float(timeout)
        self.http = ArenaHttpClient(
            self.base_url,
            timeout=self.timeout,
            api_key=api_key,
            api_secret=api_secret,
        )
        if creds_file:
            self.http.set_creds_file(creds_file)
        elif src_http is not None and src_http._creds_path is not None:
            self.http._creds_path = src_http._creds_path
            self.http._creds_role = src_http._creds_role
            self.http._creds_fallback_role = src_http._creds_fallback_role
            self.http._creds_mtime_ns = src_http._creds_mtime_ns
        self._tcp_host = tcp_host or (urllib.parse.urlparse(self.base_url).hostname or "127.0.0.1")
        self._tcp_port = int(tcp_port)
        self._udp_port = int(udp_port)
        self._wire_key_lo64 = int(wire_key_lo64) if wire_key_lo64 is not None else DEFAULT_KEY_LO64
        self._wire_key_hi64 = int(wire_key_hi64) if wire_key_hi64 is not None else DEFAULT_KEY_HI64
        self.binary: Optional[ArenaBinaryClient] = None
        self._tcp_connected = False
        self._synced_binary_accounts: set[int] = set()

        self.markets: Dict[str, Dict[str, Any]] = {}
        self.symbols: List[str] = []
        self.markets_by_symbol: Dict[str, Dict[str, Any]] = {}
        self.markets_by_id: Dict[int, Dict[str, Any]] = {}
        self.unified_to_native: Dict[str, str] = {}
        self.options: Dict[str, Any] = (
            dict(base_url["options"])
            if isinstance(base_url, dict) and isinstance(base_url.get("options"), dict)
            else {}
        )
        self.precisionMode: int = TICK_SIZE
        self.fees: Dict[str, Any] = {"trading": {"maker": 0.0, "taker": 0.0}}
        self.currencies: Dict[str, Dict[str, Any]] = {}
        self.features: Dict[str, Any] = {
            "spot": {"fetchOHLCV": {"limit": 240}},
            "swap": {"linear": {"fetchOHLCV": {"limit": 240}}},
        }
        self.has: Dict[str, bool] = dict(self.has)

        if wallet_privkey_hex:
            signer = EthWalletSigner(wallet_privkey_hex)
            login_res = self.login_with_wallet(
                signer,
                _preserve_explicit_wire_keys=(wire_key_lo64 is not None or wire_key_hi64 is not None),
            )
            if not login_res.get("ok"):
                raise RuntimeError(f"Wallet login failed: {login_res}")

        if self._tcp_port > 0:
            self.binary = ArenaBinaryClient(
                account_id=max(0, self.account_id),
                host=self._tcp_host,
                tcp_port=self._tcp_port,
                udp_port=self._udp_port,
                key_lo64=self._wire_key_lo64,
                key_hi64=self._wire_key_hi64,
            )

    def set_sandbox_mode(self, enabled: bool = True) -> str:
        """Enable/disable CCXT sandbox mode (defaults to `PUBLIC_TESTNET_URL` when no custom URL was passed)."""
        self.sandbox = bool(enabled)
        if self.sandbox:
            target_url = (
                self._api_base_url
                if (self._has_custom_url and not self._has_custom_test_url)
                else self._test_base_url
            )
        else:
            target_url = self._api_base_url
        target_url = str(target_url).rstrip("/")
        if target_url != self.base_url:
            self.base_url = target_url
            self.http.base_url = target_url
            if not self._explicit_tcp_host:
                self._tcp_host = urllib.parse.urlparse(self.base_url).hostname or "127.0.0.1"
            self.markets.clear()
            self.symbols.clear()
            self.markets_by_symbol.clear()
            self.markets_by_id.clear()
            self.unified_to_native.clear()
        self.urls["api"] = {
            "public": self.base_url,
            "private": self.base_url,
            "rest": self.base_url,
            "ws": http_url_to_ws_url(self.base_url),
        }
        return self.base_url

    @classmethod
    def testnet(
        cls,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> "ArenaCcxtAdapter":
        """Connect in 1 line to the live public Base Sepolia testnet (`https://testnet.feraterra.app`)."""
        cfg = dict(config or {})
        cfg.setdefault("sandbox", True)
        kwargs.setdefault("timeout", 10.0)
        return cls(cfg, **kwargs)

    def login_with_wallet(
        self,
        signer: EthWalletSigner,
        *,
        _preserve_explicit_wire_keys: bool = False,
    ) -> Dict[str, Any]:
        login_res = self.http.login_with_wallet(signer)
        if not login_res.get("ok"):
            return login_res
        aid = int(login_res.get("account_id", 0))
        if aid > 0:
            self.account_id = aid
        if not _preserve_explicit_wire_keys:
            if "wire_key_lo64" in login_res:
                self._wire_key_lo64 = int(login_res["wire_key_lo64"]) & MASK64
            if "wire_key_hi64" in login_res:
                self._wire_key_hi64 = int(login_res["wire_key_hi64"]) & MASK64
        if self.binary is not None and self.account_id > 0:
            self.binary.close()
            self._tcp_connected = False
            self._synced_binary_accounts.clear()
            self.binary.set_credentials(
                self.account_id, self._wire_key_lo64, self._wire_key_hi64
            )
        return login_res

    def __enter__(self) -> "ArenaCcxtAdapter":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        if self.binary is not None:
            self.binary.close()
            self._tcp_connected = False
        self._synced_binary_accounts.clear()
        self.http.close()

    def _ensure_binary(self, account_id: Optional[int] = None) -> ArenaBinaryClient:
        target_aid = int(account_id) if account_id is not None else int(self.account_id)
        uses_prov = (
            self._wire_key_lo64 != DEFAULT_KEY_LO64
            or self._wire_key_hi64 != DEFAULT_KEY_HI64
        )
        signer_aid = int(self.account_id) if (uses_prov and int(self.account_id) > 0) else max(0, target_aid)
        if self.binary is None:
            if self._tcp_port <= 0:
                raise RuntimeError("ArenaCcxtAdapter binary wire requested without tcp_port > 0")
            self.binary = ArenaBinaryClient(
                account_id=signer_aid,
                host=self._tcp_host,
                tcp_port=self._tcp_port,
                udp_port=self._udp_port,
                key_lo64=self._wire_key_lo64,
                key_hi64=self._wire_key_hi64,
            )
        if self.binary._tcp_sock is None:
            self._tcp_connected = False
            self._synced_binary_accounts.clear()
        if uses_prov:
            if signer_aid > 0 and (
                self.binary.account_id != signer_aid
                or self.binary.key_lo64 != self._wire_key_lo64
                or self.binary.key_hi64 != self._wire_key_hi64
            ):
                self.binary.set_credentials(
                    signer_aid, self._wire_key_lo64, self._wire_key_hi64
                )
                self._synced_binary_accounts.discard(signer_aid)
        elif target_aid > 0 and self.binary.account_id != target_aid:
            self.binary.set_account_id(target_aid)
        if not self._tcp_connected:
            self.binary.connect_tcp(timeout=self.timeout)
            self._tcp_connected = True
            self._synced_binary_accounts.clear()
        sync_aid = signer_aid if uses_prov else target_aid
        if sync_aid > 0 and sync_aid not in self._synced_binary_accounts:
            sync_resp = self.binary.sync_sequence(account_id=sync_aid)
            if sync_resp.status_code != WireStatusCode.OK:
                self.binary.close()
                self._tcp_connected = False
                self._synced_binary_accounts.clear()
                raise RuntimeError(
                    f"ArenaBinaryClient sync_sequence failed ({sync_resp.status_code.name})"
                )
            self._synced_binary_accounts.add(sync_aid)
        return self.binary

    @staticmethod
    def _unified_symbol_for_market(m: Dict[str, Any]) -> str:
        sym = str(m.get("symbol", "")).strip()
        kind = str(m.get("kind", "")).strip().lower()
        if sym.endswith("-USD-SPOT"):
            base = sym[: -len("-USD-SPOT")]
            return f"{base}/USD"
        if sym.endswith("-USD-PERP"):
            base = sym[: -len("-USD-PERP")]
            return f"{base}/USD:USD"
        if kind == "spot":
            return f"{sym}/USD"
        return sym

    def _build_ccxt_market_entry(self, m: Dict[str, Any]) -> Dict[str, Any]:
        mid = int(m["market_id"])
        native_sym = str(m["symbol"])
        kind = str(m.get("kind", "")).lower()
        unified = self._unified_symbol_for_market(m)
        base = unified.split("/", 1)[0] if "/" in unified else native_sym
        is_spot = (kind == "spot")
        is_swap = kind in ("perp", "linear_perp", "linear_perpetual", "formula_perp", "formula_perpetual")
        return {
            "id": str(mid),
            "numericId": mid,
            "symbol": unified,
            "nativeSymbol": native_sym,
            "base": base,
            "quote": "USD",
            "settle": "USD" if not is_spot else None,
            "baseId": str(m.get("base_asset_id", 0)),
            "quoteId": "0",
            "type": "spot" if is_spot else ("swap" if is_spot is False and is_swap else kind),
            "spot": is_spot,
            "margin": not is_spot,
            "swap": is_swap,
            "future": False,
            "contract": not is_spot,
            "contractSize": 1.0 if not is_spot else None,
            "linear": True if not is_spot else None,
            "inverse": False if not is_spot else None,
            "active": str(m.get("trading_status", "live")).lower() != "halted",
            "precision": {"amount": 0.0001, "price": 0.01},
            "limits": {
                "amount": {"min": 0.0001, "max": qty_lots_to_float(int(m.get("max_order_lots", 1)))},
                "price": {
                    "min": price_ticks_to_float(int(m.get("min_price_ticks", 1))),
                    "max": price_ticks_to_float(int(m.get("max_price_ticks", 1))),
                },
                "cost": {"min": None, "max": None},
                "leverage": {"min": 1.0, "max": None},
            },
            "maker": int(m.get("maker_fee_bps", 0)) / 10000.0,
            "taker": int(m.get("taker_fee_bps", 0)) / 10000.0,
            "info": m,
        }

    def load_markets(
        self,
        reload: bool = False,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        _ = params
        if self.markets_by_symbol and not reload:
            return {**self.markets, **self.markets_by_symbol}
        resp = self.http.markets()
        if not resp.get("ok"):
            raise RuntimeError(f"GET /markets failed: {resp}")
        by_unified: Dict[str, Dict[str, Any]] = {}
        by_sym: Dict[str, Dict[str, Any]] = {}
        by_id: Dict[int, Dict[str, Any]] = {}
        u2n: Dict[str, str] = {}
        for m in list(resp.get("markets", [])):
            entry = self._build_ccxt_market_entry(m)
            native_sym = str(entry["nativeSymbol"]).upper()
            unified_sym = str(entry["symbol"]).upper()
            mid = int(entry["numericId"])
            by_unified[str(entry["symbol"])] = entry
            by_sym[entry["nativeSymbol"]] = entry
            by_id[mid] = entry
            u2n[native_sym] = entry["nativeSymbol"]
            u2n[unified_sym] = entry["nativeSymbol"]
            u2n[str(mid)] = entry["nativeSymbol"]
        self.markets = by_unified
        self.symbols = sorted(by_unified.keys())
        self.markets_by_symbol = by_sym
        self.markets_by_id = by_id
        self.unified_to_native = u2n
        return {**self.markets, **self.markets_by_symbol}

    def fetch_markets(
        self,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        self.load_markets(reload=True, params=params)
        return [self.markets_by_id[mid] for mid in sorted(self.markets_by_id.keys())]

    def resolve_market(self, symbol_or_id: str | int) -> Dict[str, Any]:
        if not self.markets_by_id:
            self.load_markets(reload=False)
        if isinstance(symbol_or_id, int):
            if symbol_or_id in self.markets_by_id:
                return self.markets_by_id[symbol_or_id]["info"]
            self.load_markets(reload=True)
            if symbol_or_id in self.markets_by_id:
                return self.markets_by_id[symbol_or_id]["info"]
            raise KeyError(f"Unknown Arena market_id: {symbol_or_id}")
        raw = str(symbol_or_id or "").strip()
        if not raw:
            raise KeyError("Market symbol or ID must not be empty")
        if raw.isdigit():
            mid = int(raw)
            if mid in self.markets_by_id:
                return self.markets_by_id[mid]["info"]
        up = raw.upper()
        candidates = [up]
        if "/" in up:
            pair, *settle = up.split(":", 1)
            base, quote = pair.split("/", 1)
            if settle:
                candidates.append(f"{base}-{quote}-PERP")
            else:
                candidates.append(f"{base}-{quote}-SPOT")
                candidates.append(f"{base}-{quote}-PERP")
        for cand in candidates:
            native = self.unified_to_native.get(cand)
            if native and native in self.markets_by_symbol:
                return self.markets_by_symbol[native]["info"]
        self.load_markets(reload=True)
        for cand in candidates:
            native = self.unified_to_native.get(cand)
            if native and native in self.markets_by_symbol:
                return self.markets_by_symbol[native]["info"]
        raise KeyError(f"Unknown Arena symbol or market_id: {symbol_or_id!r}")

    def _format_ticker(self, m: Dict[str, Any]) -> Dict[str, Any]:
        unified = self._unified_symbol_for_market(m)
        bid_t = int(m.get("best_bid_ticks") or 0)
        ask_t = int(m.get("best_ask_ticks") or 0)
        mark_t = int(m.get("mark_price_ticks") or 0)
        last_t = int(m.get("last_trade_price_ticks") or 0) or mark_t
        return {
            "symbol": unified,
            "nativeSymbol": m.get("symbol"),
            "marketId": int(m.get("market_id") or 0),
            "bid": price_ticks_to_float(bid_t) if bid_t != 0 else None,
            "bidVolume": qty_lots_to_float(int(m.get("best_bid_lots") or 0)) if bid_t != 0 else 0.0,
            "ask": price_ticks_to_float(ask_t) if ask_t != 0 else None,
            "askVolume": qty_lots_to_float(int(m.get("best_ask_lots") or 0)) if ask_t != 0 else 0.0,
            "last": price_ticks_to_float(last_t) if last_t != 0 else None,
            "markPrice": price_ticks_to_float(mark_t) if mark_t != 0 else None,
            "baseVolume": qty_lots_to_float(int(m.get("total_volume_lots") or 0)),
            "quoteVolume": micro_to_float(int(m.get("total_quote_volume_micro") or 0)),
            "info": m,
        }

    def fetch_ticker(
        self,
        symbol: str | int,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = params
        m = self.resolve_market(symbol)
        resp = self.http.ticker(int(m["market_id"]))
        if not resp.get("ok") or "ticker" not in resp:
            raise RuntimeError(f"GET /ticker failed: {resp}")
        return self._format_ticker(resp["ticker"])

    def fetch_tickers(
        self,
        symbols: Optional[Sequence[str | int]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        _ = params
        resp = self.http.markets()
        if not resp.get("ok"):
            raise RuntimeError(f"GET /markets failed: {resp}")
        allowed_mids: Optional[set[int]] = None
        if symbols is not None:
            sym_seq: Sequence[str | int] = [symbols] if isinstance(symbols, (str, int)) else symbols
            allowed_mids = {int(self.resolve_market(s)["market_id"]) for s in sym_seq}
        out: Dict[str, Dict[str, Any]] = {}
        for m in list(resp.get("markets", [])):
            if allowed_mids is not None and int(m["market_id"]) not in allowed_mids:
                continue
            tk = self._format_ticker(m)
            out[str(tk["symbol"])] = tk
        return out

    def fetch_order_book(
        self,
        symbol: str | int,
        limit: Optional[int] = 50,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        eff_limit = 50 if limit is None else int(limit)
        if limit is None and p.get("depth") is not None:
            eff_limit = int(p["depth"])
        m = self.resolve_market(symbol)
        resp = self.http.book(int(m["market_id"]), depth=max(1, min(200, eff_limit)))
        if not resp.get("ok"):
            raise RuntimeError(f"GET /book failed: {resp}")
        bids = [[price_ticks_to_float(lvl[0]), qty_lots_to_float(lvl[1])] for lvl in list(resp.get("bids", []))]
        asks = [[price_ticks_to_float(lvl[0]), qty_lots_to_float(lvl[1])] for lvl in list(resp.get("asks", []))]
        return {
            "symbol": self._unified_symbol_for_market(m),
            "bids": bids,
            "asks": asks,
            "nonce": int(resp.get("wal_seq", 0)),
            "timestamp": None,
            "datetime": None,
            "info": resp,
        }

    def fetch_l2_order_book(
        self,
        symbol: str | int,
        limit: Optional[int] = 50,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.fetch_order_book(symbol, limit=limit, params=params)

    @staticmethod
    def _trade_matches_since(t: Dict[str, Any], since: int) -> bool:
        ts_raw = t.get("timestamp", t.get("ts_ms"))
        if ts_raw is not None:
            return int(ts_raw) >= int(since)
        if int(since) < 100_000_000_000 and t.get("wal_seq") is not None:
            return int(t["wal_seq"]) >= int(since)
        return True

    def fetch_trades(
        self,
        symbol: str | int,
        since: Optional[int] = None,
        limit: Optional[int] = 100,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        _ = params
        eff_limit = 100 if limit is None else int(limit)
        m = self.resolve_market(symbol)
        req_limit = 512 if since is not None else max(1, min(512, eff_limit))
        resp = self.http.trades(int(m["market_id"]), limit=req_limit)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /trades failed: {resp}")
        unified = self._unified_symbol_for_market(m)
        out: List[Dict[str, Any]] = []
        for t in list(resp.get("trades", [])):
            if since is not None and not self._trade_matches_since(t, int(since)):
                continue
            side_raw = str(t.get("taker_side", "bid")).lower()
            px_t = int(t["price_ticks"])
            qty_l = int(t["qty_lots"])
            out.append(
                {
                    "id": str(t.get("trade_id_str", t.get("trade_id", 0))),
                    "symbol": unified,
                    "side": "buy" if side_raw in ("bid", "buy") else "sell",
                    "price": price_ticks_to_float(px_t),
                    "amount": qty_lots_to_float(qty_l),
                    "cost": micro_to_float(int(t.get("notional_micro", px_t * qty_l))),
                    "timestamp": int(t["timestamp"]) if t.get("timestamp") is not None else None,
                    "datetime": None,
                    "fee": {
                        "cost": micro_to_float(int(t.get("taker_fee_micro", 0))),
                        "currency": "USD",
                    },
                    "info": t,
                }
            )
            if len(out) >= max(1, eff_limit):
                break
        return out

    def fetch_my_trades(
        self,
        symbol: Optional[str | int] = None,
        since: Optional[int] = None,
        limit: Optional[int] = 100,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        p = dict(params or {})
        aid = self._effective_account_id(p)
        eff_limit = 100 if limit is None else int(limit)
        eff_sym = symbol if symbol is not None else p.get("symbol", p.get("market_id"))
        if eff_sym is not None:
            markets_to_scan = [self.resolve_market(eff_sym)]
        else:
            if not self.markets_by_id:
                self.load_markets(reload=False)
            markets_to_scan = [
                self.markets_by_id[mid]["info"] for mid in sorted(self.markets_by_id.keys())
            ]
        out: List[Dict[str, Any]] = []
        for m in markets_to_scan:
            mid = int(m["market_id"])
            resp = self.http.trades(mid, limit=min(512, max(100, eff_limit * 4)))
            if not resp.get("ok"):
                raise RuntimeError(f"GET /trades failed: {resp}")
            unified = self._unified_symbol_for_market(m)
            for t in list(resp.get("trades", [])):
                maker_aid = int(t.get("maker_account_id", 0))
                taker_aid = int(t.get("taker_account_id", 0))
                acct_aid = int(t.get("account_id", 0))
                if aid not in (maker_aid, taker_aid, acct_aid):
                    continue
                if since is not None and not self._trade_matches_since(t, int(since)):
                    continue
                side_raw = str(t.get("taker_side", "bid")).lower()
                taker_is_buy = side_raw in ("bid", "buy")
                if taker_aid == aid or (acct_aid == aid and maker_aid != aid):
                    role = "taker"
                    my_side = "buy" if taker_is_buy else "sell"
                    ord_raw = t.get("taker_order_id_str", t.get("taker_order_id", t.get("order_id")))
                    fee_m = int(t.get("taker_fee_micro", t.get("fee_micro", 0)))
                else:
                    role = "maker"
                    my_side = "sell" if taker_is_buy else "buy"
                    ord_raw = t.get("maker_order_id_str", t.get("maker_order_id", t.get("order_id")))
                    fee_m = int(t.get("maker_fee_micro", 0))
                px_t = int(t["price_ticks"])
                qty_l = int(t["qty_lots"])
                out.append(
                    {
                        "id": str(t.get("trade_id_str", t.get("trade_id", 0))),
                        "order": str(ord_raw) if ord_raw is not None and str(ord_raw) != "0" else None,
                        "symbol": unified,
                        "marketId": mid,
                        "side": my_side,
                        "takerOrMaker": role,
                        "price": price_ticks_to_float(px_t),
                        "amount": qty_lots_to_float(qty_l),
                        "cost": micro_to_float(int(t.get("notional_micro", px_t * qty_l))),
                        "timestamp": int(t["timestamp"]) if t.get("timestamp") is not None else None,
                        "datetime": None,
                        "fee": {
                            "cost": micro_to_float(fee_m),
                            "currency": "USD",
                        },
                        "walSeq": int(t.get("wal_seq", 0)),
                        "info": t,
                    }
                )
                if len(out) >= max(1, eff_limit):
                    return out
        return out

    def fetch_ohlcv(
        self,
        symbol: str | int,
        timeframe: str = "1m",
        since: Optional[int] = None,
        limit: Optional[int] = 120,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[List[float | int]]:
        _ = params
        eff_limit = 120 if limit is None else int(limit)
        tf = str(timeframe or "1m").strip()
        if tf not in self.timeframes:
            raise ValueError(f"Unsupported timeframe {timeframe!r}; expected one of {tuple(self.timeframes)}")
        m = self.resolve_market(symbol)
        req_limit = 240 if since is not None else max(1, min(240, eff_limit))
        resp = self.http.candles(int(m["market_id"]), interval=tf, limit=req_limit)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /candles failed: {resp}")
        since_i = int(since) if since is not None else None
        out: List[List[float | int]] = []
        for bar in list(resp.get("candles", [])):
            bar_ts = int(bar[0])
            if since_i is not None:
                if since_i >= 100_000_000_000 and 0 < bar_ts < 100_000_000_000 and tf != "tick":
                    if bar_ts * 1000 < since_i:
                        continue
                elif bar_ts < since_i:
                    continue
            out.append(
                [
                    bar_ts,
                    price_ticks_to_float(int(bar[1])),
                    price_ticks_to_float(int(bar[2])),
                    price_ticks_to_float(int(bar[3])),
                    price_ticks_to_float(int(bar[4])),
                    qty_lots_to_float(int(bar[5])),
                ]
            )
            if len(out) >= max(1, eff_limit):
                break
        return out

    def fetch_funding_rate(
        self,
        symbol: str | int,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = params
        m = self.resolve_market(symbol)
        mid = int(m["market_id"])
        resp = self.http.ticker(mid)
        if not resp.get("ok") or "ticker" not in resp:
            raise RuntimeError(f"GET /ticker failed: {resp}")
        tk = resp["ticker"]
        unified = self._unified_symbol_for_market(tk)
        mark_t = int(tk.get("mark_price_ticks", 0))
        mark_px = price_ticks_to_float(mark_t) if mark_t != 0 else None
        if tk.get("funding_rate") is not None:
            fr_val = float(tk["funding_rate"])
        elif tk.get("funding_rate_bps") is not None:
            fr_val = float(tk["funding_rate_bps"]) / 10000.0
        else:
            fr_val = 0.0
        return {
            "symbol": unified,
            "marketId": mid,
            "markPrice": mark_px,
            "indexPrice": mark_px,
            "fundingRate": fr_val,
            "cumulativeFundingPhi": int(tk.get("cumulative_funding_phi", 0)),
            "timestamp": None,
            "datetime": None,
            "fundingTimestamp": None,
            "fundingDatetime": None,
            "info": tk,
        }

    def _effective_account_id(self, params: Optional[Dict[str, Any]] = None) -> int:
        aid = int((params or {}).get("account_id", self.account_id))
        if aid <= 0:
            raise ValueError("account_id must be > 0 (pass params={'account_id': ...} or configure adapter account_id)")
        return aid

    def fetch_balance(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        aid = self._effective_account_id(params)
        resp = self.http.account(aid)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /account failed: {resp}")
        usd_free = micro_to_float(int(resp.get("free_usd_micro", 0)))
        usd_used = micro_to_float(int(resp.get("locked_usd_micro", 0)))
        usd_total = micro_to_float(int(resp.get("free_usd_micro", 0)) + int(resp.get("locked_usd_micro", 0)))
        equity_usd = micro_to_float(int(resp.get("total_equity_micro", 0)))
        withdrawable_usd = micro_to_float(int(resp.get("withdrawable_usd_micro", 0)))
        info_dict = dict(resp)
        info_dict["equity_usd"] = equity_usd
        info_dict["withdrawable_usd"] = withdrawable_usd
        free_map: Dict[str, float] = {"USD": usd_free}
        used_map: Dict[str, float] = {"USD": usd_used}
        total_map: Dict[str, float] = {"USD": usd_total}
        result: Dict[str, Any] = {
            "USD": {"free": usd_free, "used": usd_used, "total": usd_total},
            "free": free_map,
            "used": used_map,
            "total": total_map,
            "equity_usd": equity_usd,
            "withdrawable_usd": withdrawable_usd,
            "info": info_dict,
        }
        for bb in list(resp.get("base_balances", [])):
            sym_raw = str(bb.get("symbol", f"ASSET_{bb.get('asset_id')}"))
            code = sym_raw.split("-", 1)[0] if "-USD-" in sym_raw else sym_raw
            free_b = qty_lots_to_float(int(bb.get("free_lots", 0)))
            used_b = qty_lots_to_float(int(bb.get("locked_lots", 0)))
            tot_b = free_b + used_b
            free_map[code] = free_b
            used_map[code] = used_b
            total_map[code] = tot_b
            result[code] = {"free": free_b, "used": used_b, "total": tot_b}
        return result

    def fetch_positions(
        self,
        symbols: Optional[Sequence[str | int]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        aid = self._effective_account_id(params)
        self.load_markets(reload=True)
        resp = self.http.account(aid)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /account failed: {resp}")
        allowed_mids: Optional[set[int]] = None
        if symbols is not None:
            sym_seq: Sequence[str | int] = [symbols] if isinstance(symbols, (str, int)) else symbols
            allowed_mids = {int(self.resolve_market(s)["market_id"]) for s in sym_seq}
        out: List[Dict[str, Any]] = []
        for pos in list(resp.get("perp_positions", [])):
            mid = int(pos["market_id"])
            if allowed_mids is not None and mid not in allowed_mids:
                continue
            lots = int(pos.get("position_lots", 0))
            if lots == 0:
                continue
            entry = self.markets_by_id.get(mid)
            unified = entry["symbol"] if entry is not None else f"MARKET_{mid}"
            mark_ticks = int(entry["info"].get("mark_price_ticks", 0)) if entry is not None else 0
            q_entry_micro = int(pos.get("quote_entry_micro", 0))
            # quote_entry_micro is signed cost basis: long entry adds negative cash; mark * lots + quote_entry_micro = uPnL
            entry_ticks_dec = Decimal(-q_entry_micro) / (Decimal(lots) * Decimal("100"))
            upnl_micro = lots * mark_ticks + q_entry_micro
            ko_ticks = int(pos.get("knockout_price_ticks", 0))
            out.append(
                {
                    "symbol": unified,
                    "marketId": mid,
                    "side": "long" if lots > 0 else "short",
                    "contracts": float(Decimal(abs(lots)) / LOTS_PER_BASE_UNIT),
                    "entryPrice": float(entry_ticks_dec),
                    "markPrice": price_ticks_to_float(mark_ticks),
                    "unrealizedPnl": micro_to_float(upnl_micro),
                    "realizedPnl": micro_to_float(int(pos.get("realized_pnl_micro", 0))),
                    "knockoutPrice": price_ticks_to_float(ko_ticks) if ko_ticks != 0 else None,
                    "marginMode": "cross",
                    "info": pos,
                }
            )
        return out

    def fetch_open_orders(
        self,
        symbol: Optional[str | int] = None,
        since: Optional[int] = None,
        limit: Optional[int] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if isinstance(since, dict) and params is None:
            params, since = since, None
        aid = self._effective_account_id(params)
        if not self.markets_by_id:
            self.load_markets(reload=False)
        target_mid: Optional[int] = int(self.resolve_market(symbol)["market_id"]) if symbol is not None else None
        resp = self.http.account(aid)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /account failed: {resp}")
        since_i = int(since) if since is not None else None
        out: List[Dict[str, Any]] = []
        for o in list(resp.get("open_orders", [])):
            mid = int(o["market_id"])
            if target_mid is not None and mid != target_mid:
                continue
            if since_i is not None:
                if o.get("timestamp") is not None and int(o["timestamp"]) < since_i:
                    continue
                if since_i < 100_000_000_000 and o.get("sequence_num") is not None and int(o["sequence_num"]) < since_i:
                    continue
            entry = self.markets_by_id.get(mid)
            unified = entry["symbol"] if entry is not None else f"MARKET_{mid}"
            init_lots = int(o.get("initial_lots", 0))
            rem_lots = int(o.get("remaining_lots", 0))
            filled_lots = max(0, init_lots - rem_lots)
            px_t = int(o.get("price_ticks", 0))
            out.append(
                {
                    "id": str(o["order_id"]),
                    "marketId": mid,
                    "symbol": unified,
                    "side": "buy" if str(o.get("side", "bid")).lower() == "bid" else "sell",
                    "type": "limit",
                    "price": price_ticks_to_float(px_t),
                    "amount": qty_lots_to_float(init_lots),
                    "remaining": qty_lots_to_float(rem_lots),
                    "filled": qty_lots_to_float(filled_lots),
                    "cost": micro_to_float(px_t * filled_lots) if filled_lots > 0 else 0.0,
                    "reduceOnly": bool(o.get("reduce_only", False)),
                    "status": "open",
                    "clientOrderId": str(o.get("client_tag", 0)) if int(o.get("client_tag", 0)) else None,
                    "fee": {"cost": 0.0, "currency": "USD"},
                    "info": o,
                }
            )
            if limit is not None and len(out) >= max(0, int(limit)):
                break
        return out

    def fetch_leaderboard(
        self,
        limit: int = 50,
        params: Optional[Dict[str, Any]] = None,
        *,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        p = dict(params or {})
        eff_limit = max(1, min(500, int(p.get("limit", limit))))
        eff_sort = str(sort or p.get("sort") or p.get("sort_by") or "equity")
        resp = self.http.get_leaderboard(limit=eff_limit, sort=eff_sort)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /leaderboard failed: {resp}")
        raw_rows = resp.get("entries")
        if not isinstance(raw_rows, list):
            raw_rows = resp.get("leaderboard") if isinstance(resp.get("leaderboard"), list) else []
        out: List[Dict[str, Any]] = []
        for idx, row in enumerate(raw_rows, start=1):
            if not isinstance(row, dict):
                continue
            eq_m = row.get("total_equity_micro", row.get("equity_micro"))
            rpnl_m = row.get("realized_pnl_micro")
            upnl_m = row.get("unrealized_pnl_micro")
            tpnl_m = row.get(
                "total_pnl_micro",
                row.get(
                    "net_pnl_micro",
                    (int(rpnl_m or 0) + int(upnl_m or 0))
                    if (rpnl_m is not None or upnl_m is not None)
                    else None,
                ),
            )
            vol_m = row.get("total_volume_notional_micro_128", row.get("total_volume_micro_128", row.get("volume_micro")))
            out.append(
                {
                    "rank": int(row.get("rank", idx)),
                    "accountId": int(row["account_id"]) if row.get("account_id") is not None else None,
                    "address": row.get("wallet_masked") or row.get("trader") or row.get("eth_address"),
                    "equityUsd": (
                        float(row["equity_usd"])
                        if row.get("equity_usd") is not None
                        else (micro_to_float(int(eq_m)) if eq_m is not None else 0.0)
                    ),
                    "realizedPnlUsd": (
                        float(row["realized_pnl_usd"])
                        if row.get("realized_pnl_usd") is not None
                        else (micro_to_float(int(rpnl_m)) if rpnl_m is not None else 0.0)
                    ),
                    "unrealizedPnlUsd": (
                        float(row["unrealized_pnl_usd"])
                        if row.get("unrealized_pnl_usd") is not None
                        else (micro_to_float(int(upnl_m)) if upnl_m is not None else 0.0)
                    ),
                    "totalPnlUsd": (
                        float(row["pnl_usd"])
                        if row.get("pnl_usd") is not None
                        else (micro_to_float(int(tpnl_m)) if tpnl_m is not None else 0.0)
                    ),
                    "volumeUsd": (
                        float(row["volume_usd"])
                        if row.get("volume_usd") is not None
                        else (micro_to_float(int(vol_m)) if vol_m is not None else 0.0)
                    ),
                    "roiPct": (
                        float(row["roi_pct"])
                        if row.get("roi_pct") is not None
                        else (float(row["roi_bps"]) / 100.0 if row.get("roi_bps") is not None else None)
                    ),
                    "bboStreakEpochs": int(row.get("bbo_uptime_streak_epochs", 0)),
                    "bboMultiplier": row.get("bbo_uptime_multiplier", "1.00x"),
                    "walSeq": int(row.get("wal_seq", resp.get("wal_seq", 0))),
                    "info": row,
                }
            )
        return out

    def create_order(
        self,
        symbol: str | int,
        order_type: Optional[str] = None,
        side: str = "buy",
        amount: int | float | str | Decimal = 0.0,
        price: Optional[int | float | str | Decimal] = None,
        params: Optional[Dict[str, Any]] = None,
        *,
        type: Optional[str] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        m = self.resolve_market(symbol)
        mid = int(m["market_id"])
        aid = int(p.get("account_id", self.account_id))
        if aid <= 0:
            raise ValueError("account_id must be > 0 before placing orders")
        qty_lots = base_to_qty_lots(amount)
        eff_type = order_type if order_type is not None else (type if type is not None else p.get("type", "limit"))
        type_norm = str(eff_type or "limit").strip().lower()
        side_norm = str(side or "").strip().lower()
        if side_norm in ("buy", "bid"):
            side_str = "bid"
            wire_side = OrderSide.BID
        elif side_norm in ("sell", "ask"):
            side_str = "ask"
            wire_side = OrderSide.ASK
        else:
            raise ValueError(f"Unsupported side {side!r}; expected buy|sell|bid|ask")

        is_market = type_norm == "market"
        is_pegged = any(
            bool(p.get(flag_k, False))
            for flag_k in ("primary_peg", "midpoint_peg", "mark_peg", "trailing_peg", "dark_midpoint")
        )
        price_ticks = self._resolve_ccxt_price_ticks(
            m, price, p, is_market=is_market, is_pegged=is_pegged
        )

        tif_raw = str(p.get("tif", p.get("timeInForce", "ioc" if is_market else "gtc"))).strip().lower()
        tif_map = {
            "gtc": TimeInForce.GTC,
            "ioc": TimeInForce.IOC,
            "fok": TimeInForce.FOK,
            "post_only": TimeInForce.POST_ONLY,
            "postonly": TimeInForce.POST_ONLY,
        }
        if bool(p.get("postOnly", False)) and tif_raw == "gtc":
            tif_raw = "post_only"
        if tif_raw not in tif_map:
            raise ValueError(f"Unsupported timeInForce {tif_raw!r}")

        stp_raw = str(p.get("stp", "cancel_resting")).strip().lower()
        stp_map = {
            "cancel_resting": StpMode.CANCEL_RESTING,
            "cancel_incoming": StpMode.CANCEL_INCOMING,
            "cancel_aggressor": StpMode.CANCEL_INCOMING,
            "cancel_both": StpMode.CANCEL_BOTH,
            "decrement_and_cancel": StpMode.CANCEL_BOTH,
            "dc": StpMode.CANCEL_BOTH,
            "none": StpMode.NONE,
        }
        if stp_raw not in stp_map:
            raise ValueError(f"Unsupported stp mode {stp_raw!r}")

        reduce_only = bool(p.get("reduceOnly", p.get("reduce_only", False)))
        post_only_slide = bool(p.get("post_only_slide", False))
        margin_spot = bool(p.get("margin_spot", False))
        raw_client_oid = p.get("clientOrderId", p.get("client_order_id"))
        if p.get("client_tag") is not None:
            client_tag = int(p["client_tag"])
        elif isinstance(raw_client_oid, str) and raw_client_oid.strip():
            client_tag = _client_order_id_to_tag62(raw_client_oid)
        elif isinstance(raw_client_oid, int) and raw_client_oid > 0:
            client_tag = (int(raw_client_oid) & CANCEL_ALL_TAG_MASK) or 1
        else:
            client_tag = 0
        resolved_client_oid = (
            raw_client_oid.strip()
            if isinstance(raw_client_oid, str) and raw_client_oid.strip()
            else (str(client_tag) if client_tag > 0 else None)
        )
        min_qty_lots = base_to_qty_lots(p["min_qty_base"]) if "min_qty_base" in p else int(p.get("min_qty_lots", 0))
        display_qty_lots = (
            base_to_qty_lots(p["display_qty_base"])
            if "display_qty_base" in p
            else int(p.get("display_qty_lots", 0))
        )
        jit_elastic_mult = int(p.get("jit_elastic_mult", 0))
        stp_dc = bool(p.get("stp_decrement_and_cancel", stp_raw in ("decrement_and_cancel", "dc")))
        priority_fee_ppm = int(p.get("priority_fee_ppm", 0))
        if not (0 <= priority_fee_ppm <= MAX_PRIORITY_FEE_PPM):
            raise ValueError(f"priority_fee_ppm {priority_fee_ppm} out of [0, {MAX_PRIORITY_FEE_PPM}]")
        use_binary = bool(p.get("use_binary_wire", False))

        if use_binary:
            bin_cli = self._ensure_binary(account_id=aid)
            wres = bin_cli.place_order(
                market_id=mid,
                side=wire_side,
                price_ticks=price_ticks,
                qty_lots=qty_lots,
                tif=tif_map[tif_raw],
                stp=stp_map[stp_raw],
                reduce_only=reduce_only,
                is_market=is_market,
                client_tag=client_tag,
                post_only_slide=post_only_slide,
                min_qty_lots=min_qty_lots,
                primary_peg=bool(p.get("primary_peg", False)),
                midpoint_peg=bool(p.get("midpoint_peg", False)),
                margin_spot=margin_spot,
                display_qty_lots=display_qty_lots,
                dark_midpoint=bool(p.get("dark_midpoint", False)),
                auto_skew_ticks=int(p.get("auto_skew_ticks", 0)),
                peg_offset_ticks=int(p.get("peg_offset_ticks", 0)),
                oco_linked=bool(p.get("oco_linked", False)),
                max_lifetime_wal_seqs=int(p.get("max_lifetime_wal_seqs", 0)),
                jit_elastic_mult=jit_elastic_mult,
                mark_peg=bool(p.get("mark_peg", False)),
                auto_flip_ticks=int(p.get("auto_flip_ticks", 0)),
                trailing_peg=bool(p.get("trailing_peg", False)),
                stp_decrement_and_cancel=stp_dc,
                account_id=aid,
                priority_fee_ppm=priority_fee_ppm,
            )
            if wres.status_code != WireStatusCode.OK:
                raise RuntimeError(f"Wire place_order rejected ({wres.status_code.name})")
            filled_lots = int(wres.filled_lots)
            resting_lots = int(wres.resting_lots)
            avg_px_t = int(wres.avg_price_ticks)
            avg_px = price_ticks_to_float(avg_px_t) if avg_px_t != 0 else None
            fee_micro = int(wres.fee_or_position)
            exec_px_t = avg_px_t if avg_px_t != 0 else price_ticks
            cost_val = micro_to_float(exec_px_t * filled_lots) if filled_lots > 0 else 0.0
            return {
                "id": str(wres.order_id),
                "clientOrderId": resolved_client_oid,
                "symbol": self._unified_symbol_for_market(m),
                "marketId": mid,
                "type": type_norm,
                "side": "buy" if side_str == "bid" else "sell",
                "price": price_ticks_to_float(price_ticks) if price_ticks != 0 else avg_px,
                "average": avg_px,
                "amount": qty_lots_to_float(qty_lots),
                "filled": qty_lots_to_float(filled_lots),
                "remaining": qty_lots_to_float(resting_lots),
                "cost": cost_val,
                "fee": {"cost": micro_to_float(fee_micro), "currency": "USD"},
                "status": _wire_status_from_order_res(wres.order_status.name, filled_lots, resting_lots),
                "walSeq": int(wres.wal_seq),
                "info": {
                    "ok": True,
                    "status": wres.status_code.name,
                    "order_status": wres.order_status.name,
                    "order_id": wres.order_id,
                    "wal_seq": wres.wal_seq,
                    "filled_lots": filled_lots,
                    "resting_lots": resting_lots,
                    "avg_price_ticks": avg_px_t,
                    "net_fee_micro": fee_micro,
                    "client_tag": client_tag,
                },
            }

        res = self.http.place_order(
            account_id=aid,
            market_id=mid,
            side=side_str,
            price_ticks=price_ticks,
            qty_lots=qty_lots,
            tif=tif_raw,
            reduce_only=reduce_only,
            is_market=is_market,
            post_only_slide=post_only_slide,
            min_qty_lots=min_qty_lots,
            client_tag=client_tag,
            primary_peg=bool(p.get("primary_peg", False)),
            midpoint_peg=bool(p.get("midpoint_peg", False)),
            margin_spot=margin_spot,
            display_qty_lots=display_qty_lots,
            dark_midpoint=bool(p.get("dark_midpoint", False)),
            auto_skew_ticks=int(p.get("auto_skew_ticks", 0)),
            peg_offset_ticks=int(p.get("peg_offset_ticks", 0)),
            oco_linked=bool(p.get("oco_linked", False)),
            max_lifetime_wal_seqs=int(p.get("max_lifetime_wal_seqs", 0)),
            jit_elastic_mult=jit_elastic_mult,
            mark_peg=bool(p.get("mark_peg", False)),
            auto_flip_ticks=int(p.get("auto_flip_ticks", 0)),
            trailing_peg=bool(p.get("trailing_peg", False)),
            stp=stp_raw,
            stp_decrement_and_cancel=stp_dc,
            priority_fee_ppm=priority_fee_ppm,
        )
        if not res.get("ok"):
            raise RuntimeError(f"POST /order rejected: {res}")
        filled_lots = int(res.get("filled_lots", 0))
        resting_lots = int(res.get("resting_lots", 0))
        avg_px_t = int(res.get("avg_price_ticks", 0))
        avg_px = price_ticks_to_float(avg_px_t) if avg_px_t != 0 else None
        fee_micro = int(res.get("net_fee_micro", res.get("fee_micro", 0)))
        exec_px_t = avg_px_t if avg_px_t != 0 else price_ticks
        cost_val = micro_to_float(exec_px_t * filled_lots) if filled_lots > 0 else 0.0
        return {
            "id": str(res.get("order_id_str", res.get("order_id", 0))),
            "clientOrderId": resolved_client_oid,
            "symbol": self._unified_symbol_for_market(m),
            "marketId": mid,
            "type": type_norm,
            "side": "buy" if side_str == "bid" else "sell",
            "price": price_ticks_to_float(price_ticks) if price_ticks != 0 else avg_px,
            "average": avg_px,
            "amount": qty_lots_to_float(qty_lots),
            "filled": qty_lots_to_float(filled_lots),
            "remaining": qty_lots_to_float(resting_lots),
            "cost": cost_val,
            "fee": {"cost": micro_to_float(fee_micro), "currency": "USD"},
            "status": _wire_status_from_order_res(str(res.get("order_status", "")), filled_lots, resting_lots),
            "walSeq": int(res.get("wal_seq", 0)),
            "info": res,
        }

    def create_limit_order(
        self,
        symbol: str | int,
        side: str,
        amount: int | float | str | Decimal,
        price: int | float | str | Decimal,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(symbol, "limit", side, amount, price, params)

    def create_market_order(
        self,
        symbol: str | int,
        side: str,
        amount: int | float | str | Decimal,
        price: Optional[int | float | str | Decimal | Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(price, dict) and params is None:
            params, price = price, None
        return self.create_order(symbol, "market", side, amount, price, params)

    def create_limit_buy_order(
        self,
        symbol: str | int,
        amount: int | float | str | Decimal,
        price: int | float | str | Decimal,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(symbol, "limit", "buy", amount, price, params)

    def create_limit_sell_order(
        self,
        symbol: str | int,
        amount: int | float | str | Decimal,
        price: int | float | str | Decimal,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(symbol, "limit", "sell", amount, price, params)

    def create_market_buy_order(
        self,
        symbol: str | int,
        amount: int | float | str | Decimal,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(symbol, "market", "buy", amount, None, params)

    def create_market_sell_order(
        self,
        symbol: str | int,
        amount: int | float | str | Decimal,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(symbol, "market", "sell", amount, None, params)

    def _resolve_ccxt_price_ticks(
        self,
        m: Dict[str, Any],
        price: Optional[int | float | str | Decimal],
        p: Dict[str, Any],
        *,
        is_market: bool,
        is_pegged: bool,
    ) -> int:
        is_spread = str(m.get("kind", "")).lower() == "spread_book"
        if "price_ticks" in p and p["price_ticks"] is not None:
            pt = _validate_price_ticks_48(int(p["price_ticks"]), "price_ticks")
        elif is_spread and "differential_usd" in p and p["differential_usd"] is not None:
            offset_t = int(m.get("offset_ticks", 1_000_000))
            pt = offset_t + usd_to_price_ticks(
                p["differential_usd"], allow_zero=True, allow_negative=True
            )
        elif (is_market or is_pegged) and price is None:
            pt = 0
        elif price is None:
            raise ValueError(
                "Limit order requires exact USD price (or price_ticks / differential_usd in params)"
            )
        else:
            pt = usd_to_price_ticks(
                price, allow_zero=(is_spread or is_pegged), allow_negative=is_spread
            )
        if not is_market and not is_pegged and pt <= 0:
            if is_spread:
                raise ValueError(
                    "SpreadBook limit price_ticks must be > 0 (shifted by offset_ticks=1000000 / $10,000.00 par; "
                    "pass price=10000+diff or params={'differential_usd': ...})"
                )
            raise ValueError(f"Limit order price_ticks must be > 0 (got {pt})")
        return _validate_price_ticks_48(pt, "price_ticks")

    def preview_order(
        self,
        symbol: str | int,
        order_type: Optional[str] = None,
        side: str = "buy",
        amount: int | float | str | Decimal = 0.0,
        price: Optional[int | float | str | Decimal] = None,
        params: Optional[Dict[str, Any]] = None,
        *,
        type: Optional[str] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        m = self.resolve_market(symbol)
        mid = int(m["market_id"])
        aid = int(p.get("account_id", self.account_id))
        if aid < 0:
            raise ValueError("account_id must be >= 0 before previewing orders")
        qty_lots = base_to_qty_lots(amount)
        eff_type = order_type if order_type is not None else (type if type is not None else p.get("type", "limit"))
        type_norm = str(eff_type or "limit").strip().lower()
        side_norm = str(side or "").strip().lower()
        if side_norm in ("buy", "bid"):
            side_str = "bid"
        elif side_norm in ("sell", "ask"):
            side_str = "ask"
        else:
            raise ValueError(f"Unsupported side {side!r}; expected buy|sell|bid|ask")
        is_market = type_norm == "market"
        is_pegged = any(
            bool(p.get(flag_k, False))
            for flag_k in ("primary_peg", "midpoint_peg", "mark_peg", "trailing_peg", "dark_midpoint")
        )
        price_ticks = self._resolve_ccxt_price_ticks(
            m, price, p, is_market=is_market, is_pegged=is_pegged
        )
        tif_raw = str(p.get("tif", p.get("timeInForce", "ioc" if is_market else "gtc"))).strip().lower()
        if bool(p.get("postOnly", False)) and tif_raw == "gtc":
            tif_raw = "post_only"
        stp_raw = str(p.get("stp", "cancel_resting")).strip().lower()
        stp_dc = bool(p.get("stp_decrement_and_cancel", stp_raw in ("decrement_and_cancel", "dc")))
        reduce_only = bool(p.get("reduceOnly", p.get("reduce_only", False)))
        raw_client_oid = p.get("clientOrderId", p.get("client_order_id"))
        if p.get("client_tag") is not None:
            client_tag = int(p["client_tag"])
        elif isinstance(raw_client_oid, str) and raw_client_oid.strip():
            client_tag = _client_order_id_to_tag62(raw_client_oid)
        elif isinstance(raw_client_oid, int) and raw_client_oid > 0:
            client_tag = (int(raw_client_oid) & CANCEL_ALL_TAG_MASK) or 1
        else:
            client_tag = 0
        min_qty_lots = base_to_qty_lots(p["min_qty_base"]) if "min_qty_base" in p else int(p.get("min_qty_lots", 0))
        display_qty_lots = (
            base_to_qty_lots(p["display_qty_base"])
            if "display_qty_base" in p
            else int(p.get("display_qty_lots", 0))
        )
        priority_fee_ppm = int(p.get("priority_fee_ppm", 0))
        if not (0 <= priority_fee_ppm <= MAX_PRIORITY_FEE_PPM):
            raise ValueError(f"priority_fee_ppm {priority_fee_ppm} out of [0, {MAX_PRIORITY_FEE_PPM}]")
        res = self.http.preview_order(
            account_id=aid,
            market_id=mid,
            side=side_str,
            price_ticks=price_ticks,
            qty_lots=qty_lots,
            tif=tif_raw,
            reduce_only=reduce_only,
            is_market=is_market,
            post_only_slide=bool(p.get("post_only_slide", False)),
            min_qty_lots=min_qty_lots,
            client_tag=client_tag,
            primary_peg=bool(p.get("primary_peg", False)),
            midpoint_peg=bool(p.get("midpoint_peg", False)),
            margin_spot=bool(p.get("margin_spot", False)),
            display_qty_lots=display_qty_lots,
            dark_midpoint=bool(p.get("dark_midpoint", False)),
            auto_skew_ticks=int(p.get("auto_skew_ticks", 0)),
            peg_offset_ticks=int(p.get("peg_offset_ticks", 0)),
            oco_linked=bool(p.get("oco_linked", False)),
            max_lifetime_wal_seqs=int(p.get("max_lifetime_wal_seqs", 0)),
            jit_elastic_mult=int(p.get("jit_elastic_mult", 0)),
            mark_peg=bool(p.get("mark_peg", False)),
            auto_flip_ticks=int(p.get("auto_flip_ticks", 0)),
            trailing_peg=bool(p.get("trailing_peg", False)),
            stp=stp_raw,
            stp_decrement_and_cancel=stp_dc,
            priority_fee_ppm=priority_fee_ppm,
        )
        est_filled = int(res.get("estimated_filled_lots", 0))
        est_resting = int(res.get("estimated_resting_lots", 0))
        avg_px_t = int(res.get("estimated_avg_price_ticks", 0))
        est_fee_micro = int(
            res.get("estimated_fee_micro", res.get("estimated_net_fee_micro", 0))
        )
        would_acc = bool(res.get("would_accept", False))
        status_str = str(res.get("status", ""))
        pre_imr_m = int(res.get("pre_imr_micro", 0))
        post_imr_m = int(res.get("post_imr_micro", 0))
        return {
            "preview": True,
            "wouldAccept": would_acc,
            "status": status_str,
            "rejectionReason": None if would_acc else (status_str or "rejected"),
            "symbol": self._unified_symbol_for_market(m),
            "marketId": mid,
            "type": type_norm,
            "side": "buy" if side_str == "bid" else "sell",
            "price": price_ticks_to_float(int(res.get("effective_price_ticks", price_ticks))),
            "average": price_ticks_to_float(avg_px_t) if avg_px_t != 0 else None,
            "amount": qty_lots_to_float(qty_lots),
            "estimatedFilled": qty_lots_to_float(est_filled),
            "estimatedResting": qty_lots_to_float(est_resting),
            "estimatedNetFeeUsd": micro_to_float(est_fee_micro),
            "preImrUsd": micro_to_float(pre_imr_m),
            "postImrUsd": micro_to_float(post_imr_m),
            "marginDeltaUsd": micro_to_float(post_imr_m - pre_imr_m),
            "postFreeMarginUsd": micro_to_float(int(res.get("post_free_margin_micro", 0))),
            "walSeq": int(res.get("wal_seq", 0)),
            "info": res,
        }

    def edit_order(
        self,
        order_id: str | int,
        symbol: str | int,
        order_type: str,
        side: str,
        amount: int | float | str | Decimal,
        price: Optional[int | float | str | Decimal] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = (order_type, side)
        p = dict(params or {})
        m = self.resolve_market(symbol)
        mid = int(m["market_id"])
        aid = self._effective_account_id(p)
        oid = int(order_id)
        new_ticks = self._resolve_ccxt_price_ticks(
            m, price, p, is_market=False, is_pegged=False
        )
        new_lots = base_to_qty_lots(amount)
        keep_priority = bool(p.get("keep_priority", False))
        if bool(p.get("use_binary_wire", False)):
            bin_cli = self._ensure_binary(account_id=aid)
            wres = bin_cli.modify_order(
                market_id=mid,
                order_id=oid,
                new_price_ticks=new_ticks,
                new_qty_lots=new_lots,
                keep_priority=keep_priority,
                account_id=aid,
            )
            if wres.status_code != WireStatusCode.OK:
                raise RuntimeError(f"Wire modify_order rejected ({wres.status_code.name})")
            return {
                "id": str(wres.order_id or oid),
                "symbol": self._unified_symbol_for_market(m),
                "price": price_ticks_to_float(new_ticks),
                "amount": qty_lots_to_float(new_lots),
                "remaining": qty_lots_to_float(int(wres.resting_lots)),
                "status": "open",
                "walSeq": int(wres.wal_seq),
                "info": {"ok": True, "order_id": wres.order_id, "wal_seq": wres.wal_seq},
            }
        res = self.http.modify_order(
            account_id=aid,
            market_id=mid,
            order_id=oid,
            price_ticks=new_ticks,
            qty_lots=new_lots,
            keep_priority=keep_priority,
        )
        if not res.get("ok"):
            raise RuntimeError(f"POST /modify rejected: {res}")
        return {
            "id": str(res.get("order_id_str", res.get("order_id", oid))),
            "symbol": self._unified_symbol_for_market(m),
            "price": price_ticks_to_float(new_ticks),
            "amount": qty_lots_to_float(new_lots),
            "remaining": qty_lots_to_float(int(res.get("resting_lots", 0))),
            "status": "open",
            "walSeq": int(res.get("wal_seq", 0)),
            "info": res,
        }

    def cancel_order(
        self,
        order_id: Optional[int | str] = None,
        symbol: Optional[str | int] = None,
        params: Optional[Dict[str, Any]] = None,
        *,
        id: Optional[int | str] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        eff_oid = order_id if order_id is not None else (id if id is not None else p.get("order_id", p.get("id")))
        if eff_oid is None:
            raise ValueError("order_id (or id=) is required to cancel an order")
        oid = int(eff_oid)
        aid = self._effective_account_id(p)
        eff_sym = symbol if symbol is not None else p.get("symbol", p.get("market_id"))
        if eff_sym is not None:
            m = self.resolve_market(eff_sym)
        else:
            acct_resp = self.http.account(aid)
            if not acct_resp.get("ok"):
                raise RuntimeError(f"GET /account failed while resolving order {oid}: {acct_resp}")
            matched_mid: Optional[int] = None
            for o in list(acct_resp.get("open_orders", [])):
                if int(o.get("order_id", -1)) == oid:
                    matched_mid = int(o["market_id"])
                    break
            if matched_mid is None:
                raise ValueError("symbol (or market_id in params) is required when order is not in open_orders")
            m = self.resolve_market(matched_mid)
        mid = int(m["market_id"])
        if bool(p.get("use_binary_wire", False)):
            bin_cli = self._ensure_binary(account_id=aid)
            wres = bin_cli.cancel_order(market_id=mid, order_id=oid, account_id=aid)
            if wres.status_code != WireStatusCode.OK:
                raise RuntimeError(f"Wire cancel_order rejected ({wres.status_code.name})")
            return {
                "id": str(oid),
                "symbol": self._unified_symbol_for_market(m),
                "status": "canceled",
                "walSeq": int(wres.wal_seq),
                "info": {"ok": True, "order_id": wres.order_id, "wal_seq": wres.wal_seq},
            }
        res = self.http.cancel_order(account_id=aid, market_id=mid, order_id=oid)
        if not res.get("ok"):
            raise RuntimeError(f"POST /cancel rejected: {res}")
        return {
            "id": str(oid),
            "symbol": self._unified_symbol_for_market(m),
            "status": "canceled",
            "walSeq": int(res.get("wal_seq", 0)),
            "info": res,
        }

    def set_margin_mode(
        self,
        margin_mode: Optional[str] = None,
        symbol: Optional[str | int] = None,
        params: Optional[Dict[str, Any]] = None,
        *,
        marginMode: Optional[str] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        raw_mode = (
            margin_mode
            if margin_mode is not None
            else (marginMode if marginMode is not None else p.get("marginMode", p.get("margin_mode", "")))
        )
        mode_norm = str(raw_mode or "").strip().lower()
        if mode_norm not in ("cross", "crossed"):
            raise ValueError(
                f"Unsupported marginMode {raw_mode!r}; Arena Exchange enforces unified Eigen-SPAN cross margin ('cross')"
            )
        eff_sym = symbol if symbol is not None else p.get("symbol", p.get("market_id"))
        unified: Optional[str] = None
        mid: Optional[int] = None
        if eff_sym is not None:
            m = self.resolve_market(eff_sym)
            mid = int(m["market_id"])
            unified = self._unified_symbol_for_market(m)
        info_obj: Dict[str, Any] = {
            "ok": True,
            "margin_mode": "cross",
            "engine": "eigen_span_cross_margin",
            "market_id": mid,
        }
        return {
            "ok": True,
            "marginMode": "cross",
            "symbol": unified,
            "marketId": mid,
            "info": info_obj,
        }

    def set_leverage(
        self,
        leverage: int | float | str | Decimal,
        symbol: Optional[str | int] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        lev_f = float(leverage)
        if not math.isfinite(lev_f) or lev_f <= 0.0:
            raise ValueError(f"leverage must be > 0, got {leverage!r}")
        eff_sym = symbol if symbol is not None else p.get("symbol", p.get("market_id"))
        unified: Optional[str] = None
        mid: Optional[int] = None
        max_lev: Optional[float] = None
        if eff_sym is not None:
            m = self.resolve_market(eff_sym)
            mid = int(m["market_id"])
            unified = self._unified_symbol_for_market(m)
            imr_bps = int(m.get("imr_bps", 0))
            if imr_bps > 0:
                max_lev = 10000.0 / float(imr_bps)
        info_obj: Dict[str, Any] = {
            "ok": True,
            "noop": True,
            "margin_mode": "cross",
            "requested_leverage": lev_f,
            "max_leverage": max_lev,
            "market_id": mid,
        }
        return {
            "ok": True,
            "leverage": lev_f,
            "marginMode": "cross",
            "symbol": unified,
            "marketId": mid,
            "maxLeverage": max_lev,
            "info": info_obj,
        }

    def cancel_all_orders(
        self,
        symbol: Optional[str | int] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        aid = self._effective_account_id(p)
        mid = int(self.resolve_market(symbol)["market_id"]) if symbol is not None else 0
        tag = int(p.get("client_tag_filter", 0))
        mask = int(p.get("market_bitmask", 0))
        side_f = p.get("side_filter", p.get("side", 0))
        if bool(p.get("use_binary_wire", False)):
            bin_cli = self._ensure_binary(account_id=aid)
            wres = bin_cli.cancel_all(
                market_id=mid,
                client_tag_filter=tag,
                market_bitmask=mask,
                side_filter=side_f,
                account_id=aid,
            )
            if wres.status_code != WireStatusCode.OK:
                raise RuntimeError(f"Wire cancel_all rejected ({wres.status_code.name})")
            return {
                "ok": True,
                "canceled_orders": int(wres.filled_lots),
                "walSeq": int(wres.wal_seq),
                "info": {"ok": True, "wal_seq": wres.wal_seq, "canceled_orders": int(wres.filled_lots)},
            }
        res = self.http.cancel_all(
            account_id=aid,
            market_id=mid,
            client_tag_filter=tag,
            market_bitmask=mask,
            side_filter=side_f,
        )
        if not res.get("ok"):
            raise RuntimeError(f"POST /cancel_all rejected: {res}")
        return res

    def withdraw(
        self,
        code: str,
        amount: int | float | str | Decimal,
        address: str,
        tag: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = tag
        p = dict(params or {})
        aid = self._effective_account_id(p)
        c_up = str(code or "USD").strip().upper()
        if "asset_id" in p:
            asset_id = int(p["asset_id"])
        elif c_up in ("USD", "USDC"):
            asset_id = 0
        else:
            mkt = self.resolve_market(f"{c_up}-USD-SPOT")
            asset_id = int(mkt["base_asset_id"])
        raw_amt = usd_to_micro(amount) if asset_id == 0 else base_to_qty_lots(amount)
        res = self.http.withdraw(
            account_id=aid,
            amount=raw_amt,
            asset_id=asset_id,
            recipient_eth_address=str(address),
        )
        if not res.get("ok"):
            raise RuntimeError(f"POST /withdraw rejected: {res}")
        w_obj = res.get("withdrawal") if isinstance(res.get("withdrawal"), dict) else {}
        wid = w_obj.get("withdrawal_id_str") or w_obj.get("withdrawal_id") or res.get("withdrawal_id", "")
        return {
            "id": str(wid),
            "currency": c_up,
            "amount": float(_parse_exact_decimal(amount, "amount")),
            "address": str(address),
            "info": res,
        }

    def subscribe_express_port(
        self,
        duration_epochs: int = 1,
        max_fee_usd_micro: int = 0,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        p = dict(params or {})
        dur_i = int(p.get("duration_epochs", duration_epochs))
        max_fee_i = int(p.get("max_fee_usd_micro", max_fee_usd_micro))
        if not (1 <= dur_i <= MAX_EXPRESS_PORT_LEASE_EPOCHS):
            raise ValueError(
                f"duration_epochs {dur_i} out of [1, {MAX_EXPRESS_PORT_LEASE_EPOCHS}]"
            )
        if max_fee_i < 0:
            raise ValueError("max_fee_usd_micro must be >= 0")
        aid = self._effective_account_id(p)
        if bool(p.get("use_binary_wire", False)):
            bin_cli = self._ensure_binary(account_id=aid)
            wres = bin_cli.subscribe_express_port(
                duration_epochs=dur_i,
                max_fee_usd_micro=max_fee_i,
                account_id=aid,
            )
            if wres.status_code != WireStatusCode.OK:
                raise RuntimeError(f"Wire subscribe_express_port rejected ({wres.status_code.name})")
            return {
                "ok": True,
                "account_id": aid,
                "epochs_purchased": int(wres.filled_lots),
                "lease_epochs_remaining": int(wres.order_id),
                "fee_paid_usd_micro": int(wres.avg_price_ticks),
                "free_usd_after_micro": int(wres.best_bid_ticks),
                "fee_per_epoch_usd_micro": int(wres.best_ask_ticks),
                "walSeq": int(wres.wal_seq),
                "info": {
                    "ok": True,
                    "wal_seq": wres.wal_seq,
                    "account_id": aid,
                    "epochs_purchased": int(wres.filled_lots),
                    "lease_epochs_remaining": int(wres.order_id),
                    "fee_paid_usd_micro": int(wres.avg_price_ticks),
                    "free_usd_after_micro": int(wres.best_bid_ticks),
                    "fee_per_epoch_usd_micro": int(wres.best_ask_ticks),
                },
            }
        res = self.http.subscribe_express_port(
            account_id=aid,
            duration_epochs=dur_i,
            max_fee_usd_micro=max_fee_i,
        )
        if not res.get("ok"):
            raise RuntimeError(f"POST /account/express_port rejected: {res}")
        return {
            "ok": True,
            "account_id": int(res.get("account_id", aid)),
            "epochs_purchased": int(res.get("epochs_purchased", dur_i)),
            "lease_epochs_remaining": int(res.get("lease_epochs_remaining", 0)),
            "fee_paid_usd_micro": int(res.get("fee_paid_usd_micro", 0)),
            "free_usd_after_micro": int(res.get("free_usd_after_micro", 0)),
            "fee_per_epoch_usd_micro": int(res.get("fee_per_epoch_usd_micro", 0)),
            "walSeq": int(res.get("wal_seq", 0)),
            "info": res,
        }

    # Standard CCXT camelCase method aliases
    loadMarkets = load_markets
    fetchMarkets = fetch_markets
    fetchTicker = fetch_ticker
    fetchTickers = fetch_tickers
    fetchOrderBook = fetch_order_book
    fetchL2OrderBook = fetch_l2_order_book
    fetchTrades = fetch_trades
    fetchMyTrades = fetch_my_trades
    fetchOHLCV = fetch_ohlcv
    fetchFundingRate = fetch_funding_rate
    fetchBalance = fetch_balance
    fetchPositions = fetch_positions
    fetchOpenOrders = fetch_open_orders
    createOrder = create_order
    createLimitOrder = create_limit_order
    createMarketOrder = create_market_order
    createLimitBuyOrder = create_limit_buy_order
    createLimitSellOrder = create_limit_sell_order
    createMarketBuyOrder = create_market_buy_order
    createMarketSellOrder = create_market_sell_order
    previewOrder = preview_order
    editOrder = edit_order
    cancelOrder = cancel_order
    cancelAllOrders = cancel_all_orders
    setLeverage = set_leverage
    setMarginMode = set_margin_mode
    loginWithWallet = login_with_wallet
    setSandboxMode = set_sandbox_mode
    fetchLeaderboard = fetch_leaderboard
    subscribeExpressPort = subscribe_express_port


ArenaHftClient = ArenaBinaryClient
ArenaWireClient = ArenaBinaryClient
ArenaRestClient = ArenaHttpClient
ArenaWsClient = ArenaWebSocketClient
ArenaItchMessage = ArenaItchEvent
ArenaItchBookReconstructor = ItchOrderBookReconstructor
ArenaCcxtExchange = ArenaCcxtAdapter


def _run_self_test() -> int:
    import http.server
    import sys
    import tempfile

    # 1. Verify ArenaHttpClient.wind_down_pools existence & POST /admin/wind_down_pools dispatch
    if not callable(getattr(ArenaHttpClient, "wind_down_pools", None)):
        print("[FAIL] ArenaHttpClient.wind_down_pools method missing", file=sys.stderr)
        return 1

    pending_nonce = 0
    observed_tx_count = 0
    wind_down_calls: List[str] = []

    class _SdkTestHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            _ = (fmt, args)

        def do_POST(self) -> None:
            nonlocal pending_nonce, observed_tx_count
            clen = int(self.headers.get("Content-Length", "0"))
            raw_req = self.rfile.read(clen) if clen > 0 else b"{}"
            if self.path == "/admin/wind_down_pools":
                wind_down_calls.append(raw_req.decode("utf-8", errors="replace"))
                out_b = json.dumps({"ok": True, "pools_wound_down": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out_b)))
                self.end_headers()
                self.wfile.write(out_b)
                return

            req_obj = json.loads(raw_req.decode("utf-8"))
            rid = req_obj.get("id", 1)
            method = str(req_obj.get("method", ""))
            if method == "anvil_dumpState":
                res: Any = "0x" + ("ab" * 2048)
            elif method == "eth_chainId":
                res = "0x7a69"
            elif method == "eth_gasPrice":
                res = "0x3b9aca00"
            elif method == "eth_getBlockByNumber":
                res = {"baseFeePerGas": "0x3b9aca00"}
            elif method == "eth_maxPriorityFeePerGas":
                res = "0x3b9aca00"
            elif method == "eth_getTransactionCount":
                res = hex(pending_nonce)
            elif method == "eth_sendRawTransaction":
                pending_nonce += 1
                observed_tx_count += 1
                res = "0x" + f"{observed_tx_count:064x}"
            else:
                res = "0x0"

            out_b = json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_b)))
            self.end_headers()
            self.wfile.write(out_b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SdkTestHandler)
    port = int(srv.server_address[1])
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        http_cli = ArenaHttpClient(base_url=base_url, timeout=5.0)
        try:
            wd_res = http_cli.wind_down_pools()
            if not wd_res.get("ok") or len(wind_down_calls) != 1:
                print(f"[FAIL] wind_down_pools unexpected result: {wd_res}", file=sys.stderr)
                return 1
        finally:
            http_cli.close()

        # 2. Verify EvmJsonRpcClient.rpc max_response_bytes enforcement & override
        evm_plain = EvmJsonRpcClient(base_url, timeout=5.0)
        try:
            caught_cap = False
            try:
                _ = evm_plain.rpc("anvil_dumpState", [], max_response_bytes=2048)
            except RuntimeError as exc:
                if "exceeded" in str(exc) and "limit" in str(exc):
                    caught_cap = True
            if not caught_cap:
                print("[FAIL] EvmJsonRpcClient.rpc did not enforce max_response_bytes=2048", file=sys.stderr)
                return 1

            big_res = evm_plain.rpc("anvil_dumpState", [], max_response_bytes=65536)
            if not isinstance(big_res, str) or len(big_res) < 4098:
                print(f"[FAIL] EvmJsonRpcClient.rpc failed with raised max_response_bytes: {len(str(big_res))}", file=sys.stderr)
                return 1
        finally:
            evm_plain.close()

        # 3. Verify _acquire_tx_file_lock contention & cross-client nonce cache invalidation
        with tempfile.TemporaryDirectory() as tmp_d:
            lock_file = str(Path(tmp_d) / "locks" / "evm.tx.lock")
            with _acquire_tx_file_lock(lock_file, timeout_sec=2.0):
                contended = False
                try:
                    with _acquire_tx_file_lock(lock_file, timeout_sec=0.06):
                        contended = False
                except TimeoutError:
                    contended = True
                if not contended:
                    print("[FAIL] _acquire_tx_file_lock did not block concurrent lock acquisition", file=sys.stderr)
                    return 1

            signer = EthWalletSigner("0x" + ("11" * 32))
            recipient = "0x2000000000000000000000000000000000000002"
            evm_a = EvmJsonRpcClient(base_url, timeout=5.0, tx_lock_file=lock_file)
            evm_b = EvmJsonRpcClient(base_url, timeout=5.0, tx_lock_file=lock_file)
            try:
                _ = evm_a.send_transaction(signer, recipient, b"", gas_limit=21_000)
                if evm_a._next_nonce_by_addr.get(signer.address.lower()) != 1:
                    print("[FAIL] Expected evm_a cached next nonce == 1 after tx #1", file=sys.stderr)
                    return 1
                # Simulate external process sending a transaction using the same wallet
                _ = evm_b.send_transaction(signer, recipient, b"", gas_limit=21_000)
                if pending_nonce != 2:
                    print(f"[FAIL] Expected server pending_nonce == 2, got {pending_nonce}", file=sys.stderr)
                    return 1
                # evm_a must invalidate its stale cached nonce (1) under tx_lock_file and use pending_nonce (2)
                _ = evm_a.send_transaction(signer, recipient, b"", gas_limit=21_000)
                if evm_a._next_nonce_by_addr.get(signer.address.lower()) != 3:
                    print(
                        f"[FAIL] tx_lock_file did not refresh stale nonce cache on evm_a: {evm_a._next_nonce_by_addr}",
                        file=sys.stderr,
                    )
                    return 1
            finally:
                evm_a.close()
                evm_b.close()
    finally:
        srv.shutdown()
        srv.server_close()

    # 4. Verify ArenaBinaryClient.rotate_session_key adopts server seq_hi50 (resting_lots) & resets next_seq_lo=1
    rot_cli = ArenaBinaryClient(42, tcp_port=19100)
    rot_cli.send_frame = lambda frame, **kw: ArenaWireResponse(  # type: ignore[method-assign]
        status_code=WireStatusCode.OK,
        order_status=WireOrderStatus.NONE,
        wal_seq=1,
        order_id=0,
        filled_lots=0,
        resting_lots=9,
        avg_price_ticks=0,
        best_bid_ticks=0,
        best_ask_ticks=0,
        fee_or_position=0,
    )
    rot_resp = rot_cli.rotate_session_key(0x1111_2222_3333_4444, 0x5555_6666_7777_8888)
    if (
        rot_resp.status_code != WireStatusCode.OK
        or rot_cli.seq_hi50 != 9
        or rot_cli.peek_next_seq_lo() != 1
        or 42 not in rot_cli._verified_seq_by_account
    ):
        print(
            f"[FAIL] rotate_session_key did not adopt server seq_hi50=9 & next_seq_lo=1: hi50={rot_cli.seq_hi50} lo={rot_cli.peek_next_seq_lo()}",
            file=sys.stderr,
        )
        return 1

    # 5. Verify Gladiator Launchpad SDK additions: ArenaWsClient, per-call account_id frames,
    #    EVM calldata encoders, ArenaCcxtAdapter(client/dict/camelCase/SpreadBook), and previewOrder
    if ArenaWsClient is not ArenaWebSocketClient:
        print("[FAIL] ArenaWsClient alias mismatch", file=sys.stderr)
        return 1
    if KNOWN_PUBLIC_RPC_BY_CHAIN_ID.get(84532) != "https://sepolia.base.org":
        print("[FAIL] KNOWN_PUBLIC_RPC_BY_CHAIN_ID missing Base Sepolia 84532", file=sys.stderr)
        return 1
    dep_cd = encode_deposit_trader_margin_calldata(77, 0, 10_000_000)
    if len(dep_cd) != (2 + 8 + 3 * 64):
        print(f"[FAIL] encode_deposit_trader_margin_calldata bad length: {len(dep_cd)}", file=sys.stderr)
        return 1
    v_cd = encode_claim_withdrawal_voucher_calldata(
        {
            "withdrawal_id": 1,
            "wal_seq": 5,
            "account_id": 77,
            "asset_id": 0,
            "amount": 10_000_000,
            "recipient_eth_address": "0x2000000000000000000000000000000000000002",
            "state_root": "0x" + ("ab" * 32),
            "operator_signature": "0x" + ("cd" * 65),
        }
    )
    if not v_cd.startswith("0x") or len(v_cd) < 522:
        print(f"[FAIL] encode_claim_withdrawal_voucher_calldata bad output: {len(v_cd)}", file=sys.stderr)
        return 1

    hdr_mr, _, _, _ = unpack_wire_frame(rot_cli.build_mint_redeem_frame(10, OrderSide.BID, 50, account_id=99))
    hdr_fa, _, _, _ = unpack_wire_frame(rot_cli.build_flash_arbitrage_frame(10, OrderSide.BID, 50, is_market=True, account_id=99))
    if hdr_mr.account_id != 99 or hdr_fa.account_id != 99:
        print(f"[FAIL] per-call account_id override failed: mr={hdr_mr.account_id} fa={hdr_fa.account_id}", file=sys.stderr)
        return 1

    base_cli = ArenaHttpClient("http://127.0.0.1:8080", api_key="k1", api_secret="s1", timeout=7.5)
    ccxt_from_cli = ArenaCcxtAdapter(base_cli, account_id=12)
    ccxt_from_dict = ArenaCcxtAdapter(
        {"url": "http://127.0.0.1:8080", "apiKey": "k2", "secret": "s2", "accountId": 15, "timeout": 8000}
    )
    try:
        if ccxt_from_cli.http.api_key != "k1" or ccxt_from_cli.timeout != 7.5:
            print("[FAIL] ArenaCcxtAdapter(ArenaHttpClient) credential copy failed", file=sys.stderr)
            return 1
        if ccxt_from_dict.http.api_key != "k2" or ccxt_from_dict.account_id != 15 or ccxt_from_dict.timeout != 8.0:
            print("[FAIL] ArenaCcxtAdapter(dict) config parse failed", file=sys.stderr)
            return 1
        for camel_m in (
            "loadMarkets",
            "fetchMarkets",
            "fetchTicker",
            "fetchTickers",
            "fetchOrderBook",
            "fetchTrades",
            "fetchOHLCV",
            "fetchBalance",
            "fetchPositions",
            "fetchOpenOrders",
            "createOrder",
            "createLimitBuyOrder",
            "createLimitSellOrder",
            "createMarketBuyOrder",
            "createMarketSellOrder",
            "previewOrder",
            "editOrder",
            "cancelOrder",
            "cancelAllOrders",
            "setSandboxMode",
            "fetchLeaderboard",
        ):
            if not callable(getattr(ccxt_from_dict, camel_m, None)):
                print(f"[FAIL] ArenaCcxtAdapter missing camelCase alias {camel_m}", file=sys.stderr)
                return 1
        sb_mkt = {"market_id": 17, "symbol": "BTC-BASIS-SPRD", "kind": "spread_book", "offset_ticks": 1_000_000}
        if ccxt_from_dict._resolve_ccxt_price_ticks(sb_mkt, None, {"differential_usd": "-5.25"}, is_market=False, is_pegged=False) != 999_475:
            print("[FAIL] SpreadBook differential_usd resolution failed", file=sys.stderr)
            return 1
        caught_neg_sb = False
        try:
            _ = ccxt_from_dict._resolve_ccxt_price_ticks(sb_mkt, "-5.25", {}, is_market=False, is_pegged=False)
        except ValueError as sb_err:
            caught_neg_sb = "offset_ticks" in str(sb_err)
        if not caught_neg_sb:
            print("[FAIL] SpreadBook negative price_ticks guard did not trigger", file=sys.stderr)
            return 1
        # Verify SSL context helper, faucet defaults, preview estimated_fee_micro, & unified+native loadMarkets
        ssl_ctx = _default_ssl_context()
        if not isinstance(ssl_ctx, ssl.SSLContext):
            print("[FAIL] _default_ssl_context did not return SSLContext", file=sys.stderr)
            return 1
        faucet_seen: Dict[str, Any] = {}
        base_cli._post = lambda path, payload, **kw: (faucet_seen.update({"path": path, "payload": payload, "kw": kw}) or {"ok": True})  # type: ignore[method-assign]
        _ = base_cli.request_testnet_faucet("0x2000000000000000000000000000000000000002", amount="5000")
        if not faucet_seen.get("payload", {}).get("drip_gas") or float(faucet_seen.get("kw", {}).get("timeout", 0)) < 45.0:
            print(f"[FAIL] request_testnet_faucet default drip_gas/timeout mismatch: {faucet_seen}", file=sys.stderr)
            return 1
        ccxt_from_dict.http.markets = lambda: {  # type: ignore[method-assign]
            "ok": True,
            "markets": [
                {"market_id": 1, "symbol": "BTC-USD-PERP", "kind": "linear_perpetual", "base_asset_id": 1, "max_order_lots": 100000, "min_price_ticks": 1, "max_price_ticks": 100000000},
            ],
        }
        ccxt_from_dict.http.preview_order = lambda **_kw: {  # type: ignore[method-assign]
            "ok": True,
            "would_accept": True,
            "status": "Ok",
            "effective_price_ticks": 5_000_000,
            "estimated_filled_lots": 100,
            "estimated_resting_lots": 0,
            "estimated_avg_price_ticks": 5_000_000,
            "estimated_fee_micro": 125_000,
            "pre_imr_micro": 0,
            "post_imr_micro": 25_000_000,
            "post_free_margin_micro": 975_000_000,
            "wal_seq": 7,
        }
        loaded_mkts = ccxt_from_dict.loadMarkets(reload=True)
        if "BTC/USD:USD" not in loaded_mkts or "BTC-USD-PERP" not in loaded_mkts or "BTC/USD:USD" not in ccxt_from_dict.markets:
            print(f"[FAIL] loadMarkets unified/native keys mismatch: {list(loaded_mkts.keys())}", file=sys.stderr)
            return 1
        prev_chk = ccxt_from_dict.previewOrder("BTC/USD:USD", "limit", "buy", "0.0100", "50000.00")
        if (
            abs(float(prev_chk["estimatedNetFeeUsd"]) - 0.125) > 1e-9
            or abs(float(prev_chk["marginDeltaUsd"]) - 25.0) > 1e-9
            or prev_chk["rejectionReason"] is not None
        ):
            print(f"[FAIL] previewOrder fee/marginDelta/rejectionReason mapping failed: {prev_chk}", file=sys.stderr)
            return 1
        ccxt_camel_cfg = ArenaCcxtAdapter({"arenaUrl": "https://arena.example.com"})
        try:
            if ccxt_camel_cfg.base_url != "https://arena.example.com":
                print(f"[FAIL] camelCase arenaUrl ignored: {ccxt_camel_cfg.base_url}", file=sys.stderr)
                return 1
        finally:
            ccxt_camel_cfg.close()
        tn_http = ArenaHttpClient.testnet()
        tn_ccxt = ArenaCcxtAdapter.testnet()
        def_ccxt = ArenaCcxtAdapter()
        try:
            if tn_http.base_url != PUBLIC_TESTNET_URL or tn_http.ws_url != PUBLIC_TESTNET_WS_URL:
                print(f"[FAIL] ArenaHttpClient.testnet() URL mismatch: {tn_http.base_url} / {tn_http.ws_url}", file=sys.stderr)
                return 1
            if tn_ccxt.base_url != PUBLIC_TESTNET_URL or not tn_ccxt.sandbox:
                print(f"[FAIL] ArenaCcxtAdapter.testnet() URL mismatch: {tn_ccxt.base_url}", file=sys.stderr)
                return 1
            if def_ccxt.base_url != DEFAULT_LOCAL_HTTP_URL:
                print(f"[FAIL] ArenaCcxtAdapter() default URL mismatch: {def_ccxt.base_url}", file=sys.stderr)
                return 1
            if def_ccxt.setSandboxMode(True) != PUBLIC_TESTNET_URL or def_ccxt.setSandboxMode(False) != DEFAULT_LOCAL_HTTP_URL:
                print("[FAIL] ArenaCcxtAdapter.setSandboxMode toggle failed", file=sys.stderr)
                return 1
            tn_ccxt.http._get = lambda path, params=None: {  # type: ignore[method-assign]
                "ok": True,
                "path": path,
                "params": dict(params or {}),
                "wal_seq": 42,
                "entries": [
                    {
                        "rank": 1,
                        "account_id": 1001,
                        "wallet_masked": "0x1234...abcd",
                        "total_equity_micro": 250_000_000,
                        "realized_pnl_micro": 12_500_000,
                        "unrealized_pnl_micro": 0,
                        "total_pnl_micro": 12_500_000,
                        "total_volume_notional_micro_128": "1000000000",
                        "roi_bps": 500,
                        "bbo_uptime_streak_epochs": 4,
                        "bbo_uptime_multiplier": "2.00x",
                    }
                ],
            }
            raw_lb_sort = tn_ccxt.http.get_leaderboard(limit=5, sort="pnl")
            raw_lb_sort_by = tn_ccxt.http.get_leaderboard(limit=5, sort_by="streak")
            if raw_lb_sort["params"]["sort"] != "pnl" or raw_lb_sort_by["params"]["sort"] != "streak":
                print("[FAIL] ArenaHttpClient.get_leaderboard sort/sort_by parameter handling failed", file=sys.stderr)
                return 1
            lb_rows = tn_ccxt.fetchLeaderboard(limit=5, sort="equity")
            if len(lb_rows) != 1 or lb_rows[0]["accountId"] != 1001 or abs(lb_rows[0]["equityUsd"] - 250.0) > 1e-9:
                print(f"[FAIL] fetchLeaderboard mapping failed: {lb_rows}", file=sys.stderr)
                return 1

            # 6. Verify v4.9.3 CCXT compatibility attributes, signatures, clientOrderId tag62, fee/cost & new methods
            if (
                def_ccxt.options != {}
                or def_ccxt.precisionMode != 4
                or def_ccxt.fees != {"trading": {"maker": 0.0, "taker": 0.0}}
                or def_ccxt.currencies != {}
                or def_ccxt.features != {
                    "spot": {"fetchOHLCV": {"limit": 240}},
                    "swap": {"linear": {"fetchOHLCV": {"limit": 240}}},
                }
            ):
                print("[FAIL] ArenaCcxtAdapter v4.9.3 CCXT instance attributes mismatch", file=sys.stderr)
                return 1
            for req_has in (
                "createLimitOrder",
                "createMarketOrder",
                "fetchL2OrderBook",
                "fetchMyTrades",
                "setLeverage",
                "setMarginMode",
                "fetchFundingRate",
            ):
                if def_ccxt.has.get(req_has) is not True:
                    print(f"[FAIL] ArenaCcxtAdapter.has missing {req_has}", file=sys.stderr)
                    return 1
            for req_alias in (
                "createLimitOrder",
                "createMarketOrder",
                "fetchL2OrderBook",
                "fetchMyTrades",
                "setLeverage",
                "setMarginMode",
                "fetchFundingRate",
            ):
                if not callable(getattr(def_ccxt, req_alias, None)):
                    print(f"[FAIL] ArenaCcxtAdapter missing camelCase method {req_alias}", file=sys.stderr)
                    return 1
            perp_entry = ccxt_from_dict.markets["BTC/USD:USD"]
            spot_entry = ccxt_from_dict._build_ccxt_market_entry(
                {"market_id": 2, "symbol": "BTC-USD-SPOT", "kind": "spot", "base_asset_id": 1}
            )
            if (
                perp_entry.get("contractSize") != 1.0
                or perp_entry.get("inverse") is not False
                or perp_entry["limits"].get("cost") != {"min": None, "max": None}
                or perp_entry["limits"].get("leverage") != {"min": 1.0, "max": None}
                or spot_entry.get("contractSize") is not None
                or spot_entry.get("inverse") is not None
            ):
                print(f"[FAIL] _build_ccxt_market_entry v4.9.3 fields mismatch: {perp_entry}", file=sys.stderr)
                return 1

            captured_place: Dict[str, Any] = {}
            ccxt_from_dict.http.place_order = lambda **kw: (  # type: ignore[method-assign]
                captured_place.update(kw)
                or {
                    "ok": True,
                    "order_id": 888,
                    "order_id_str": "888",
                    "order_status": "filled",
                    "wal_seq": 19,
                    "filled_lots": 2000,
                    "resting_lots": 0,
                    "avg_price_ticks": 5_000_000,
                    "net_fee_micro": 3_500_000,
                }
            )
            ord_kw = ccxt_from_dict.create_order(
                "BTC/USD:USD",
                side="buy",
                amount="0.2",
                price="50000",
                params={"clientOrderId": "gladiator-alpha-01"},
                type="limit",
            )
            expected_tag = _client_order_id_to_tag62("gladiator-alpha-01")
            if (
                not (0 < expected_tag <= CANCEL_ALL_TAG_MASK)
                or captured_place.get("client_tag") != expected_tag
                or abs(float(ord_kw["cost"]) - 10_000.0) > 1e-9
                or ord_kw.get("fee") != {"cost": 3.5, "currency": "USD"}
            ):
                print(f"[FAIL] create_order type=/clientOrderId/cost/fee failed: {ord_kw} / {captured_place}", file=sys.stderr)
                return 1
            lim_ord = ccxt_from_dict.createLimitOrder("BTC/USD:USD", "sell", 0.2, 50000.0)
            mkt_ord = ccxt_from_dict.createMarketOrder("BTC/USD:USD", "buy", 0.2)
            if lim_ord["type"] != "limit" or mkt_ord["type"] != "market":
                print(f"[FAIL] createLimitOrder/createMarketOrder failed: {lim_ord} / {mkt_ord}", file=sys.stderr)
                return 1

            seen_cancel: Dict[str, Any] = {}
            ccxt_from_dict.http.cancel_order = lambda account_id, market_id, order_id: (  # type: ignore[method-assign]
                seen_cancel.update({"aid": account_id, "mid": market_id, "oid": order_id})
                or {"ok": True, "wal_seq": 20}
            )
            c_kw = ccxt_from_dict.cancel_order(id="888", symbol="BTC/USD:USD")
            if c_kw["id"] != "888" or seen_cancel.get("oid") != 888:
                print(f"[FAIL] cancel_order(id=...) failed: {c_kw} / {seen_cancel}", file=sys.stderr)
                return 1

            ccxt_from_dict.http.book = lambda market_id, depth=20, include_l3=True: {  # type: ignore[method-assign]
                "ok": True,
                "wal_seq": 21,
                "depth": depth,
                "bids": [[5_000_000, 1000]],
                "asks": [[5_001_000, 1500]],
            }
            ob_l2 = ccxt_from_dict.fetchL2OrderBook("BTC/USD:USD", limit=None, params={})
            if ob_l2["info"]["depth"] != 50 or ob_l2["bids"][0] != [50000.0, 0.1]:
                print(f"[FAIL] fetchL2OrderBook(limit=None) failed: {ob_l2}", file=sys.stderr)
                return 1

            ccxt_from_dict.http.candles = lambda market_id, interval="1m", limit=120: {  # type: ignore[method-assign]
                "ok": True,
                "candles": [
                    [1000, 5_000_000, 5_010_000, 4_990_000, 5_005_000, 2500, 2],
                    [2000, 5_005_000, 5_020_000, 5_000_000, 5_015_000, 3000, 3],
                ],
            }
            bars_since = ccxt_from_dict.fetchOHLCV("BTC/USD:USD", "1m", since=1500, limit=None, params={})
            if len(bars_since) != 1 or bars_since[0][0] != 2000:
                print(f"[FAIL] fetchOHLCV(since=..., limit=None) failed: {bars_since}", file=sys.stderr)
                return 1

            ccxt_from_dict.http.trades = lambda market_id, limit=100: {  # type: ignore[method-assign]
                "ok": True,
                "trades": [
                    {
                        "trade_id": 1,
                        "wal_seq": 10,
                        "maker_account_id": 15,
                        "taker_account_id": 99,
                        "maker_order_id": 501,
                        "taker_order_id": 502,
                        "taker_side": "bid",
                        "price_ticks": 5_000_000,
                        "qty_lots": 1000,
                        "notional_micro": 5_000_000_000,
                        "maker_fee_micro": -500_000,
                        "taker_fee_micro": 1_750_000,
                    },
                    {
                        "trade_id": 2,
                        "wal_seq": 11,
                        "maker_account_id": 88,
                        "taker_account_id": 99,
                        "maker_order_id": 503,
                        "taker_order_id": 504,
                        "taker_side": "ask",
                        "price_ticks": 4_999_000,
                        "qty_lots": 1000,
                        "notional_micro": 4_999_000_000,
                        "maker_fee_micro": 0,
                        "taker_fee_micro": 1_000_000,
                    },
                ],
            }
            my_trds = ccxt_from_dict.fetchMyTrades("BTC/USD:USD", since=None, limit=None)
            if (
                len(my_trds) != 1
                or my_trds[0]["takerOrMaker"] != "maker"
                or my_trds[0]["side"] != "sell"
                or my_trds[0]["fee"]["cost"] != -0.5
            ):
                print(f"[FAIL] fetchMyTrades filtering/mapping failed: {my_trds}", file=sys.stderr)
                return 1

            ccxt_from_dict.http.ticker = lambda market_id=0: {  # type: ignore[method-assign]
                "ok": True,
                "ticker": {
                    "market_id": 1,
                    "symbol": "BTC-USD-PERP",
                    "kind": "linear_perpetual",
                    "mark_price_ticks": 5_005_000,
                    "best_bid_ticks": 5_004_000,
                    "best_ask_ticks": 5_006_000,
                    "cumulative_funding_phi": 12_345,
                },
            }
            fr_res = ccxt_from_dict.fetchFundingRate("BTC/USD:USD")
            if fr_res["symbol"] != "BTC/USD:USD" or fr_res["markPrice"] != 50050.0 or fr_res["cumulativeFundingPhi"] != 12_345:
                print(f"[FAIL] fetchFundingRate mapping failed: {fr_res}", file=sys.stderr)
                return 1

            mm_ok = ccxt_from_dict.setMarginMode("cross", "BTC/USD:USD")
            lev_ok = ccxt_from_dict.setLeverage(10, "BTC/USD:USD")
            if mm_ok["marginMode"] != "cross" or lev_ok["leverage"] != 10.0:
                print(f"[FAIL] setMarginMode/setLeverage failed: {mm_ok} / {lev_ok}", file=sys.stderr)
                return 1
            caught_iso = False
            try:
                _ = ccxt_from_dict.setMarginMode("isolated", "BTC/USD:USD")
            except ValueError:
                caught_iso = True
            if not caught_iso:
                print("[FAIL] setMarginMode('isolated') did not raise ValueError", file=sys.stderr)
                return 1

            ccxt_from_dict.http.account = lambda account_id: {  # type: ignore[method-assign]
                "ok": True,
                "account_id": account_id,
                "free_usd_micro": 80_000_000,
                "locked_usd_micro": 20_000_000,
                "total_equity_micro": 105_000_000,
                "withdrawable_usd_micro": 75_000_000,
                "base_balances": [],
                "open_orders": [
                    {"order_id": 1, "market_id": 1, "side": "bid", "price_ticks": 4_900_000, "initial_lots": 1000, "remaining_lots": 1000, "sequence_num": 5},
                    {"order_id": 2, "market_id": 1, "side": "ask", "price_ticks": 5_100_000, "initial_lots": 1000, "remaining_lots": 1000, "sequence_num": 9},
                ],
            }
            bal_chk = ccxt_from_dict.fetchBalance()
            oo_chk = ccxt_from_dict.fetchOpenOrders("BTC/USD:USD", since=7, limit=1)
            if (
                bal_chk["equity_usd"] != 105.0
                or bal_chk["withdrawable_usd"] != 75.0
                or bal_chk["info"].get("equity_usd") != 105.0
                or bal_chk["info"].get("withdrawable_usd") != 75.0
                or len(oo_chk) != 1
                or oo_chk[0]["id"] != "2"
            ):
                print(f"[FAIL] fetchBalance info mirror or fetchOpenOrders(since, limit) failed: {bal_chk} / {oo_chk}", file=sys.stderr)
                return 1

            # 7. Verify v4.9.4 version, anonymous account_id=0 previewOrder, and empty-book fetchTicker null BBO
            if __version__ != "4.9.4":
                print(f"[FAIL] Expected __version__ == '4.9.4', got {__version__!r}", file=sys.stderr)
                return 1
            seen_anon_prev: Dict[str, Any] = {}
            def_ccxt.markets = ccxt_from_dict.markets
            def_ccxt.markets_by_symbol = ccxt_from_dict.markets_by_symbol
            def_ccxt.markets_by_id = ccxt_from_dict.markets_by_id
            def_ccxt.unified_to_native = ccxt_from_dict.unified_to_native
            def_ccxt.http.preview_order = lambda **kw: (  # type: ignore[method-assign]
                seen_anon_prev.update(kw)
                or {
                    "ok": True,
                    "would_accept": True,
                    "status": "Ok",
                    "effective_price_ticks": kw["price_ticks"],
                    "estimated_filled_lots": kw["qty_lots"],
                    "estimated_resting_lots": 0,
                    "estimated_avg_price_ticks": kw["price_ticks"],
                    "estimated_fee_micro": 0,
                    "wal_seq": 22,
                }
            )
            anon_prev = def_ccxt.previewOrder("BTC/USD:USD", "limit", "buy", "0.0100", "50000.00")
            if seen_anon_prev.get("account_id") != 0 or not anon_prev["wouldAccept"]:
                print(f"[FAIL] Anonymous account_id=0 previewOrder failed: {seen_anon_prev} / {anon_prev}", file=sys.stderr)
                return 1
            caught_neg_aid = False
            try:
                _ = def_ccxt.previewOrder("BTC/USD:USD", "limit", "buy", "0.0100", "50000.00", {"account_id": -1})
            except ValueError:
                caught_neg_aid = True
            if not caught_neg_aid:
                print("[FAIL] previewOrder(account_id=-1) did not raise ValueError", file=sys.stderr)
                return 1
            ccxt_from_dict.http.ticker = lambda market_id=0: {  # type: ignore[method-assign]
                "ok": True,
                "ticker": {
                    "market_id": 1,
                    "symbol": "BTC-USD-PERP",
                    "kind": "linear_perpetual",
                    "mark_price_ticks": 5_005_000,
                    "best_bid_ticks": 0,
                    "best_ask_ticks": 0,
                    "best_bid_lots": 0,
                    "best_ask_lots": 0,
                },
            }
            empty_tk = ccxt_from_dict.fetchTicker("BTC/USD:USD")
            if empty_tk["bid"] is not None or empty_tk["ask"] is not None or empty_tk["markPrice"] != 50050.0:
                print(f"[FAIL] Empty-book fetchTicker did not report bid=None, ask=None: {empty_tk}", file=sys.stderr)
                return 1
        finally:
            tn_http.close()
            tn_ccxt.close()
            def_ccxt.close()
    finally:
        ccxt_from_cli.close()
        ccxt_from_dict.close()
        base_cli.close()

    print("[PASS] arena_sdk.py self-test OK")
    return 0


if __name__ == "__main__":
    import argparse
    import sys

    _ap = argparse.ArgumentParser(description="Arena Exchange Official Python SDK")
    _ap.add_argument("--self-test", action="store_true", help="Run deterministic offline SDK self-test")
    _args = _ap.parse_args()
    if _args.self_test:
        raise SystemExit(_run_self_test())
    _ap.print_help()
    raise SystemExit(0)

