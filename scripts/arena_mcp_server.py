"""
Arena Exchange v4.9.5 — Zero-Dependency Model Context Protocol (MCP) JSON-RPC 2.0 Server
(`scripts/arena_mcp_server.py`)

Exposes Arena Exchange's headless HTTP REST, stateless `POST /order/preview`, 64-byte
binary TCP wire (`ArenaWire`), zero-capital flash-arbitrage & liquidation sweepers,
cryptographic ledger-tip/Merkle-escape verification, Prime sub-account/drawdown risk
guardrails, self-service testnet onboarding, and `ArenaCcxtAdapter` market-normalization
utilities over BOTH MCP `stdio` (newline-delimited JSON-RPC 2.0 + `Content-Length`
framing) and Streamable HTTP (`POST /mcp`, `GET /mcp/health`, `GET /mcp/server-card`,
`GET /.well-known/mcp/server-card.json`).
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hmac
import http.server
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
from typing import Any, BinaryIO, Dict, List, Optional, Tuple
import urllib.parse

_THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = _THIS_DIR.parent.parent if _THIS_DIR.name == "python" and _THIS_DIR.parent.name == "sdk" else _THIS_DIR.parent
for _cand_dir in (_THIS_DIR, REPO_ROOT / "sdk" / "python"):
    if (_cand_dir / "arena_sdk.py").is_file() and str(_cand_dir) not in sys.path:
        sys.path.insert(0, str(_cand_dir))

from arena_sdk import (  # noqa: E402
    ARENA_WIRE_BYTES,
    MASK64,
    MAX_WIRE_HEADER_QTY_LOTS,
    PUBLIC_TESTNET_URL,
    ArenaBinaryClient,
    ArenaCcxtAdapter,
    ArenaHttpClient,
    EthWalletSigner,
    EvmJsonRpcClient,
    OrderSide,
    StpMode,
    TimeInForce,
    WireStatusCode,
    base_to_qty_lots,
    micro_to_usd_str,
    price_ticks_to_usd_str,
    qty_lots_to_base_str,
    reconstruct_escape_merkle_proof_from_logs,
    usd_to_micro,
    usd_to_price_ticks,
    verify_escape_merkle_proof,
    verify_ledger_tip,
)

MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_MCP_PROTOCOL_VERSIONS: Tuple[str, ...] = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
SERVER_NAME = "arena-exchange-mcp"
SERVER_VERSION = "4.9.5"
MCP_SERVER_CARD_SCHEMA = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"
MCP_REGISTRY_NAME = "io.github.FeraTerra/feraterra-sdk"
MCP_WEBSITE_URL = "https://feraterra.app"
MCP_REPOSITORY_URL = "https://github.com/FeraTerra/feraterra-sdk"
MCP_REMOTE_URL = "https://mcp.feraterra.app/mcp"
DEFAULT_LOCAL_ARENA_URL = "http://127.0.0.1:8080"
PUBLIC_TESTNET_ARENA_URL = PUBLIC_TESTNET_URL
MAX_STDIO_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_HTTP_MESSAGE_BYTES = 65_536
HTTP_MAX_INFLIGHT_REQUESTS = 64
MAX_BUILDER_FEE_SHARE_BPS = 5000

PUBLIC_UNAUTH_HIDDEN_READ_TOOLS = frozenset(
    {
        "arena_get_account_portfolio",
        "arena_get_withdrawals_and_escape_proof",
    }
)

_LOCK_FREE_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "prompts/get",
    }
)

_CANCEL_TOOLS = frozenset(
    {
        "arena_cancel_orders",
        "arena_cancel_order",
        "arena_cancel_all",
    }
)

READ_ONLY_TOOLS = frozenset(
    {
        "arena_health_and_manifest",
        "arena_list_markets",
        "arena_get_orderbook",
        "arena_get_trades_and_candles",
        "arena_get_leaderboard",
        "arena_get_account_portfolio",
        "arena_verify_ledger_tip",
        "arena_get_withdrawals_and_escape_proof",
        "arena_preview_order",
    }
)

RISK_INCREASING_TOOLS = frozenset(
    {
        "arena_place_order",
        "arena_replace_two_sided_quote",
        "arena_modify_order",
        "arena_execute_atomic_basket",
        "arena_portfolio_delta_hedge",
        "arena_subscribe_express_port",
        "arena_flash_arbitrage",
        "arena_auto_liquidate",
    }
)

_SENSITIVE_FIELDS = frozenset(
    {
        "api_key",
        "api_secret",
        "wire_key_lo64",
        "wire_key_hi64",
        "wire_key_lo_hex",
        "wire_key_hi_hex",
        "wallet_privkey",
        "privkey",
        "private_key",
    }
)


_SECRET_KV_RE = re.compile(
    r'("?(?:api_key|api_secret|wallet_privkey|private_key|privkey|wire_key_lo64|wire_key_hi64|wire_key_lo_hex|wire_key_hi_hex)"?\s*[:=]\s*)'
    r'("[^"]*"|\'[^\']*\'|0x[0-9a-fA-F]+|[^\s,}\]]+)',
    re.IGNORECASE,
)


def _scrub_secrets(obj: Any, *, text_scrubber: Optional[Any] = None) -> Any:
    if isinstance(obj, dict):
        return {
            str(k): ("[REDACTED]" if str(k).lower() in _SENSITIVE_FIELDS else _scrub_secrets(v, text_scrubber=text_scrubber))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_scrub_secrets(x, text_scrubber=text_scrubber) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_scrub_secrets(x, text_scrubber=text_scrubber) for x in obj)
    if isinstance(obj, str):
        s = text_scrubber(obj) if text_scrubber is not None else obj
        return _SECRET_KV_RE.sub(r"\1[REDACTED]", s)
    return obj


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False)


def _canonical_market_kind(raw_kind: object) -> str:
    k = str(raw_kind or "").strip().lower()
    if k in ("perp", "linear_perp", "linear_perpetual"):
        return "perp"
    if k in ("formula_perp", "formula_perpetual"):
        return "formula_perp"
    return k


def _norm_eth_address(addr: str) -> str:
    s = str(addr or "").strip()
    if s.startswith(("0x", "0X")):
        s = "0x" + s[2:].lower()
    elif len(s) == 40:
        s = "0x" + s.lower()
    if len(s) != 42 or not s.startswith("0x"):
        raise ValueError(f"Invalid Ethereum address: {addr!r}")
    int(s[2:], 16)
    return s


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _strict_bool(val: Any, field_name: str) -> bool:
    if isinstance(val, bool):
        return val
    raise ValueError(
        f"Invalid boolean for {field_name}: expected JSON boolean true/false, got {type(val).__name__} ({val!r})"
    )


def _opt_strict_bool(args: Dict[str, Any], field_name: str, default: bool = False) -> bool:
    if field_name not in args or args[field_name] is None:
        return default
    return _strict_bool(args[field_name], field_name)


def _is_loopback_bind_host(host: str) -> bool:
    raw = str(host or "").strip().lower()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if raw in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


def _parse_int_csv(raw: str) -> Optional[frozenset[int]]:
    txt = str(raw or "").strip()
    if not txt:
        return None
    vals: set[int] = set()
    for part in txt.split(","):
        p = part.strip()
        if not p:
            continue
        v = int(p)
        if v <= 0:
            raise ValueError(f"Allowed account ID must be > 0, got {v}")
        vals.add(v)
    return frozenset(vals) if vals else None


def _parse_addr_csv(raw: str) -> Optional[frozenset[str]]:
    txt = str(raw or "").strip()
    if not txt:
        return None
    addrs: set[str] = set()
    for part in txt.split(","):
        p = part.strip()
        if p:
            addrs.add(_norm_eth_address(p))
    return frozenset(addrs) if addrs else None


def _read_exact_bytes(stream: BinaryIO, count: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < count:
        chunk = stream.read(count - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class McpStdioTransport:
    """Dual-framing (JSONL & Content-Length) MCP stdio frame reader/writer."""

    def __init__(self, stdin_stream: BinaryIO, stdout_stream: BinaryIO) -> None:
        self._in = stdin_stream
        self._out = stdout_stream

    def read_message(self) -> Tuple[Optional[bytes], bool]:
        while True:
            line = self._in.readline(MAX_STDIO_MESSAGE_BYTES + 1)
            if not line:
                return None, False
            if len(line) > MAX_STDIO_MESSAGE_BYTES:
                raise ValueError("MCP stdio line exceeds 4 MiB safety limit")
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith((b"{", b"[")) and b":" in stripped:
                headers: Dict[str, str] = {}
                cur_line = line
                header_lines = 0
                while True:
                    txt = cur_line.decode("ascii", errors="replace").strip()
                    if not txt:
                        break
                    header_lines += 1
                    if header_lines > 64:
                        raise ValueError("MCP stdio header block exceeds 64-line safety limit")
                    if ":" in txt:
                        k, v = txt.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                    cur_line = self._in.readline(65536)
                    if not cur_line:
                        return None, True
                cl_raw = headers.get("content-length", "")
                try:
                    length = int(cl_raw)
                except ValueError as exc:
                    raise ValueError(f"Invalid Content-Length header: {cl_raw!r}") from exc
                if length <= 0 or length > MAX_STDIO_MESSAGE_BYTES:
                    raise ValueError(f"Content-Length {length} out of bounds [1, {MAX_STDIO_MESSAGE_BYTES}]")
                body = _read_exact_bytes(self._in, length)
                if body is None:
                    raise ValueError("Unexpected EOF reading Content-Length body")
                return body, True
            return stripped, False

    def write_message(self, payload_obj: Any, use_content_length: bool) -> None:
        raw = _json_dumps(payload_obj).encode("utf-8")
        if use_content_length:
            hdr = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
            self._out.write(hdr + raw)
        else:
            self._out.write(raw + b"\n")
        self._out.flush()


_TOOL_TITLES: Dict[str, str] = {
    "arena_health_and_manifest": "Health & Protocol Manifest",
    "arena_list_markets": "List Markets",
    "arena_get_orderbook": "Get L2/L3 Orderbook",
    "arena_get_trades_and_candles": "Get Trades & OHLCV Candles",
    "arena_get_leaderboard": "Get Gladiator Leaderboard",
    "arena_get_account_portfolio": "Get Account Portfolio",
    "arena_verify_ledger_tip": "Verify Sovereign Ledger Tip",
    "arena_get_withdrawals_and_escape_proof": "Get Withdrawals & Merkle Escape Proof",
    "arena_login_wallet": "Authenticate EIP-191 Wallet",
    "arena_configure_risk_guardrails": "Configure Risk Guardrails",
    "arena_manage_prime_subaccount": "Manage Prime Sub-Account",
    "arena_bind_builder": "Bind Builder Code",
    "arena_place_order": "Place Order",
    "arena_replace_two_sided_quote": "Replace Two-Sided Quote",
    "arena_modify_order": "Modify Resting Order",
    "arena_cancel_orders": "Cancel Resting Orders",
    "arena_execute_atomic_basket": "Execute Atomic Basket",
    "arena_portfolio_delta_hedge": "Execute Portfolio Delta Hedge",
    "arena_request_withdrawal": "Request Withdrawal Voucher",
    "arena_subscribe_express_port": "Subscribe Express Port",
    "arena_preview_order": "Preview Order (Dry-Run Simulation)",
    "arena_flash_arbitrage": "Execute Zero-Capital Flash Arbitrage",
    "arena_auto_liquidate": "Sweep Auto-Liquidation Bounties",
    "arena_onboard_and_deposit": "Onboard Wallet, Claim Faucet & Deposit Margin",
}


def _build_tool_annotations(tool_name: str) -> Dict[str, Any]:
    title = _TOOL_TITLES.get(tool_name, tool_name)
    if tool_name in READ_ONLY_TOOLS:
        return {
            "title": title,
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }
    if tool_name in _CANCEL_TOOLS:
        return {
            "title": title,
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": True,
        }
    if tool_name == "arena_request_withdrawal":
        return {
            "title": title,
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        }
    return {
        "title": title,
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }


def _build_server_card() -> Dict[str, Any]:
    return {
        "$schema": MCP_SERVER_CARD_SCHEMA,
        "name": MCP_REGISTRY_NAME,
        "title": "FeraTerra / Arena Exchange Headless Trading & Risk MCP",
        "description": (
            "Zero-dependency 24-tool MCP gateway for Arena Exchange spot, perps, "
            "stateless order previews, zero-capital flash arbitrage, and L2 custody."
        ),
        "version": SERVER_VERSION,
        "websiteUrl": MCP_WEBSITE_URL,
        "repository": {
            "url": MCP_REPOSITORY_URL,
            "source": "github",
        },
        "remotes": [
            {
                "type": "streamable-http",
                "url": MCP_REMOTE_URL,
                "supportedProtocolVersions": list(SUPPORTED_MCP_PROTOCOL_VERSIONS),
            }
        ],
    }


def _tool_specs() -> List[Dict[str, Any]]:
    raw_specs: List[Dict[str, Any]] = [
        {
            "name": "arena_health_and_manifest",
            "description": (
                "Check Arena Exchange daemon liveness, double-entry conservation status, monotonic WAL sequence, "
                "insurance reserve health, and public protocol manifest via GET /health and GET /. "
                "Read-only diagnostics; use this for venue connectivity and manifest discovery, whereas "
                "arena_verify_ledger_tip cryptographically verifies the operator-signed Keccak-256 ledger commitment."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_manifest": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, also fetches GET / protocol manifest metadata (endpoints, chain ID, L2 collateral vault address) alongside GET /health.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_list_markets",
            "description": (
                "List Arena Exchange markets (Spot, LinearPerpetual, FormulaPerpetual, BoundedClaim, SpreadBook) "
                "with unified symbols, fixed-point tick/lot precision (`1 tick = $0.01`, `1 lot = 1e-4` base), "
                "mark prices, and top-of-book BBOs (`null` when resting book side is empty). "
                "Read-only market catalog; use arena_get_orderbook instead for multi-level L2/L3 depth on a single market."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "description": "Optional market category filter ('spot', 'perp', 'formula_perp', 'bounded_claim', or 'spread_book'); empty string returns all kinds.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Optional case-insensitive market symbol filter matching native (e.g. 'BTC-USD-PERP') or CCXT unified (e.g. 'BTC/USD:USD') symbols.",
                    },
                    "active_only": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, excludes halted instruments and returns only live/active tradable markets.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_get_orderbook",
            "description": (
                "Fetch a live L2/L3 resting orderbook snapshot (bids, asks, mark price, and WAL sequence) for one Arena market. "
                "Read-only; use this to inspect multi-level resting liquidity before sizing orders, whereas arena_list_markets "
                "scans top-of-book BBOs across all markets and arena_get_trades_and_candles retrieves historical executions. "
                "Provide either `symbol` or `market_id` (mutually exclusive market selectors)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD', 'BTC/USD', or 'BTC-USD-PERP'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "depth": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 20,
                        "description": "Maximum number of resting price levels to return per book side (1..200, default 20).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_get_trades_and_candles",
            "description": (
                "Fetch recent matched trade prints and OHLCV candlestick bars (`1 tick = $0.01`, `1 lot = 1e-4` base) for a single Arena market. "
                "Read-only; use this for historical price action and realized volume, whereas arena_get_orderbook inspects current "
                "resting L2/L3 bid/ask liquidity. Provide either `symbol` or `market_id` (mutually exclusive market selectors)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD' or 'BTC-USD-PERP'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "interval": {
                        "type": "string",
                        "enum": ["tick", "1s", "1m"],
                        "default": "1m",
                        "description": "OHLCV candle aggregation timeframe: 'tick' (per-match), '1s' (1-second bars), or '1m' (1-minute bars).",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 240,
                        "default": 50,
                        "description": "Maximum number of recent trades and OHLCV candles to return (1..240, default 50).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_get_leaderboard",
            "description": (
                "Fetch the public Gladiator Leaderboard ranking active accounts by total equity, net PnL, maker BBO uptime streak, "
                "notional volume, or ROI. Read-only public benchmark; use arena_get_account_portfolio instead to inspect private "
                "positions, balances, and open orders for your authenticated account."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 25,
                        "description": "Maximum number of ranked Gladiator accounts to return (1..100, default 25).",
                    },
                    "sort": {
                        "type": "string",
                        "enum": ["equity", "pnl", "streak", "volume", "roi"],
                        "default": "equity",
                        "description": "Ranking metric: 'equity' (total USD equity), 'pnl' (net PnL), 'streak' (maker BBO uptime epochs), 'volume', or 'roi'.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_get_account_portfolio",
            "description": (
                "Inspect an authenticated account's USD collateral (`1 micro = $1e-6`), Spot base holdings (`1 lot = 1e-4` base), "
                "perpetual/claim positions, Eigen-SPAN IMR/MMR, active drawdown stop, builder binding, and resting open orders. "
                "Read-only; use this for live margin, position, and open-order state, whereas arena_get_withdrawals_and_escape_proof "
                "queries withdrawal vouchers and Merkle custody proofs and arena_get_leaderboard views public account rankings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target Arena account ID (>= 1); defaults to the authenticated session account_id when omitted.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_verify_ledger_tip",
            "description": (
                "Fetch GET /ledger/tip and cryptographically verify its ARENA_LEDGER_TIP_V2_1 Keccak-256 digest and secp256k1 "
                "operator signature locally. Read-only solvency verifier; use this to verify the global WAL chain hash and state root, "
                "whereas arena_get_withdrawals_and_escape_proof verifies per-account L2 collateral vault Merkle escape proofs."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "expected_operator_address": {
                        "type": "string",
                        "description": "Optional 0x-prefixed 20-byte Ethereum operator address to pin against the recovered secp256k1 signer (overrides --expected-operator-address).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_get_withdrawals_and_escape_proof",
            "description": (
                "Fetch an account's off-chain withdrawal vouchers and optionally verify an L2 collateral vault Merkle emergency escape proof "
                "(off-chain or reconstructed from L1/L2 EVM logs). Read-only custody audit tool; use arena_request_withdrawal to "
                "initiate a new withdrawal debit, or arena_get_account_portfolio to inspect live trading balances and open orders."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target Arena account ID (>= 1); defaults to the authenticated session account_id when omitted.",
                    },
                    "asset_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Collateral asset ID for Merkle escape proof lookup (0 = USD settlement collateral, >= 1 = Spot base asset ID).",
                    },
                    "include_escape_proof": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, fetches GET /settlement/escape_proof and cryptographically verifies leaf inclusion against the Merkle root.",
                    },
                    "pending": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true with include_escape_proof, inspects the pending settlement batch tree instead of the last finalized L2 root.",
                    },
                    "expected_escape_merkle_root": {
                        "type": "string",
                        "description": "Optional 0x-prefixed 32-byte Merkle root hash to pin verification against instead of the server-reported root.",
                    },
                    "verify_from_onchain_logs": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, reconstructs the account Merkle proof directly from L2 collateral vault EVM logs (requires --rpc-url and --clearinghouse).",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 2000,
                        "default": 50,
                        "description": "Maximum number of withdrawal voucher records to return (1..2000, default 50).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_login_wallet",
            "description": (
                "Authenticate an Ethereum wallet into this MCP session via EIP-191 challenge-response signing (API/wire session "
                "secrets stay bound in-memory and are never echoed). Mutates local session credentials only; use this when your "
                "wallet is already funded or for $0-pre-margin flash arbitrage, whereas arena_onboard_and_deposit also claims "
                "testnet faucet collateral and deposits margin on-chain."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "generate_ephemeral": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, generates a fresh CSPRNG secp256k1 wallet in-memory for this session instead of using --wallet-privkey.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_configure_risk_guardrails",
            "description": (
                "Configure server-enforced account risk guardrails: portfolio equity drawdown kill-switch, per-position Knock-Out "
                "price barrier, Rolling Market-Maker Protection (MMP), and TCP Cancel-on-Disconnect. Mutates account risk settings "
                "(required before risk-increasing tools when --require-drawdown-stop is active); use arena_get_account_portfolio "
                "to read current guardrail values. Provide mutually exclusive decimal vs integer fields (`drawdown_stop_usd` vs "
                "`drawdown_stop_usd_micro`, `knockout_symbol` vs `knockout_market_id`, `knockout_price_usd` vs `knockout_price_ticks`)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target Arena account ID (>= 1); defaults to the authenticated session account_id when omitted.",
                    },
                    "drawdown_stop_usd": {
                        "type": ["string", "number"],
                        "description": "Exact USD equity kill-switch floor as decimal string or number (e.g. '9500.00'; '0' disables when permitted); mutually exclusive with drawdown_stop_usd_micro.",
                    },
                    "drawdown_stop_usd_micro": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Portfolio equity kill-switch floor in integer micro-USD (1 micro = $1e-6, 0 = disable when permitted); mutually exclusive with drawdown_stop_usd.",
                    },
                    "knockout_symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD') for per-position Knock-Out barrier; mutually exclusive with knockout_market_id.",
                    },
                    "knockout_market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market ID (>= 1) for per-position Knock-Out barrier; mutually exclusive with knockout_symbol.",
                    },
                    "knockout_price_usd": {
                        "type": ["string", "number"],
                        "description": "Per-position Knock-Out trigger price in exact USD (e.g. '48500.00', multiple of $0.01; '0' clears barrier); mutually exclusive with knockout_price_ticks.",
                    },
                    "knockout_price_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Per-position Knock-Out trigger price in integer ticks (1 tick = $0.01, 0 = clear barrier); mutually exclusive with knockout_price_usd.",
                    },
                    "mmp_window_wal_seqs": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "description": "Rolling Market-Maker Protection lookback window in WAL sequence increments (0..65535, 0 = disable MMP).",
                    },
                    "mmp_max_fill_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Maximum cumulative maker fill size in integer lots (1 lot = 1e-4 base, 0 = uncapped) within mmp_window_wal_seqs before MMP triggers.",
                    },
                    "mmp_max_delta_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Maximum net signed maker delta in integer lots (1 lot = 1e-4 base, 0 = uncapped) within mmp_window_wal_seqs before MMP triggers.",
                    },
                    "mmp_cooldown_wal_seqs": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "description": "Cooldown duration in WAL sequence increments (0..65535) blocking new maker quotes after an MMP breach.",
                    },
                    "cancel_on_disconnect": {
                        "type": "boolean",
                        "description": "Enable (true) or disable (false) automatic resting order cancellation on TCP binary wire disconnect (requires --tcp-port > 0).",
                    },
                    "cod_market_id": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "default": 0,
                        "description": "Market ID scope for Cancel-on-Disconnect (0 = all markets across session, 1..65535 = single market).",
                    },
                    "cod_timeout_ms": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 86400000,
                        "default": 0,
                        "description": "Grace timeout in milliseconds (0..86400000, 0 = cancel immediately upon socket disconnect) before sweeping orders.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_manage_prime_subaccount",
            "description": (
                "Link or unlink (`max_guaranty_usd_micro=-2`) a Prime sub-account cross-margin guaranty, or execute 0-bps internal "
                "USD/Spot transfers between linked accounts. Mutates Prime account links or internal balances; use "
                "arena_request_withdrawal instead for external L2 Ethereum withdrawals. Provide mutually exclusive decimal "
                "(`max_guaranty_usd`, `amount_usd`, `amount_base`) vs fixed-point integer (`max_guaranty_usd_micro`, `amount`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["link", "unlink", "transfer"],
                        "description": "Prime operation: 'link' (set sub-account guaranty cap), 'unlink' (remove link via sentinel -2), or 'transfer' (0-bps internal transfer).",
                    },
                    "master_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Prime master account ID (>= 1) for 'link' or 'unlink'; defaults to session account_id when omitted.",
                    },
                    "sub_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target Prime sub-account ID (>= 1) to link to or unlink from master_account_id.",
                    },
                    "max_guaranty_usd": {
                        "type": ["string", "number"],
                        "description": "Maximum master cross-margin guaranty cap in exact USD (e.g. '5000.00'; '0' = unlimited when notional cap is off); mutually exclusive with max_guaranty_usd_micro.",
                    },
                    "max_guaranty_usd_micro": {
                        "type": "integer",
                        "minimum": -2,
                        "description": "Master guaranty cap in integer micro-USD (1 micro = $1e-6, 0 = unlimited when permitted, -2 = unlink sentinel); mutually exclusive with max_guaranty_usd.",
                    },
                    "from_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Source account ID (>= 1) debited during action='transfer'; defaults to session account_id when omitted.",
                    },
                    "to_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Destination linked account ID (>= 1) credited during action='transfer'.",
                    },
                    "asset_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Collateral asset ID for action='transfer' (0 = USD collateral, >= 1 = Spot base asset ID).",
                    },
                    "amount_usd": {
                        "type": ["string", "number"],
                        "description": "Exact USD transfer amount as decimal string or number (e.g. '250.00', requires asset_id=0); mutually exclusive with amount and amount_base.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "Exact Spot base-asset transfer quantity (e.g. '0.2500', multiple of 1e-4, requires asset_id > 0); mutually exclusive with amount and amount_usd.",
                    },
                    "amount": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Raw fixed-point transfer quantity: micro-USD (1 micro = $1e-6) when asset_id=0, or lots (1 lot = 1e-4 base) when asset_id > 0; mutually exclusive with amount_usd/amount_base.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_bind_builder",
            "description": (
                "Bind a trader account to a Builder / Order-Flow Router account and configure its protocol taker-fee share "
                "(0..5000 bps) via POST /account/builder. Mutates fee-routing metadata (locked when operator "
                "--default-builder-account policy is set); use arena_manage_prime_subaccount instead for Prime margin linking."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["builder_account_id", "builder_fee_share_bps"],
                "properties": {
                    "trader_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Trader account ID (>= 1) binding the builder code; defaults to session account_id when omitted.",
                    },
                    "builder_account_id": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Builder / router recipient account ID (0 = unbind builder code, >= 1 = active builder account).",
                    },
                    "builder_fee_share_bps": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 5000,
                        "description": "Builder share of protocol taker fees in basis points (0..5000 bps, where 100 bps = 1.00% and 0 clears fee share).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_place_order",
            "description": (
                "Submit a live single-leg limit, market, pegged, iceberg, dark-midpoint, or reduce-only order over HTTP POST /order "
                "or 64-byte TCP wire. Mutates L3 book, margin locks, and WAL state; call arena_preview_order first for a "
                "zero-mutation dry run, arena_replace_two_sided_quote for atomic bid+ask market-making, or "
                "arena_execute_atomic_basket for multi-leg spreads. Provide mutually exclusive market (`symbol` vs `market_id`), "
                "price (`price_usd` vs `price_ticks`), and size (`amount_base` vs `qty_lots`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["side"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Trading account ID (>= 1); defaults to the authenticated session account_id when omitted.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD', 'BTC/USD', or 'BTC-USD-PERP'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "side": {
                        "type": "string",
                        "enum": ["buy", "sell", "bid", "ask"],
                        "description": "Order side: 'buy'/'bid' (long/buy) or 'sell'/'ask' (short/sell).",
                    },
                    "price_usd": {
                        "type": ["string", "number"],
                        "description": "Exact limit price in USD decimal string or number (e.g. '50000.00', exact multiple of $0.01); mutually exclusive with price_ticks (optional when is_market=true or pegged).",
                    },
                    "price_ticks": {
                        "type": "integer",
                        "description": "Limit price in fixed-point integer ticks (1 tick = $0.01; 0 allowed for market/pegged orders; SpreadBook par = 1000000); mutually exclusive with price_usd.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "Order size in exact base-asset decimal string or number (e.g. '0.1000', exact multiple of 0.0001); mutually exclusive with qty_lots.",
                    },
                    "qty_lots": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Order size in fixed-point integer lots (1 lot = 1e-4 base unit, minimum 1); mutually exclusive with amount_base.",
                    },
                    "tif": {
                        "type": "string",
                        "enum": ["gtc", "ioc", "fok", "post_only"],
                        "default": "gtc",
                        "description": "Time-in-force: 'gtc' (Good-Til-Cancelled), 'ioc' (Immediate-Or-Cancel), 'fok' (Fill-Or-Kill), or 'post_only' (maker-only).",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_both", "decrement_and_cancel", "none"],
                        "default": "cancel_resting",
                        "description": "Self-Trade Prevention mode applied if this order crosses resting orders from the same account.",
                    },
                    "is_market": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, submits an immediate market sweep order (defaults tif to 'ioc' and allows 0 limit price).",
                    },
                    "reduce_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, strictly reduces an existing open position and never increases directional exposure.",
                    },
                    "margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true on a Spot market, enables cross-margined Spot borrowing/collateralization under Eigen-SPAN.",
                    },
                    "post_only_slide": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, slides a crossing maker order 1 tick passive of the opposing BBO instead of rejecting.",
                    },
                    "primary_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, dynamically pegs resting order price to the same-side BBO plus peg_offset_ticks.",
                    },
                    "midpoint_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, dynamically pegs resting order price to the BBO midpoint plus peg_offset_ticks.",
                    },
                    "mark_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, dynamically pegs resting order price to the oracle/index mark price plus peg_offset_ticks.",
                    },
                    "trailing_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, ratchets the pegged order one-way as market price moves favorably by peg_offset_ticks.",
                    },
                    "dark_midpoint": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, rests non-displayed at the BBO midpoint for zero pre-trade market impact.",
                    },
                    "oco_linked": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, links this order in a One-Cancels-the-Other bracket with orders sharing client_tag.",
                    },
                    "stp_decrement_and_cancel": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, decrements the larger self-crossing order by the smaller quantity and cancels the smaller order.",
                    },
                    "client_tag": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional unsigned strategy/group tag (0 = untagged) used for OCO linking and tag-filtered batch cancels.",
                    },
                    "min_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Minimum acceptable immediate fill quantity in integer lots (1 lot = 1e-4 base, 0 = no minimum).",
                    },
                    "display_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Visible iceberg clip size in integer lots (1 lot = 1e-4 base, 0 = display full order size unless dark_midpoint=true).",
                    },
                    "auto_skew_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Automatic inventory-skew price adjustment in integer ticks (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "auto_flip_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Automatic passive counter-order flip distance in integer ticks after fill (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "peg_offset_ticks": {
                        "type": "integer",
                        "minimum": -500,
                        "maximum": 500,
                        "default": 0,
                        "description": "Signed tick offset (-500..500, 1 tick = $0.01) added to the reference price when a peg flag is enabled.",
                    },
                    "max_lifetime_wal_seqs": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "default": 0,
                        "description": "Good-Til-Sequence auto-expiry lifetime in WAL sequence increments (0..65535, 0 = no sequence expiry).",
                    },
                    "jit_elastic_mult": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 50,
                        "default": 0,
                        "description": "Elastic liquidity / dynamic iceberg reload multiplier (0..50; >= 2 activates elastic depth/reload, 0 or 1 = standard).",
                    },
                    "priority_fee_ppm": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 50000,
                        "default": 0,
                        "description": "Optional priority fee bid in parts-per-million of notional (0..50000 ppm, where 100 ppm = 1 bps; 0 = none).",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, dispatches via 64-byte TCP ArenaWire with automatic HTTP REST fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_replace_two_sided_quote",
            "description": (
                "Atomically cancel and replace both resting Bid and Ask maker quotes on a single market in 1 engine step via "
                "POST /quote or 64-byte TCP TwoSidedQuoteReplace (`0xC`). Mutates resting maker quotes; prefer this over two "
                "separate arena_place_order calls when market-making, or use arena_modify_order to amend a single order_id. "
                "Provide mutually exclusive market (`symbol` vs `market_id`), bid/ask price (`*_price_usd` vs `*_price_ticks`), "
                "and bid/ask size (`*_amount_base` vs `*_qty_lots`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Market-maker account ID (>= 1); defaults to the authenticated session account_id when omitted.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD' or 'BTC-USD-PERP'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "bid_price_usd": {
                        "type": ["string", "number"],
                        "description": "Exact Bid quote price in USD decimal string or number (e.g. '49995.00', multiple of $0.01); mutually exclusive with bid_price_ticks.",
                    },
                    "bid_price_ticks": {
                        "type": "integer",
                        "description": "Bid quote price in integer ticks (1 tick = $0.01; 0 allowed when quote_peg_mode > 0 or canceling bid side); mutually exclusive with bid_price_usd.",
                    },
                    "bid_amount_base": {
                        "type": ["string", "number"],
                        "description": "Bid quote size in exact base units (e.g. '0.1000', multiple of 1e-4; '0' cancels resting bid only); mutually exclusive with bid_qty_lots.",
                    },
                    "bid_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Bid quote size in integer lots (1 lot = 1e-4 base, 0 = cancel resting bid side without posting a new bid); mutually exclusive with bid_amount_base.",
                    },
                    "ask_price_usd": {
                        "type": ["string", "number"],
                        "description": "Exact Ask quote price in USD decimal string or number (e.g. '50005.00', multiple of $0.01); mutually exclusive with ask_price_ticks.",
                    },
                    "ask_price_ticks": {
                        "type": "integer",
                        "description": "Ask quote price in integer ticks (1 tick = $0.01; 0 allowed when quote_peg_mode > 0 or canceling ask side); mutually exclusive with ask_price_usd.",
                    },
                    "ask_amount_base": {
                        "type": ["string", "number"],
                        "description": "Ask quote size in exact base units (e.g. '0.1000', multiple of 1e-4; '0' cancels resting ask only); mutually exclusive with ask_qty_lots.",
                    },
                    "ask_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Ask quote size in integer lots (1 lot = 1e-4 base, 0 = cancel resting ask side without posting a new ask); mutually exclusive with ask_amount_base.",
                    },
                    "tif": {
                        "type": "string",
                        "enum": ["gtc", "post_only", "postonly", "ioc", "fok"],
                        "default": "gtc",
                        "description": "Time-in-force applied to both Bid and Ask legs (use 'post_only' for strict maker-only quoting).",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_aggressor", "cancel_both", "none"],
                        "default": "cancel_resting",
                        "description": "Self-Trade Prevention policy applied to both Bid and Ask quote legs.",
                    },
                    "post_only_slide": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, slides any crossing quote leg 1 tick passive of the opposing BBO instead of rejecting.",
                    },
                    "margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true on a Spot market, enables cross-margined Spot quoting under Eigen-SPAN.",
                    },
                    "client_tag": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Unsigned quote-slot tag (0 = default market quote slot; combine with ladder_by_tag=true for multi-rung quote ladders).",
                    },
                    "auto_skew_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Inventory-driven price skew step in integer ticks (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "auto_flip_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Automatic counter-side re-quote flip distance in ticks upon fill (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "quote_peg_mode": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 4,
                        "default": 0,
                        "description": "Native quote pegging mode: 0 = fixed limit prices, 1 = primary BBO peg, 2 = midpoint peg, 3 = mark-price peg, 4 = trailing peg.",
                    },
                    "peg_offset_ticks": {
                        "type": "integer",
                        "minimum": -500,
                        "maximum": 500,
                        "default": 0,
                        "description": "Signed half-spread or reference offset in integer ticks (-500..500, 1 tick = $0.01) when quote_peg_mode > 0.",
                    },
                    "oco_linked": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, links Bid and Ask legs as One-Cancels-the-Other so filling one cancels the opposite leg.",
                    },
                    "max_lifetime_wal_seqs": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "default": 0,
                        "description": "Good-Til-Sequence auto-expiry lifetime in WAL sequence increments (0..65535, 0 = no sequence expiry).",
                    },
                    "jit_elastic_mult": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 50,
                        "default": 0,
                        "description": "Elastic maker liquidity multiplier (0..50; >= 2 enables elastic depth scaling, 0 or 1 = standard).",
                    },
                    "ladder_by_tag": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, replaces only resting quotes matching client_tag so multiple tagged quote rungs coexist.",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, dispatches via 64-byte TCP TwoSidedQuoteReplace with HTTP fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_modify_order",
            "description": (
                "Modify an existing resting order's limit price and/or quantity in-place by order_id with optional FIFO queue "
                "priority preservation. Mutates a single open order; use arena_replace_two_sided_quote for paired bid+ask updates "
                "or arena_cancel_orders to cancel. Provide mutually exclusive market (`symbol` vs `market_id`), price (`price_usd` "
                "vs `price_ticks`), and size (`amount_base` vs `qty_lots`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["order_id"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Account ID (>= 1) owning the open order; defaults to the authenticated session account_id when omitted.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "order_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Unique positive integer order_id of the currently resting open order to modify.",
                    },
                    "price_usd": {
                        "type": ["string", "number"],
                        "description": "New exact limit price in USD decimal string or number (e.g. '50100.00', multiple of $0.01); mutually exclusive with price_ticks.",
                    },
                    "price_ticks": {
                        "type": "integer",
                        "description": "New limit price in fixed-point integer ticks (1 tick = $0.01); mutually exclusive with price_usd.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "New total order quantity in exact base units (e.g. '0.2000', multiple of 1e-4); mutually exclusive with qty_lots.",
                    },
                    "qty_lots": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "New total order quantity in fixed-point integer lots (1 lot = 1e-4 base, minimum 1); mutually exclusive with amount_base.",
                    },
                    "keep_priority": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, retains existing L3 FIFO queue priority when downsizing quantity at an unchanged price.",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, sends a 64-byte TCP ModifyOrder frame with HTTP fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_cancel_orders",
            "description": (
                "Cancel one specific resting order by order_id or batch-cancel resting orders across all or selected markets "
                "filtered by side, client_tag_filter, or market_bitmask. Idempotently removes open orders without closing filled "
                "positions; use arena_portfolio_delta_hedge or a reduce_only arena_place_order to close open positions. "
                "Provide either `symbol` or `market_id` when scoping to a single market."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Account ID (>= 1) whose resting orders will be cancelled; defaults to session account_id when omitted.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Optional market symbol scope (required when cancelling a single order_id without market_id); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Market ID scope (0 = all markets during batch cancel_all; >= 1 = specific market); mutually exclusive with symbol.",
                    },
                    "order_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Specific resting order ID to cancel (> 0 cancels single order; 0 triggers filtered batch cancel_all).",
                    },
                    "cancel_all": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true (or when order_id == 0), executes batch cancel_all across matching market/side/tag filters.",
                    },
                    "side": {
                        "type": "string",
                        "enum": ["", "bid", "ask", "buy", "sell"],
                        "default": "",
                        "description": "Optional side filter for batch cancel_all: '' (both sides), 'buy'/'bid' (bids only), or 'sell'/'ask' (asks only).",
                    },
                    "client_tag_filter": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional strategy client_tag filter for batch cancel_all (0 = all tags, > 0 = cancel only matching client_tag).",
                    },
                    "market_bitmask": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional 64-bit bitmask of market IDs for multi-market batch cancel_all (0 = no bitmask filter).",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, dispatches CancelOrder/CancelAll over 64-byte TCP wire with HTTP fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_execute_atomic_basket",
            "description": (
                "Execute an all-or-nothing 2..4-leg cross-market basket, basis, or butterfly spread trade in a single atomic "
                "commit via POST /basket (reverts all legs if any leg fails price, liquidity, or Eigen-SPAN margin checks). "
                "Use this for multi-leg relative-value execution, whereas arena_place_order places a single-leg order and "
                "arena_portfolio_delta_hedge auto-computes residual portfolio delta hedges. Within each leg, provide mutually "
                "exclusive market (`symbol` vs `market_id`), price (`price_usd` vs `price_ticks`), and size (`amount_base` vs `qty_lots`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["legs"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Trading account ID (>= 1) executing the atomic basket; defaults to session account_id when omitted.",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_both", "none"],
                        "default": "cancel_resting",
                        "description": "Self-Trade Prevention policy applied across all basket legs.",
                    },
                    "margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "Default cross-margined Spot flag applied to Spot legs unless overridden per leg.",
                    },
                    "client_tag": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional unsigned strategy/correlation tag (0 = untagged) recorded on basket fills.",
                    },
                    "express_surplus_bid_bps": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 5000,
                        "default": 0,
                        "description": "Optional priority auction share of positive basket surplus bid to protocol in basis points (0..5000 bps, 0 = none).",
                    },
                    "legs": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 4,
                        "description": "Ordered array of 2 to 4 individual market legs executed atomically (all legs fill within limits or none execute).",
                        "items": {
                            "type": "object",
                            "required": ["side"],
                            "properties": {
                                "symbol": {
                                    "type": "string",
                                    "description": "Leg unified or native market symbol (e.g. 'BTC/USD:USD' or 'BTC/USD'); mutually exclusive with leg market_id.",
                                },
                                "market_id": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "Leg numeric Arena market identifier (>= 1); mutually exclusive with leg symbol.",
                                },
                                "side": {
                                    "type": "string",
                                    "enum": ["buy", "sell", "bid", "ask"],
                                    "description": "Leg execution side: 'buy'/'bid' or 'sell'/'ask'.",
                                },
                                "price_usd": {
                                    "type": ["string", "number"],
                                    "description": "Leg worst-case limit price in exact USD (e.g. '50000.00', multiple of $0.01); mutually exclusive with leg price_ticks.",
                                },
                                "price_ticks": {
                                    "type": "integer",
                                    "description": "Leg worst-case limit price in integer ticks (1 tick = $0.01; 0 allowed when is_market=true); mutually exclusive with leg price_usd.",
                                },
                                "amount_base": {
                                    "type": ["string", "number"],
                                    "description": "Leg quantity in exact base units (e.g. '0.0500', multiple of 1e-4); mutually exclusive with leg qty_lots.",
                                },
                                "qty_lots": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "Leg quantity in fixed-point integer lots (1 lot = 1e-4 base, minimum 1); mutually exclusive with leg amount_base.",
                                },
                                "is_market": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "When true, sweeps resting book liquidity on this leg without a strict limit price.",
                                },
                                "reduce_only": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "When true, constrains this leg to strictly reduce an existing open position.",
                                },
                                "margin_spot": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "When true on a Spot leg, enables cross-margined Spot execution under Eigen-SPAN.",
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_portfolio_delta_hedge",
            "description": (
                "Compute the account's analytic Jacobian net asset delta across Spot, LinearPerpetual, and FormulaPerpetual "
                "positions and execute a 1-frame delta-neutralizing IOC hedge via POST /auto_delta_hedge. Mutates positions "
                "to flatten residual directional delta; use this for automated portfolio hedging, whereas "
                "arena_execute_atomic_basket executes explicit caller-specified multi-leg trade quantities."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Account ID (>= 1) whose residual portfolio delta will be hedged; defaults to session account_id when omitted.",
                    },
                    "base_asset_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Target underlying base asset ID to hedge (0 = hedge all base assets with non-zero net delta, >= 1 = single asset).",
                    },
                    "preferred_market_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional preferred Arena market ID for routing the hedge (0 = engine auto-selects deepest liquid Spot/Perp venue).",
                    },
                    "max_slippage_bps": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                        "default": 200,
                        "description": "Maximum acceptable execution slippage from reference mark/BBO in basis points (1..5000 bps, default 200 = 2.00%).",
                    },
                    "max_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Maximum hedge size cap per base asset in integer lots (1 lot = 1e-4 base, 0 = hedge full residual delta).",
                    },
                    "margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, permits cross-margined Spot borrowing/collateralization if the hedge routes through a Spot market.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_request_withdrawal",
            "description": (
                "Debit free off-chain collateral and issue an operator-signed ARENA_WITHDRAW_V1_4 voucher for L2 collateral vault "
                "claim via POST /withdraw (blocked unless --allow-withdrawals is explicitly enabled). Destructively debits "
                "off-chain balance into an on-chain claimable voucher; use arena_manage_prime_subaccount (`action='transfer'`) "
                "for 0-bps internal transfers, or arena_get_withdrawals_and_escape_proof to inspect existing vouchers. "
                "Provide mutually exclusive amount fields (`amount_usd`, `amount_base`, or raw `amount`)."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["recipient_eth_address"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Source Arena account ID (>= 1) to debit; defaults to session account_id when omitted.",
                    },
                    "asset_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Collateral asset ID to withdraw (0 = USD settlement collateral, >= 1 = Spot base asset ID).",
                    },
                    "amount_usd": {
                        "type": ["string", "number"],
                        "description": "Exact USD withdrawal amount as decimal string or number (e.g. '100.00', requires asset_id=0); mutually exclusive with amount and amount_base.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "Exact Spot base-asset withdrawal quantity (e.g. '0.5000', multiple of 1e-4, requires asset_id > 0); mutually exclusive with amount and amount_usd.",
                    },
                    "amount": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Raw fixed-point withdrawal quantity: micro-USD (1 micro = $1e-6) when asset_id=0, or lots (1 lot = 1e-4 base) when asset_id > 0; mutually exclusive with amount_usd/amount_base.",
                    },
                    "recipient_eth_address": {
                        "type": "string",
                        "description": "Destination 0x-prefixed 20-byte Ethereum wallet address authorized to claim the voucher on the L2 collateral vault.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_subscribe_express_port",
            "description": (
                "Purchase or extend a Native Colocation Express Port lease (in epochs) for priority wire tie-breaking and "
                "maximum Core 1 ingress batching via POST /account/express_port or 64-byte TCP wire. Debits free USD collateral "
                "for the standing epoch lease; pass `priority_fee_ppm` on arena_place_order instead when bidding priority on a "
                "single order without a standing lease."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Account ID (>= 1) purchasing or extending the Express Port lease; defaults to session account_id when omitted.",
                    },
                    "duration_epochs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1051200,
                        "default": 1,
                        "description": "Number of Express Port epochs to purchase or append to the active lease (1..1051200, default 1).",
                    },
                    "max_fee_usd_micro": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Maximum acceptable total lease fee in integer micro-USD (1 micro = $1e-6, 0 = accept protocol epoch rate up to notional cap).",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, submits the Express Port subscription over 64-byte TCP wire with HTTP fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_preview_order",
            "description": (
                "Run a stateless, zero-mutation order simulation via POST /order/preview (never mutates WAL, L3 book, or balances; "
                "supports `account_id=0` anonymous zero-key preview as well as authenticated Eigen-SPAN IMR/MMR/free-margin checks). "
                "Always call this to verify fill price, net fee/rebate, and margin impact before calling arena_place_order to execute live. "
                "Provide mutually exclusive market (`symbol` vs `market_id`), price (`price_usd`, `price_ticks`, or SpreadBook "
                "`differential_usd`), and size (`amount_base` vs `qty_lots`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["side"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Account ID for simulation (0 = anonymous zero-key preview without credentials; >= 1 = simulate against account's live Eigen-SPAN portfolio; defaults to session account or 0 when unauthenticated).",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Unified or native market symbol (e.g. 'BTC/USD:USD', 'BTC/USD', or 'BTC-USD-PERP'); mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "side": {
                        "type": "string",
                        "enum": ["buy", "sell", "bid", "ask"],
                        "description": "Simulated order direction: 'buy'/'bid' or 'sell'/'ask'.",
                    },
                    "price_usd": {
                        "type": ["string", "number"],
                        "description": "Simulated limit price in exact USD decimal string or number (e.g. '50000.00', multiple of $0.01); mutually exclusive with price_ticks and differential_usd.",
                    },
                    "price_ticks": {
                        "type": "integer",
                        "description": "Simulated limit price in fixed-point integer ticks (1 tick = $0.01; 0 allowed for market/pegged orders); mutually exclusive with price_usd and differential_usd.",
                    },
                    "differential_usd": {
                        "type": ["string", "number"],
                        "description": "Signed USD spread differential relative to $10,000.00 par (e.g. '-5.25') for SpreadBook markets only; mutually exclusive with price_usd and price_ticks.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "Simulated order size in exact base units (e.g. '0.1000', multiple of 1e-4); mutually exclusive with qty_lots.",
                    },
                    "qty_lots": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Simulated order size in fixed-point integer lots (1 lot = 1e-4 base, minimum 1); mutually exclusive with amount_base.",
                    },
                    "tif": {
                        "type": "string",
                        "enum": ["gtc", "ioc", "fok", "post_only"],
                        "default": "gtc",
                        "description": "Simulated time-in-force policy: 'gtc', 'ioc', 'fok', or 'post_only'.",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_both", "decrement_and_cancel", "none"],
                        "default": "cancel_resting",
                        "description": "Simulated Self-Trade Prevention mode against same-account resting orders.",
                    },
                    "is_market": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates an immediate market order sweep (defaults tif to 'ioc').",
                    },
                    "reduce_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates a strict position-reducing order.",
                    },
                    "margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true on a Spot market, simulates cross-margined Spot execution under Eigen-SPAN.",
                    },
                    "post_only_slide": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates passive 1-tick BBO sliding if the order would cross resting liquidity.",
                    },
                    "primary_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates a primary same-side BBO pegged order plus peg_offset_ticks.",
                    },
                    "midpoint_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates a BBO midpoint pegged order plus peg_offset_ticks.",
                    },
                    "mark_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates an oracle/index mark-price pegged order plus peg_offset_ticks.",
                    },
                    "trailing_peg": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates a one-way ratcheting trailing pegged order.",
                    },
                    "dark_midpoint": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates a non-displayed dark-midpoint order.",
                    },
                    "oco_linked": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates OCO bracket validation alongside client_tag.",
                    },
                    "stp_decrement_and_cancel": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, simulates decrement-and-cancel self-trade prevention.",
                    },
                    "client_tag": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Optional unsigned strategy/OCO client tag (0 = untagged).",
                    },
                    "min_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Minimum immediate fill quantity in integer lots (1 lot = 1e-4 base, 0 = no minimum).",
                    },
                    "display_qty_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Simulated visible iceberg clip size in integer lots (1 lot = 1e-4 base, 0 = full size displayed).",
                    },
                    "auto_skew_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Simulated inventory-skew step in integer ticks (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "auto_flip_ticks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 500,
                        "default": 0,
                        "description": "Simulated passive counter-order flip distance in ticks (0..500, 1 tick = $0.01, 0 = disabled).",
                    },
                    "peg_offset_ticks": {
                        "type": "integer",
                        "minimum": -500,
                        "maximum": 500,
                        "default": 0,
                        "description": "Signed tick offset (-500..500, 1 tick = $0.01) applied to pegged reference price.",
                    },
                    "max_lifetime_wal_seqs": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 65535,
                        "default": 0,
                        "description": "Simulated Good-Til-Sequence auto-expiry lifetime in WAL sequences (0..65535, 0 = none).",
                    },
                    "jit_elastic_mult": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 50,
                        "default": 0,
                        "description": "Simulated elastic liquidity / dynamic iceberg reload multiplier (0..50, 0 or 1 = standard).",
                    },
                    "priority_fee_ppm": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 50000,
                        "default": 0,
                        "description": "Simulated priority fee bid in parts-per-million of notional (0..50000 ppm, 0 = none).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_flash_arbitrage",
            "description": (
                "Execute an atomic, zero-pre-margin intra-tick Flash Arbitrage (mint+sell or buy+redeem) between an intrinsic "
                "Bonding-Curve Spot / BoundedClaim payoff and the L3 orderbook via POST /flash_arb or 64-byte TCP wire (reverts "
                "if net profit < min_profit). Use this for $0-collateral curve/claim dislocations, whereas "
                "arena_execute_atomic_basket trades margined cross-market spreads and arena_auto_liquidate sweeps underwater "
                "accounts. Provide mutually exclusive market (`symbol` vs `market_id`), size (`amount_base` vs `qty_lots`), "
                "limit (`limit_price_usd` vs `limit_price_ticks`), and profit (`min_profit_usd` vs `min_profit_micro`) fields."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["side"],
                "properties": {
                    "account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Arbitrageur account ID (>= 1) credited with realized net USD profit; defaults to session account_id when omitted.",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Target Bonding-Curve Spot or BoundedClaim market symbol; mutually exclusive with market_id.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Target numeric Arena market identifier (>= 1); mutually exclusive with symbol.",
                    },
                    "side": {
                        "type": "string",
                        "enum": ["buy", "sell", "bid", "ask", "mint", "redeem", "mint_and_sell", "buy_and_redeem"],
                        "description": "Flash arbitrage direction: 'buy'/'bid'/'mint'/'mint_and_sell' or 'sell'/'ask'/'redeem'/'buy_and_redeem'.",
                    },
                    "amount_base": {
                        "type": ["string", "number"],
                        "description": "Flash-arbitrage sweep quantity in exact base units (e.g. '1.0000', multiple of 1e-4); mutually exclusive with qty_lots.",
                    },
                    "qty_lots": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Flash-arbitrage sweep quantity in fixed-point integer lots (1 lot = 1e-4 base, minimum 1); mutually exclusive with amount_base.",
                    },
                    "limit_price_usd": {
                        "type": ["string", "number"],
                        "description": "Optional worst-case book execution limit price in exact USD (e.g. '0.95', multiple of $0.01); mutually exclusive with limit_price_ticks.",
                    },
                    "limit_price_ticks": {
                        "type": "integer",
                        "default": 0,
                        "description": "Worst-case book limit price in integer ticks (1 tick = $0.01, 0 = unconstrained when is_market=true); mutually exclusive with limit_price_usd.",
                    },
                    "min_profit_usd": {
                        "type": ["string", "number"],
                        "description": "Minimum required net realized profit in exact USD (e.g. '0.05'; atomic revert if unmet); mutually exclusive with min_profit_micro.",
                    },
                    "min_profit_micro": {
                        "type": "integer",
                        "default": 0,
                        "description": "Minimum required net realized profit in integer micro-USD (1 micro = $1e-6, 0 = break-even floor); mutually exclusive with min_profit_usd.",
                    },
                    "is_market": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, sweeps available book depth up to qty_lots subject to the atomic min_profit floor.",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_both", "none"],
                        "default": "cancel_resting",
                        "description": "Self-Trade Prevention policy when encountering the arbitrageur's own resting orders.",
                    },
                    "express_surplus_bid_bps": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 5000,
                        "default": 0,
                        "description": "Optional auction bid sharing positive arbitrage surplus with the protocol in basis points (0..5000 bps, 0 = none).",
                    },
                    "use_binary_wire": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true and --tcp-port > 0 is configured, dispatches over 64-byte TCP FlashArbitrage wire frame with HTTP fallback.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_auto_liquidate",
            "description": (
                "Execute an autonomous zero-capital liquidation and backstop bounty sweep across underwater accounts (MMR breach) "
                "via POST /auto_liquidate, optionally offloading seized contracts immediately onto the L3 book. Mutates underwater "
                "positions and credits liquidator bounty when net bounty >= min_bounty; use arena_flash_arbitrage instead for "
                "Bonding-Curve / BoundedClaim mint-redeem dislocations. Provide mutually exclusive `min_bounty_usd` vs `min_bounty_micro`."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "liquidator_account_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Liquidator account ID (>= 1) credited with the liquidation bounty; defaults to session account_id when omitted.",
                    },
                    "market_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Target market ID to scan for underwater positions (0 = all markets; >= 1 required when --max-order-notional-usd is enabled).",
                    },
                    "target_account_id": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Specific underwater account ID to liquidate (0 = scan all eligible underwater accounts).",
                    },
                    "max_lots": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Maximum position size to liquidate in integer lots (1 lot = 1e-4 base, 0 = all eligible lots unless notional cap requires > 0).",
                    },
                    "min_bounty_usd": {
                        "type": ["string", "number"],
                        "description": "Minimum net liquidation bounty required in exact USD (e.g. '0.10'; atomic revert if unmet); mutually exclusive with min_bounty_micro.",
                    },
                    "min_bounty_micro": {
                        "type": "integer",
                        "default": 0,
                        "description": "Minimum net liquidation bounty required in integer micro-USD (1 micro = $1e-6, 0 = any non-negative bounty); mutually exclusive with min_bounty_usd.",
                    },
                    "flash_offload_to_book": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, atomically offloads seized positions into resting L3 book liquidity so $0 pre-margin is required.",
                    },
                    "stp": {
                        "type": "string",
                        "enum": ["cancel_resting", "cancel_incoming", "cancel_both", "none"],
                        "default": "cancel_resting",
                        "description": "Self-Trade Prevention policy applied when flash-offloading onto the orderbook.",
                    },
                    "hedge_margin_spot": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, permits cross-margined Spot hedging during liquidation offload.",
                    },
                    "bounty_rebate_bid_bps": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9000,
                        "default": 0,
                        "description": "Optional competitive share of liquidation bounty rebated to the insurance reserve in basis points (0..9000 bps, 0 = keep 100%).",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "arena_onboard_and_deposit",
            "description": (
                "End-to-end self-service AI agent cold-start: logs in or generates an ephemeral EIP-191 wallet, claims Base Sepolia "
                "testnet collateral + gas from POST /faucet, and deposits ERC-20 margin on-chain into the L2 collateral vault. Mutates session "
                "auth, faucet state, and trading margin; use arena_login_wallet instead when your wallet is already funded or when "
                "running $0-pre-margin flash arbitrage without on-chain deposits."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "generate_ephemeral": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, generates a fresh CSPRNG secp256k1 wallet in-memory and authenticates it into this session.",
                    },
                    "request_faucet": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, calls POST /faucet on testnet to mint test collateral (and optional gas) to the wallet.",
                    },
                    "faucet_amount": {
                        "type": ["string", "number"],
                        "default": "10000",
                        "description": "Testnet collateral amount to request from POST /faucet in exact asset units (e.g. '10000' USD).",
                    },
                    "asset_symbol": {
                        "type": "string",
                        "default": "USD",
                        "description": "Collateral asset symbol for faucet minting and L2 collateral vault margin deposit (default 'USD').",
                    },
                    "drip_gas": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true with request_faucet, also requests Base Sepolia ETH gas drip for signing on-chain deposit transactions.",
                    },
                    "deposit_onchain": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, broadcasts ERC-20 approve + L2 collateral vault margin deposit transactions on-chain.",
                    },
                    "deposit_amount": {
                        "type": ["string", "number"],
                        "description": "Exact collateral amount to deposit on-chain into the L2 collateral vault (defaults to faucet_amount when omitted).",
                    },
                    "rpc_url": {
                        "type": "string",
                        "default": "",
                        "description": "Optional public HTTPS EVM JSON-RPC endpoint override for on-chain deposit (empty uses --rpc-url or chain default; loopback/private IPs blocked).",
                    },
                    "wait_for_credit": {
                        "type": "boolean",
                        "default": True,
                        "description": "When true, polls GET /account until the Arena deposit indexer credits off-chain trading margin.",
                    },
                    "poll_timeout_sec": {
                        "type": "number",
                        "minimum": 0.5,
                        "maximum": 120.0,
                        "default": 30.0,
                        "description": "Maximum seconds (0.5..120.0, default 30.0) to poll for off-chain margin credit when wait_for_credit=true.",
                    },
                },
                "additionalProperties": False,
            },
        },
    ]
    for spec in raw_specs:
        ann = _build_tool_annotations(str(spec["name"]))
        spec["title"] = ann["title"]
        spec["annotations"] = ann
    return raw_specs


class ArenaMcpGateway:
    """Policy-enforcing MCP server handler wired to a real ArenaHttpClient/ArenaBinaryClient."""

    def __init__(
        self,
        *,
        arena_url: str = "http://127.0.0.1:8080",
        tcp_host: str = "",
        tcp_port: int = 0,
        account_id: int = 0,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        creds_file: Optional[str | Path] = None,
        wallet_privkey_hex: Optional[str] = None,
        rpc_url: str = "",
        clearinghouse: str = "",
        expected_operator_address: str = "",
        read_only: bool = False,
        public_http_mode: bool = False,
        allowed_accounts: Optional[frozenset[int]] = None,
        max_order_notional_micro: int = 0,
        require_drawdown_stop: bool = False,
        min_drawdown_stop_micro: int = 0,
        default_builder_account: int = 0,
        default_builder_bps: int = 0,
        allow_withdrawals: bool = False,
        allowed_withdrawal_recipients: Optional[frozenset[str]] = None,
        allow_wallet_login: bool = False,
        http_bearer_token: str = "",
        timeout: float = 5.0,
    ) -> None:
        if default_builder_bps < 0 or default_builder_bps > MAX_BUILDER_FEE_SHARE_BPS:
            raise ValueError(
                f"default_builder_bps {default_builder_bps} out of [0, {MAX_BUILDER_FEE_SHARE_BPS}]"
            )
        if int(min_drawdown_stop_micro) < 0:
            raise ValueError(f"min_drawdown_stop_micro must be >= 0, got {min_drawdown_stop_micro}")
        self.public_http_mode = _strict_bool(public_http_mode, "public_http_mode")
        self.read_only = _strict_bool(read_only, "read_only") or self.public_http_mode
        self._public_unauth_http_mode = self.public_http_mode
        self.http_bearer_token = str(http_bearer_token or "").strip()
        self._default_account_id = int(account_id)
        self.allowed_accounts = allowed_accounts
        self.max_order_notional_micro = int(max_order_notional_micro)
        self.min_drawdown_stop_micro = int(min_drawdown_stop_micro)
        self.require_drawdown_stop = bool(
            _strict_bool(require_drawdown_stop, "require_drawdown_stop") or self.min_drawdown_stop_micro > 0
        )
        self.default_builder_account = int(default_builder_account)
        self.default_builder_bps = int(default_builder_bps)
        self.allow_withdrawals = _strict_bool(allow_withdrawals, "allow_withdrawals")
        self.allowed_withdrawal_recipients = allowed_withdrawal_recipients
        self.allow_wallet_login = _strict_bool(allow_wallet_login, "allow_wallet_login")
        self._static_creds_configured = bool(api_key or api_secret or creds_file or wallet_privkey_hex)
        self.rpc_url = str(rpc_url or "").strip()
        self.clearinghouse = str(clearinghouse or "").strip()
        self.expected_operator_address = str(expected_operator_address or "").strip()
        self._wallet_privkey_hex = str(wallet_privkey_hex or "").strip()
        self._builder_bound_accounts: set[int] = set()
        self._initialized = False
        self._dispatch_lock = threading.RLock()
        self._market_load_lock = threading.Lock()
        self._creds_reload_lock = threading.Lock()

        self.adapter = ArenaCcxtAdapter(
            arena_url,
            account_id=account_id,
            api_key=api_key,
            api_secret=api_secret,
            creds_file=creds_file,
            wallet_privkey_hex=(None if self.read_only else (self._wallet_privkey_hex or None)),
            tcp_host=tcp_host or None,
            tcp_port=tcp_port,
            timeout=timeout,
        )
        http_pool = getattr(self.adapter.http, "_http_pool", None)
        if self.read_only and http_pool is not None and hasattr(http_pool, "_max_idle"):
            http_pool._max_idle = max(int(getattr(http_pool, "_max_idle", 4)), 32)
        if getattr(self.adapter.http, "_creds_path", None) is not None:
            orig_reload = self.adapter.http._reload_creds_file
            creds_lk = self._creds_reload_lock

            def _locked_reload(force: bool = False, raise_on_error: bool = False) -> bool:
                with creds_lk:
                    return orig_reload(force=force, raise_on_error=raise_on_error)

            self.adapter.http._reload_creds_file = _locked_reload  # type: ignore[method-assign]

    @property
    def client(self) -> ArenaHttpClient:
        return self.adapter.http

    def _has_authenticated_credentials(self) -> bool:
        has_key = bool(getattr(self.adapter.http, "api_key", None))
        has_acct = int(getattr(self.adapter, "account_id", 0)) > 0 or int(self._default_account_id) > 0
        return has_key or has_acct

    def _has_binary_wire(self) -> bool:
        return int(getattr(self.adapter, "_tcp_port", 0)) > 0 or getattr(self.adapter, "binary", None) is not None

    @staticmethod
    def _is_public_global_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        mapped = getattr(ip_obj, "ipv4_mapped", None)
        chk = mapped if mapped is not None else ip_obj
        return bool(
            chk.is_global
            and not chk.is_private
            and not chk.is_loopback
            and not chk.is_link_local
            and not chk.is_multicast
            and not chk.is_unspecified
            and not chk.is_reserved
        )

    def _validate_caller_rpc_url(self, caller_rpc: str) -> str:
        raw_in = str(caller_rpc or "")
        if any(ord(c) < 32 or ord(c) == 127 for c in raw_in):
            raise PermissionError("unsafe_rpc_url: control characters disallowed in caller rpc_url")
        raw = raw_in.strip()
        if self.rpc_url:
            if raw and raw != self.rpc_url:
                raise PermissionError("rpc_url_override_disallowed: operator --rpc-url is locked")
            return self.rpc_url
        if not raw:
            return ""
        if any(c.isspace() or ord(c) < 32 for c in raw) or "," in raw:
            raise PermissionError(
                "unsafe_rpc_url: comma-separated failover URLs and whitespace/control characters disallowed"
            )
        parsed = urllib.parse.urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise PermissionError("unsafe_rpc_url: caller rpc_url override must use https://")
        if parsed.username or parsed.password:
            raise PermissionError("unsafe_rpc_url: credentials disallowed in caller rpc_url")
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            raise ValueError(f"Invalid rpc_url host: {raw!r}")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise PermissionError("unsafe_rpc_url: local/internal hostname disallowed")
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            ip_obj = None
        if ip_obj is not None:
            if not self._is_public_global_ip(ip_obj):
                raise PermissionError("unsafe_rpc_url: non-global or reserved IP literal disallowed")
            return raw
        if all(part.isdigit() or part.startswith("0x") for part in host.split(".") if part):
            raise PermissionError("unsafe_rpc_url: non-canonical numeric IP host disallowed")
        try:
            infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise PermissionError(f"unsafe_rpc_url: DNS resolution failed for {host!r}") from exc
        if not infos:
            raise PermissionError(f"unsafe_rpc_url: empty DNS resolution for {host!r}")
        for info in infos:
            resolved_ip_str = str(info[4][0]).split("%", 1)[0]
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if not self._is_public_global_ip(resolved_ip):
                raise PermissionError("unsafe_rpc_url: hostname resolves to non-global IP address")
        return raw

    def close(self) -> None:
        self.adapter.close()

    def _effective_account(self, explicit_aid: Optional[int]) -> int:
        aid = int(explicit_aid) if explicit_aid is not None else int(self.adapter.account_id)
        if aid <= 0:
            raise ValueError("account_id required (pass account_id, --account-id, or run arena_login_wallet)")
        if self.allowed_accounts is not None and aid not in self.allowed_accounts:
            raise PermissionError(f"account_not_in_allowed_accounts: {aid}")
        return aid

    def _check_account_allowlist(self, aid: int) -> None:
        if self.allowed_accounts is not None and int(aid) not in self.allowed_accounts:
            raise PermissionError(f"account_not_in_allowed_accounts: {aid}")

    def _resolve_market_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.adapter.markets_by_id:
            with self._market_load_lock:
                if not self.adapter.markets_by_id:
                    self.adapter.load_markets(reload=False)
        if args.get("symbol"):
            return self.adapter.resolve_market(str(args["symbol"]))
        if args.get("market_id") is not None:
            return self.adapter.resolve_market(int(args["market_id"]))
        raise ValueError("Either symbol or market_id must be provided")

    def _resolve_price_ticks(
        self,
        args: Dict[str, Any],
        market: Dict[str, Any],
        *,
        usd_key: str = "price_usd",
        ticks_key: str = "price_ticks",
        allow_zero: bool = False,
    ) -> int:
        is_spread = str(market.get("kind", "")).lower() == "spread_book"
        if ticks_key in args and args[ticks_key] is not None:
            px = int(args[ticks_key])
            if not allow_zero and not is_spread and px <= 0:
                raise ValueError(f"{ticks_key} must be > 0 for non-spread market")
            return px
        if usd_key in args and args[usd_key] is not None:
            return usd_to_price_ticks(args[usd_key], allow_zero=(allow_zero or is_spread), allow_negative=is_spread)
        if allow_zero:
            return 0
        raise ValueError(f"Either {usd_key} or {ticks_key} must be provided")

    def _resolve_qty_lots(
        self,
        args: Dict[str, Any],
        *,
        base_key: str = "amount_base",
        lots_key: str = "qty_lots",
        allow_zero: bool = False,
    ) -> int:
        if lots_key in args and args[lots_key] is not None:
            q = int(args[lots_key])
            if (not allow_zero and q <= 0) or q < 0 or q > MAX_WIRE_HEADER_QTY_LOTS:
                raise ValueError(f"{lots_key} {q} out of valid wire bounds")
            return q
        if base_key in args and args[base_key] is not None:
            return base_to_qty_lots(args[base_key], allow_zero=allow_zero)
        raise ValueError(f"Either {base_key} or {lots_key} must be provided")

    def _lookup_ref_ticks(self, market_id: int, side_str: str) -> int:
        _ = side_str
        book_resp = self.adapter.http.book(market_id, depth=1)
        if book_resp.get("ok"):
            best = max(
                abs(int(book_resp.get("best_ask_ticks") or 0)),
                abs(int(book_resp.get("mark_price_ticks") or 0)),
                abs(int(book_resp.get("best_bid_ticks") or 0)),
            )
            if best > 0:
                return best
        tk_resp = self.adapter.http.ticker(market_id)
        if tk_resp.get("ok") and isinstance(tk_resp.get("ticker"), dict):
            tk = tk_resp["ticker"]
            best_tk = max(
                abs(int(tk.get("mark_price_ticks") or 0)),
                abs(int(tk.get("best_ask_ticks") or 0)),
                abs(int(tk.get("best_bid_ticks") or 0)),
                abs(int(tk.get("last_trade_price_ticks") or 0)),
            )
            if best_tk > 0:
                return best_tk
        return 0

    def _effective_min_drawdown_stop_micro(self) -> int:
        if not self.require_drawdown_stop:
            return 0
        return max(self.min_drawdown_stop_micro, 1_000_000)

    def _enforce_notional_cap(
        self,
        *,
        market: Dict[str, Any],
        side_str: str,
        price_ticks: int,
        qty_lots: int,
        reduce_only: bool,
        is_pegged_or_market: bool,
        jit_elastic_mult: int = 0,
        margin_spot: bool = False,
        is_visible_iceberg: bool = False,
        peg_offset_ticks: int = 0,
    ) -> int:
        jit_mult_in = int(jit_elastic_mult)
        if jit_mult_in < 0:
            raise ValueError(f"jit_elastic_mult must be >= 0, got {jit_mult_in}")
        if self.max_order_notional_micro <= 0 or reduce_only or qty_lots <= 0:
            return 0
        mid = int(market["market_id"])
        is_spread = str(market.get("kind", "")).lower() == "spread_book"
        norm_side = str(side_str or "").strip().lower()
        if is_spread:
            ref_list = market.get("ref_markets") if isinstance(market.get("ref_markets"), (list, tuple)) else []
            leg1 = int(
                market.get("ref_market_1", 0)
                or (ref_list[0] if len(ref_list) >= 1 else 0)
                or market.get("leg1_market_id", 0)
            )
            leg2 = int(
                market.get("ref_market_2", 0)
                or (ref_list[1] if len(ref_list) >= 2 else 0)
                or market.get("leg2_market_id", 0)
            )
            leg3 = int(
                market.get("ref_market_3", 0)
                or (ref_list[2] if len(ref_list) >= 3 else 0)
            )
            if leg1 <= 0 or leg2 <= 0:
                raise PermissionError(
                    f"max_order_notional_exceeded: unavailable spread leg metadata on spread_book market {mid}"
                )
            gross_leg_ticks = 0
            for leg_mid in ([leg1, leg2] + ([leg3] if leg3 > 0 else [])):
                leg_ref = max(
                    self._lookup_ref_ticks(leg_mid, "bid"),
                    self._lookup_ref_ticks(leg_mid, "ask"),
                )
                if leg_ref <= 0:
                    raise PermissionError(
                        f"max_order_notional_exceeded: unavailable leg {leg_mid} reference price for spread_book market {mid}"
                    )
                gross_leg_ticks += leg_ref
            eff_ticks = max(gross_leg_ticks, abs(price_ticks))
        else:
            need_ref = is_pegged_or_market or price_ticks == 0 or (norm_side in ("ask", "sell"))
            if not need_ref:
                eff_ticks = abs(price_ticks)
            else:
                ref = self._lookup_ref_ticks(mid, norm_side)
                if ref > 0:
                    eff_ticks = max(abs(price_ticks), ref)
                elif price_ticks != 0 and not is_pegged_or_market:
                    eff_ticks = abs(price_ticks)
                else:
                    raise PermissionError(
                        f"max_order_notional_exceeded: unavailable reference price on market {mid}"
                    )
        if is_pegged_or_market and int(peg_offset_ticks) > 0:
            eff_ticks += int(peg_offset_ticks)
        eff_jit_mult = (
            min(jit_mult_in, 50)
            if (jit_mult_in >= 2 and not reduce_only and not margin_spot and not is_visible_iceberg)
            else 1
        )
        notional_micro = eff_ticks * qty_lots * eff_jit_mult
        if notional_micro > self.max_order_notional_micro:
            raise PermissionError(
                f"max_order_notional_exceeded: order notional ${micro_to_usd_str(notional_micro)} "
                f"exceeds cap ${micro_to_usd_str(self.max_order_notional_micro)}"
            )
        return notional_micro

    def _enforce_delta_hedge_notional_cap(
        self,
        *,
        aid: int,
        acct_snap: Optional[Dict[str, Any]],
        base_asset_id: int,
        preferred_market_id: int,
        max_qty_lots: int,
        max_slippage_bps: int = 200,
    ) -> None:
        if self.max_order_notional_micro <= 0:
            return
        if max_qty_lots < 0:
            raise ValueError(f"max_qty_lots must be >= 0, got {max_qty_lots}")
        raw_slip = int(max_slippage_bps)
        if raw_slip < 0:
            raise ValueError(f"max_slippage_bps must be >= 0, got {raw_slip}")
        eff_slip_bps = 500 if raw_slip == 0 else min(raw_slip, 5_000)

        def _with_slip(notional: int) -> int:
            if notional <= 0:
                return 0
            return (notional * (10_000 + eff_slip_bps) + 9_999) // 10_000

        reloaded_mkts = False

        def _refresh_markets_once(ctx_label: str) -> None:
            nonlocal reloaded_mkts
            if reloaded_mkts:
                return
            reloaded_mkts = True
            try:
                self.adapter.load_markets(reload=True)
            except Exception as mkt_exc:
                if not self.adapter.markets_by_id:
                    raise PermissionError(
                        f"max_order_notional_exceeded: unavailable market metadata for {ctx_label} ({mkt_exc})"
                    ) from mkt_exc

        def _get_market_info(mid: int) -> Dict[str, Any]:
            if mid not in self.adapter.markets_by_id:
                _refresh_markets_once("hedge sizing")
            entry = self.adapter.markets_by_id.get(mid)
            if isinstance(entry, dict) and isinstance(entry.get("info"), dict):
                return dict(entry["info"])
            return {}

        def _market_base_asset_id(mid: int) -> int:
            return int(_get_market_info(mid).get("base_asset_id", 0))

        def _expand_formula_asset_deltas(mid: int, signed_notional_micro: int, depth: int = 0) -> List[tuple[int, int]]:
            if signed_notional_micro == 0:
                return []
            info = _get_market_info(mid) if mid > 0 else {}
            mkt_base_aid = int(info.get("base_asset_id", 0))
            kind = _canonical_market_kind(info.get("kind", ""))
            fkind = str(info.get("formula_kind", "")).lower()
            ref_list = info.get("ref_markets") if isinstance(info.get("ref_markets"), list) else []
            refs = [
                int(info.get(f"ref_market_{i + 1}", 0) or (ref_list[i] if len(ref_list) > i else 0))
                for i in range(3)
            ]
            if depth < 8 and kind == "perp" and refs[0] > 0 and refs[0] != mid:
                return _expand_formula_asset_deltas(refs[0], signed_notional_micro, depth + 1)
            if depth < 8 and kind == "formula_perp":
                if fkind == "power2" and refs[0] > 0:
                    return _expand_formula_asset_deltas(refs[0], signed_notional_micro * 2, depth + 1)
                if fkind == "power3" and refs[0] > 0:
                    return _expand_formula_asset_deltas(refs[0], signed_notional_micro * 3, depth + 1)
                if fkind == "ratio" and refs[0] > 0 and refs[1] > 0:
                    return (
                        _expand_formula_asset_deltas(refs[0], signed_notional_micro, depth + 1)
                        + _expand_formula_asset_deltas(refs[1], -signed_notional_micro, depth + 1)
                    )
                if fkind == "linear_spread":
                    weights = info.get("weights_centi") if isinstance(info.get("weights_centi"), list) else []
                    nz = [
                        (refs[k], int(weights[k]))
                        for k in range(3)
                        if refs[k] > 0 and k < len(weights) and int(weights[k]) != 0
                    ]
                    if nz:
                        f_mark = abs(self._lookup_ref_ticks(mid, "bid"))
                        leg_marks = [abs(self._lookup_ref_ticks(rk, "bid")) for rk, _ in nz]
                        out_ls: List[tuple[int, int]] = []
                        if f_mark > 0 and all(sm > 0 for sm in leg_marks):
                            denom = 100 * f_mark
                            for (rk, wk), sm in zip(nz, leg_marks):
                                out_ls.extend(
                                    _expand_formula_asset_deltas(
                                        rk, (signed_notional_micro * wk * sm) // denom, depth + 1
                                    )
                                )
                        else:
                            for rk, wk in nz:
                                leg_d = signed_notional_micro if wk >= 0 else -signed_notional_micro
                                out_ls.extend(_expand_formula_asset_deltas(rk, leg_d, depth + 1))
                        if out_ls:
                            return out_ls
                if fkind == "funding_and_carry_index" and refs[0] > 0 and refs[1] > 0:
                    weights = info.get("weights_centi") if isinstance(info.get("weights_centi"), list) else []
                    w1 = int(weights[1]) if len(weights) >= 2 and int(weights[1]) != 0 else 100
                    f_mark = abs(self._lookup_ref_ticks(mid, "bid"))
                    s0 = abs(self._lookup_ref_ticks(refs[0], "bid"))
                    s1 = abs(self._lookup_ref_ticks(refs[1], "bid"))
                    if f_mark > 0 and s0 > 0 and s1 > 0:
                        denom = 100 * f_mark
                        return (
                            _expand_formula_asset_deltas(refs[0], (signed_notional_micro * w1 * s0) // denom, depth + 1)
                            + _expand_formula_asset_deltas(refs[1], -(signed_notional_micro * w1 * s1) // denom, depth + 1)
                        )
                    return (
                        _expand_formula_asset_deltas(refs[0], signed_notional_micro, depth + 1)
                        + _expand_formula_asset_deltas(refs[1], -signed_notional_micro, depth + 1)
                    )
                fallback_legs: List[tuple[int, int]] = []
                for rk in refs:
                    if rk > 0 and rk != mid:
                        fallback_legs.extend(_expand_formula_asset_deltas(rk, signed_notional_micro, depth + 1))
                if fallback_legs:
                    return fallback_legs
            return [(mkt_base_aid, signed_notional_micro)]

        def _collect_cand_mids_for_asset(s_aid: int, side_for_lookup: str = "bid") -> int:
            if not self.adapter.markets_by_id:
                _refresh_markets_once("spot hedge sizing")
            pref_entry = self.adapter.markets_by_id.get(preferred_market_id)
            pref_kind = str((pref_entry.get("info") or {}).get("kind", "")).lower() if isinstance(pref_entry, dict) else ""

            def _cand_list() -> List[int]:
                mids_out: List[int] = []
                if preferred_market_id > 0 and _market_base_asset_id(preferred_market_id) == s_aid and pref_kind != "spread_book":
                    mids_out.append(int(preferred_market_id))
                for prefer_kinds in (("spot", "perp"), ("formula_perp",)):
                    for mid_k, entry in self.adapter.markets_by_id.items():
                        info = entry.get("info") if isinstance(entry, dict) else None
                        if (
                            isinstance(info, dict)
                            and int(info.get("base_asset_id", 0)) == s_aid
                            and _canonical_market_kind(info.get("kind", "")) in prefer_kinds
                            and int(mid_k) not in mids_out
                        ):
                            mids_out.append(int(mid_k))
                return mids_out

            cands = _cand_list()
            if not cands and not reloaded_mkts:
                _refresh_markets_once("spot hedge sizing")
                cands = _cand_list()
            for cand_mid in cands:
                px = self._lookup_ref_ticks(cand_mid, side_for_lookup)
                if px > 0:
                    return px
            return 0

        if preferred_market_id > 0 and max_qty_lots > 0:
            ref = self._lookup_ref_ticks(preferred_market_id, "bid")
            if ref <= 0:
                raise PermissionError(
                    f"max_order_notional_exceeded: unavailable reference price on market {preferred_market_id}"
                )
            est = _with_slip(ref * max_qty_lots)
            if est > self.max_order_notional_micro:
                raise PermissionError(
                    f"max_order_notional_exceeded: delta hedge notional ${micro_to_usd_str(est)} "
                    f"exceeds cap ${micro_to_usd_str(self.max_order_notional_micro)}"
                )
            # Only return early when the server hedge is constrained to the same single base_asset_id;
            # with base_asset_id == 0 the engine loops across all registered base assets up to max_qty_lots each.
            if base_asset_id > 0 and _market_base_asset_id(preferred_market_id) == base_asset_id:
                return

        if acct_snap is None:
            acct_snap = self.adapter.http.account(aid)
            if not isinstance(acct_snap, dict) or not acct_snap.get("ok"):
                raise RuntimeError(f"GET /account failed: {acct_snap}")

        abs_delta_by_asset: Dict[int, int] = {}
        asset_ref_px_hint: Dict[int, int] = {}

        for pp in list(acct_snap.get("perp_positions", [])):
            pos_lots = int(pp.get("position_lots", 0))
            if pos_lots == 0:
                continue
            pmid = int(pp.get("market_id", 0))
            ref_px = int(pp.get("mark_price_ticks", 0))
            if ref_px <= 0 and pmid > 0:
                ref_px = self._lookup_ref_ticks(pmid, "ask" if pos_lots > 0 else "bid")
            if ref_px <= 0:
                raise PermissionError(
                    f"max_order_notional_exceeded: unavailable reference price on market {pmid}"
                )
            pp_baid = int(pp.get("base_asset_id", 0)) or _market_base_asset_id(pmid)
            expanded = _expand_formula_asset_deltas(pmid, pos_lots * ref_px, 0)
            for d_aid, d_micro in expanded:
                eff_aid = d_aid if d_aid > 0 else pp_baid
                if base_asset_id > 0 and eff_aid != base_asset_id:
                    continue
                if d_micro != 0:
                    abs_delta_by_asset[eff_aid] = abs_delta_by_asset.get(eff_aid, 0) + abs(d_micro)
                    if eff_aid == pp_baid and pp_baid > 0:
                        asset_ref_px_hint.setdefault(eff_aid, ref_px)

        base_holdings = (
            acct_snap["base_balances"]
            if "base_balances" in acct_snap
            else acct_snap.get("spot_balances", [])
        )
        for sb in list(base_holdings or []):
            s_aid = int(sb.get("asset_id", 0))
            if base_asset_id > 0 and s_aid != base_asset_id:
                continue
            net_lots = int(sb.get("free_lots", 0)) + int(sb.get("locked_lots", 0)) - int(sb.get("borrowed_lots", 0))
            if net_lots == 0:
                continue
            ref_px = int(sb.get("mark_price_ticks", 0))
            if ref_px <= 0:
                ref_px = _collect_cand_mids_for_asset(s_aid, "ask" if net_lots > 0 else "bid")
            if ref_px <= 0:
                raise PermissionError(
                    f"max_order_notional_exceeded: unavailable reference price for asset_id={s_aid}"
                )
            abs_delta_by_asset[s_aid] = abs_delta_by_asset.get(s_aid, 0) + abs(net_lots) * ref_px
            asset_ref_px_hint.setdefault(s_aid, ref_px)

        total_notional = 0
        for b_aid_key, raw_abs in abs_delta_by_asset.items():
            eff_n = raw_abs
            if max_qty_lots > 0:
                a_ref = asset_ref_px_hint.get(b_aid_key, 0)
                if a_ref <= 0:
                    a_ref = _collect_cand_mids_for_asset(b_aid_key, "bid")
                if a_ref > 0:
                    eff_n = min(eff_n, max_qty_lots * a_ref)
            total_notional += eff_n

        worst_notional = _with_slip(total_notional)
        if worst_notional > self.max_order_notional_micro:
            raise PermissionError(
                f"max_order_notional_exceeded: delta hedge notional ${micro_to_usd_str(worst_notional)} "
                f"exceeds cap ${micro_to_usd_str(self.max_order_notional_micro)}"
            )

    def _preflight_risk_and_builder(self, aid: int, *, risk_increasing: bool) -> Optional[Dict[str, Any]]:
        need_acct_fetch = (self.require_drawdown_stop and risk_increasing) or (
            self.default_builder_account > 0
            and self.default_builder_bps > 0
            and aid != self.default_builder_account
            and aid not in self._builder_bound_accounts
        )
        if not need_acct_fetch:
            return None
        acct = self.adapter.http.account(aid)
        if not acct.get("ok"):
            raise RuntimeError(f"GET /account preflight failed: {acct}")
        if self.require_drawdown_stop and risk_increasing:
            min_dd = self._effective_min_drawdown_stop_micro()
            cur_dd = int(acct.get("drawdown_stop_equity_micro", 0))
            if cur_dd < min_dd:
                raise PermissionError(
                    f"drawdown_stop_required_before_trading: account {aid} has "
                    f"drawdown_stop_equity_micro={cur_dd} (< minimum {min_dd}); "
                    "call arena_configure_risk_guardrails first"
                )
        if (
            self.default_builder_account > 0
            and self.default_builder_bps > 0
            and aid != self.default_builder_account
            and aid not in self._builder_bound_accounts
        ):
            cur_builder = int(acct.get("builder_account_id", 0))
            if cur_builder == 0:
                bres = self.adapter.http.bind_builder_code(
                    aid, self.default_builder_account, self.default_builder_bps
                )
                if not bres.get("ok"):
                    raise RuntimeError(f"Auto bind_builder_code failed: {bres}")
            self._builder_bound_accounts.add(aid)
        return acct

    def _enforce_transfer_or_withdrawal_guardrails(
        self,
        *,
        aid: int,
        asset_id: int,
        raw_amount: int,
        op_label: str,
    ) -> None:
        amt_i = int(raw_amount)
        if amt_i <= 0:
            raise ValueError(f"{op_label} amount must be > 0, got {amt_i}")
        if self.require_drawdown_stop:
            acct = self.adapter.http.account(aid)
            if not acct.get("ok"):
                raise RuntimeError(f"GET /account preflight failed: {acct}")
            min_dd = self._effective_min_drawdown_stop_micro()
            cur_dd = int(acct.get("drawdown_stop_equity_micro", 0))
            if cur_dd < min_dd:
                raise PermissionError(
                    f"drawdown_stop_required_before_trading: account {aid} has "
                    f"drawdown_stop_equity_micro={cur_dd} (< minimum {min_dd}); "
                    "call arena_configure_risk_guardrails first"
                )
        if self.max_order_notional_micro > 0:
            aid_u16 = int(asset_id)
            if aid_u16 == 0:
                notional_micro = amt_i
            else:
                reloaded_t = False

                def _cands_for_asset() -> List[int]:
                    out_c: List[int] = []
                    for pkinds in (("spot", "perp"), ("formula_perp",)):
                        for mk, entry in self.adapter.markets_by_id.items():
                            info = entry.get("info") if isinstance(entry, dict) else None
                            if (
                                isinstance(info, dict)
                                and int(info.get("base_asset_id", 0)) == aid_u16
                                and _canonical_market_kind(info.get("kind", "")) in pkinds
                                and int(mk) not in out_c
                            ):
                                out_c.append(int(mk))
                    return out_c

                reload_exc: Optional[Exception] = None
                if not self.adapter.markets_by_id:
                    reloaded_t = True
                    try:
                        self.adapter.load_markets(reload=True)
                    except Exception as exc:
                        reload_exc = exc
                cands = _cands_for_asset()
                if not cands and not reloaded_t:
                    try:
                        self.adapter.load_markets(reload=True)
                    except Exception as exc:
                        reload_exc = exc
                    cands = _cands_for_asset()
                ref_px = 0
                for mk_id in cands:
                    ref_px = self._lookup_ref_ticks(mk_id, "bid")
                    if ref_px > 0:
                        break
                if ref_px <= 0:
                    detail = f" (market_reload_error={reload_exc})" if reload_exc is not None else ""
                    raise PermissionError(
                        f"max_order_notional_exceeded: unavailable reference price for asset_id={aid_u16} on {op_label}{detail}"
                    )
                notional_micro = amt_i * ref_px
            if notional_micro > self.max_order_notional_micro:
                raise PermissionError(
                    f"max_order_notional_exceeded: {op_label} notional ${micro_to_usd_str(notional_micro)} "
                    f"exceeds cap ${micro_to_usd_str(self.max_order_notional_micro)}"
                )

    def _scrub_obj(self, obj: Any) -> Any:
        return _scrub_secrets(obj, text_scrubber=self._scrub_secret_text)

    def _ok_tool_result(self, data: Any) -> Dict[str, Any]:
        clean = self._scrub_obj(data)
        return {
            "content": [{"type": "text", "text": json.dumps(clean, indent=2)}],
            "structuredContent": clean if isinstance(clean, dict) else {"result": clean},
            "isError": False,
        }

    def _scrub_secret_text(self, message: str) -> str:
        out = str(message)
        raw_tokens: List[str] = []
        for sec in (
            getattr(self.adapter.http, "api_key", ""),
            getattr(self.adapter.http, "api_secret", ""),
            getattr(self, "_wallet_privkey_hex", "") or "",
        ):
            s = str(sec or "").strip()
            if len(s) >= 6:
                raw_tokens.append(s)
                s_no_0x = s[2:] if s.lower().startswith("0x") else ""
                if len(s_no_0x) >= 16:
                    raw_tokens.append(s_no_0x)
        rpc_cfg = str(getattr(self, "rpc_url", "") or "").strip()
        if rpc_cfg:
            parsed_rpc = urllib.parse.urlsplit(rpc_cfg)
            if parsed_rpc.password and len(parsed_rpc.password) >= 6:
                raw_tokens.append(parsed_rpc.password)
            if parsed_rpc.query and len(parsed_rpc.query) >= 8:
                raw_tokens.append(parsed_rpc.query)
            last_seg = parsed_rpc.path.rstrip("/").rsplit("/", 1)[-1] if parsed_rpc.path else ""
            if len(last_seg) >= 16 and last_seg.lower() not in ("rpc", "jsonrpc"):
                raw_tokens.append(last_seg)
        wire_ints: List[int] = [
            int(getattr(self.adapter, "_wire_key_lo64", 0) or 0) & MASK64,
            int(getattr(self.adapter, "_wire_key_hi64", 0) or 0) & MASK64,
        ]
        bin_obj = getattr(self.adapter, "binary", None)
        if bin_obj is not None:
            wire_ints.extend(
                [
                    int(getattr(bin_obj, "key_lo64", 0) or 0) & MASK64,
                    int(getattr(bin_obj, "key_hi64", 0) or 0) & MASK64,
                ]
            )
        for wk in wire_ints:
            if wk > 0:
                wk_dec = str(wk)
                if len(wk_dec) >= 6:
                    raw_tokens.append(wk_dec)
                raw_tokens.extend(
                    [
                        f"0x{wk:016x}",
                        f"0X{wk:016X}",
                        f"{wk:016x}",
                        f"{wk:016X}",
                    ]
                )
                wk_hex_short = f"{wk:x}"
                if len(wk_hex_short) >= 6:
                    raw_tokens.append(f"0x{wk_hex_short}")
        for tok in raw_tokens:
            if tok:
                out = out.replace(tok, "[REDACTED]")
        return _SECRET_KV_RE.sub(r"\1[REDACTED]", out)

    def _err_tool_result(self, message: str) -> Dict[str, Any]:
        return {
            "content": [{"type": "text", "text": self._scrub_secret_text(str(message))}],
            "isError": True,
        }

    def list_tools(self) -> List[Dict[str, Any]]:
        specs = _tool_specs()
        if self.read_only:
            ro_specs = [t for t in specs if t["name"] in READ_ONLY_TOOLS]
            if self._public_unauth_http_mode:
                return [t for t in ro_specs if t["name"] not in PUBLIC_UNAUTH_HIDDEN_READ_TOOLS]
            return ro_specs
        return specs

    def list_prompts(self) -> List[Dict[str, Any]]:
        is_ro = bool(self.read_only)
        prompts: List[Dict[str, Any]] = []
        if not is_ro:
            prompts.append(
                {
                    "name": "onboard_and_quote_testnet",
                    "title": "Onboard & Quote Two-Sided Testnet Market",
                    "description": (
                        "Self-service cold-start workflow: provision an ephemeral EIP-191 wallet, claim Base Sepolia "
                        "faucet collateral + gas, deposit margin on-chain, arm risk guardrails, preview, and post a "
                        "two-sided maker quote."
                    ),
                    "arguments": [
                        {
                            "name": "symbol",
                            "description": "Target Arena market symbol (e.g. BTC/USD:USD or ETH/USD:USD).",
                            "required": True,
                        },
                        {
                            "name": "spread_bps",
                            "description": "Total two-sided bid/ask spread in basis points around mid/mark (e.g. 10).",
                            "required": True,
                        },
                    ],
                }
            )
        prompts.append(
            {
                "name": "scan_zero_capital_bounties",
                "title": "Scan Zero-Capital Flash Arbitrage & Liquidation Bounties",
                "description": (
                    "Read-only dry-run discovery scan of BoundedClaim and Bonding-Curve Spot markets for "
                    "$0-pre-margin flash-arbitrage dislocations and liquidation bounty candidates."
                    if is_ro
                    else (
                        "Scan BoundedClaim and Bonding-Curve Spot markets for $0-pre-margin atomic flash-arbitrage "
                        "dislocations and underwater accounts eligible for auto-liquidation bounties."
                    )
                ),
                "arguments": (
                    [
                        {
                            "name": "execute",
                            "description": "Read-only endpoint runs dry-run discovery only ('false'); use local uvx feraterra-sdk --testnet for live execution.",
                            "required": False,
                        },
                    ]
                    if is_ro
                    else [
                        {
                            "name": "execute",
                            "description": "Set to 'true' to execute positive-EV sweeps or 'false' for dry-run discovery only.",
                            "required": True,
                        },
                    ]
                ),
            }
        )
        prompts.append(
            {
                "name": "audit_exchange_solvency",
                "title": "Cryptographic Solvency & Sovereign Ledger-Tip Audit",
                "description": (
                    "Verify Arena Exchange conservation invariants, ARENA_LEDGER_TIP_V2_1 Keccak-256 + secp256k1 "
                    "operator signature, and optional L2 collateral vault Merkle emergency escape proof."
                ),
                "arguments": [
                    {
                        "name": "expected_operator_address",
                        "description": "Optional pinned 0x operator Ethereum address for ledger-tip signature verification.",
                        "required": False,
                    },
                ],
            }
        )
        return prompts

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = dict(arguments or {})
        is_ro = bool(self.read_only)
        if name == "onboard_and_quote_testnet":
            if is_ro:
                raise KeyError(
                    "Prompt 'onboard_and_quote_testnet' requires mutating tools unavailable in read-only mode; "
                    "run local `uvx feraterra-sdk --testnet` without `--read-only` instead."
                )
            symbol = str(args.get("symbol") or "BTC/USD:USD").strip() or "BTC/USD:USD"
            spread_bps = str(args.get("spread_bps") or "10").strip() or "10"
            text = (
                f"Onboard onto Arena Exchange testnet and quote {symbol} with a {spread_bps} bps two-sided spread:\n"
                "1. Inspect `arena_get_account_portfolio` if already authenticated; otherwise call "
                "`arena_onboard_and_deposit` with `generate_ephemeral=true`, `request_faucet=true`, and "
                "`deposit_onchain=true` to provision a wallet, mint Base Sepolia collateral + gas, and deposit "
                "margin into the L2 collateral vault.\n"
                "2. Call `arena_configure_risk_guardrails` to arm a portfolio `drawdown_stop_usd` floor and "
                "Rolling Market-Maker Protection (`mmp_window_wal_seqs`, `mmp_max_fill_lots`).\n"
                f"3. Call `arena_get_orderbook` for `{symbol}` to read the live best bid, best ask, and mark price.\n"
                f"4. Compute exact $0.01-aligned bid and ask prices `{spread_bps}` bps around mid/mark, run a "
                "zero-mutation margin check via `arena_preview_order` (`tif='post_only'`), and submit the quote "
                "atomically with `arena_replace_two_sided_quote` (`tif='post_only'`, `post_only_slide=true`)."
            )
            return {
                "description": f"Cold-start testnet onboarding and {spread_bps} bps two-sided maker quoting on {symbol}.",
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }

        if name == "scan_zero_capital_bounties":
            raw_exec = args.get("execute", "false")
            exec_bool = False if is_ro else (
                raw_exec
                if isinstance(raw_exec, bool)
                else str(raw_exec).strip().lower() in ("1", "true", "yes", "on")
            )
            mode_str = "LIVE EXECUTION (execute=true)" if exec_bool else "DRY-RUN SCAN ONLY (execute=false)"
            liq_step = (
                "3. Check `arena_get_leaderboard` and market volatility for potential underwater accounts and "
                "simulate candidate fills read-only via `arena_preview_order` (`account_id=0`).\n"
                if is_ro
                else (
                    "3. Check `arena_get_leaderboard` and market volatility for potential underwater positions eligible "
                    "for `arena_auto_liquidate` (`flash_offload_to_book=true`).\n"
                )
            )
            text = (
                f"Run a zero-capital Arena Exchange bounty scan in {mode_str} mode:\n"
                "1. Call `arena_list_markets` (`active_only=true`) and inspect `bounded_claim` and bonding-curve "
                "`spot` markets alongside `arena_get_orderbook` snapshots.\n"
                "2. Check for intra-tick mint+sell or buy+redeem dislocations where book bid/ask crosses intrinsic "
                "curve/claim bounds.\n"
                + liq_step
                + (
                    "4. Since `execute=true`, ensure a session wallet is logged in (`arena_login_wallet` with "
                    "`generate_ephemeral=true` requires $0 pre-margin) and submit strictly positive-EV "
                    "`arena_flash_arbitrage` (`min_profit_usd='0.01'`) or `arena_auto_liquidate` (`min_bounty_usd='0.01'`) "
                    "sweeps."
                    if exec_bool
                    else (
                        "4. Read-only mode is active: DO NOT invoke mutating tools; report all discovered spread "
                        "dislocations, estimated net profits, and exact payloads ready for local `uvx feraterra-sdk --testnet` execution."
                        if is_ro
                        else "4. Since `execute=false`, DO NOT invoke mutating tools; report all discovered spread "
                        "dislocations, estimated net profits, and exact tool payloads ready for execution."
                    )
                )
            )
            return {
                "description": f"Zero-capital flash-arbitrage & liquidation bounty scanner ({mode_str}).",
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }

        if name == "audit_exchange_solvency":
            exp_op = str(args.get("expected_operator_address") or self.expected_operator_address or "").strip()
            if exp_op:
                _ = _norm_eth_address(exp_op)
            op_clause = (
                f"passing `expected_operator_address='{exp_op}'`"
                if exp_op
                else "verifying the self-asserted or CLI-pinned operator address"
            )
            step3_clause = (
                "3. Report exact state roots, WAL sequence numbers, recovered operator address, and cryptographic "
                "solvency verdict (for account-specific Merkle escape proofs, run local authenticated `uvx feraterra-sdk`)."
                if (self._public_unauth_http_mode or (is_ro and not self._has_authenticated_credentials()))
                else (
                    "3. If authenticated account credentials are configured, call `arena_get_withdrawals_and_escape_proof` "
                    "(`include_escape_proof=true`) and confirm `merkle_proof_verified == true`. Report exact state roots, "
                    "WAL sequence numbers, recovered operator address, and verdict."
                )
            )
            text = (
                "Perform an independent cryptographic solvency and conservation audit of Arena Exchange:\n"
                "1. Call `arena_health_and_manifest` (`include_manifest=true`) and verify `ok == true`, "
                "`conservation_ok == true`, monotonic WAL sequence progression, and insurance reserve health.\n"
                f"2. Call `arena_verify_ledger_tip` ({op_clause}) and confirm `signature_verified == true` on the "
                "`ARENA_LEDGER_TIP_V2_1` Keccak-256 + secp256k1 commitment.\n"
                + step3_clause
            )
            return {
                "description": "Cryptographic conservation, sovereign WAL ledger-tip, and Merkle solvency audit.",
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }

        raise KeyError(f"Unknown prompt: {name!r}")

    def list_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "uri": "arena://protocol/manifest",
                "name": "Arena Exchange Protocol Manifest",
                "mimeType": "application/json",
            },
            {
                "uri": "arena://markets/directory",
                "name": "Arena Exchange Live Market Directory",
                "mimeType": "application/json",
            },
            {
                "uri": "arena://ledger/tip",
                "name": "Verified Sovereign WAL Ledger Tip",
                "mimeType": "application/json",
            },
        ]

    def list_resource_templates(self) -> List[Dict[str, Any]]:
        return []

    def read_resource(self, uri: str) -> Dict[str, Any]:
        if uri == "arena://protocol/manifest":
            payload = self.adapter.http.protocol_info()
        elif uri == "arena://markets/directory":
            payload = self.adapter.http.markets()
        elif uri == "arena://ledger/tip":
            payload = self._verify_ledger_tip_impl(self.expected_operator_address)
        else:
            raise ValueError(f"Unknown resource URI: {uri!r}")
        clean = self._scrub_obj(payload)
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(clean, indent=2),
                }
            ]
        }

    def _verify_ledger_tip_impl(self, exp_op_addr: str) -> Dict[str, Any]:
        tip = self.adapter.http.ledger_tip()
        if not tip.get("ok"):
            raise RuntimeError(f"GET /ledger/tip failed: {tip}")
        pinned = str(exp_op_addr or "").strip()
        verified = verify_ledger_tip(
            tip,
            expected_operator_address=pinned,
            allow_self_asserted_signer=(not bool(pinned)),
        )
        out = dict(tip)
        out["signature_verified"] = bool(verified)
        out["pinned_operator_checked"] = bool(pinned)
        return out

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        args = dict(arguments or {})
        all_names = {t["name"] for t in _tool_specs()}
        if name not in all_names:
            raise KeyError(f"Unknown tool: {name!r}")
        if self._public_unauth_http_mode and name in PUBLIC_UNAUTH_HIDDEN_READ_TOOLS:
            return self._err_tool_result(
                f"public_http_mode_restricted: account-private tool {name!r} is disabled in --public-http-mode"
            )
        if self.read_only and name not in READ_ONLY_TOOLS:
            return self._err_tool_result(f"read_only_mode_enabled: mutating tool {name!r} rejected")

        try:
            if name == "arena_health_and_manifest":
                inc_manifest = _opt_strict_bool(args, "include_manifest", True)
                health = self.adapter.http.health()
                out: Dict[str, Any] = {"health": health}
                if inc_manifest:
                    out["manifest"] = self.adapter.http.protocol_info()
                return self._ok_tool_result(out)

            if name == "arena_list_markets":
                active_only = _opt_strict_bool(args, "active_only", True)
                resp = self.adapter.http.markets()
                if not resp.get("ok"):
                    raise RuntimeError(f"GET /markets failed: {resp}")
                mkts = list(resp.get("markets", []))
                kind_f = _canonical_market_kind(args.get("kind", ""))
                sym_f = str(args.get("symbol", "")).strip().upper()
                filtered: List[Dict[str, Any]] = []
                for m in mkts:
                    if kind_f and _canonical_market_kind(m.get("kind", "")) != kind_f:
                        continue
                    if active_only and str(m.get("trading_status", "live")).lower() == "halted":
                        continue
                    unified = self.adapter._unified_symbol_for_market(m)
                    if sym_f and sym_f not in (str(m.get("symbol", "")).upper(), unified.upper()):
                        continue
                    bid_t = int(m.get("best_bid_ticks") or 0)
                    ask_t = int(m.get("best_ask_ticks") or 0)
                    item = dict(m)
                    item["unified_symbol"] = unified
                    item["mark_price_usd"] = price_ticks_to_usd_str(int(m.get("mark_price_ticks") or 0))
                    item["best_bid_usd"] = price_ticks_to_usd_str(bid_t) if bid_t != 0 else None
                    item["best_ask_usd"] = price_ticks_to_usd_str(ask_t) if ask_t != 0 else None
                    filtered.append(item)
                return self._ok_tool_result({"wal_seq": resp.get("wal_seq", 0), "count": len(filtered), "markets": filtered})

            if name == "arena_get_orderbook":
                m = self._resolve_market_args(args)
                depth = int(args.get("depth", 20))
                book = self.adapter.http.book(int(m["market_id"]), depth=depth)
                if not book.get("ok"):
                    raise RuntimeError(f"GET /book failed: {book}")
                book["unified_symbol"] = self.adapter._unified_symbol_for_market(m)
                return self._ok_tool_result(book)

            if name == "arena_get_trades_and_candles":
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                interval = str(args.get("interval", "1m"))
                limit = int(args.get("limit", 50))
                trades = self.adapter.http.trades(mid, limit=min(512, limit))
                candles = self.adapter.http.candles(mid, interval=interval, limit=min(240, limit))
                return self._ok_tool_result(
                    {
                        "market_id": mid,
                        "symbol": m.get("symbol"),
                        "unified_symbol": self.adapter._unified_symbol_for_market(m),
                        "trades": trades.get("trades", []),
                        "candles": candles.get("candles", []),
                    }
                )

            if name == "arena_get_leaderboard":
                limit = int(args.get("limit", 25))
                sort_by = str(args.get("sort", "equity")).strip().lower() or "equity"
                lb = self.adapter.http.get_leaderboard(limit=limit, sort=sort_by)
                if not lb.get("ok"):
                    raise RuntimeError(f"GET /leaderboard failed: {lb}")
                return self._ok_tool_result(lb)

            if name == "arena_get_account_portfolio":
                aid = self._effective_account(args.get("account_id"))
                acct = self.adapter.http.account(aid)
                if not acct.get("ok"):
                    raise RuntimeError(f"GET /account failed: {acct}")
                acct["total_equity_usd"] = micro_to_usd_str(int(acct.get("total_equity_micro", 0)))
                acct["free_usd"] = micro_to_usd_str(int(acct.get("free_usd_micro", 0)))
                acct["withdrawable_usd"] = micro_to_usd_str(int(acct.get("withdrawable_usd_micro", 0)))
                return self._ok_tool_result(acct)

            if name == "arena_verify_ledger_tip":
                exp = str(args.get("expected_operator_address") or self.expected_operator_address or "").strip()
                res = self._verify_ledger_tip_impl(exp)
                if not res.get("signature_verified"):
                    return self._err_tool_result(f"ledger_tip_signature_verification_failed: {json.dumps(self._scrub_obj(res))}")
                return self._ok_tool_result(res)

            if name == "arena_get_withdrawals_and_escape_proof":
                aid = self._effective_account(args.get("account_id"))
                limit = int(args.get("limit", 50))
                inc_ep = _opt_strict_bool(args, "include_escape_proof", False)
                pend_ep = _opt_strict_bool(args, "pending", False)
                ver_logs = _opt_strict_bool(args, "verify_from_onchain_logs", False)
                wres = self.adapter.http.withdrawals(account_id=aid, limit=limit)
                if not wres.get("ok"):
                    raise RuntimeError(f"GET /withdrawals failed: {wres}")
                out: Dict[str, Any] = {"account_id": aid, "withdrawals": wres.get("withdrawals", []), "total_count": wres.get("total_count", 0)}
                asset_id = int(args.get("asset_id", 0))
                if inc_ep:
                    ep = self.adapter.http.settlement_escape_proof(
                        aid, asset_id=asset_id, pending=pend_ep
                    )
                    if not ep.get("ok"):
                        raise RuntimeError(f"GET /settlement/escape_proof failed: {ep}")
                    exp_root = str(args.get("expected_escape_merkle_root") or "").strip()
                    ep["merkle_proof_verified"] = verify_escape_merkle_proof(
                        ep,
                        expected_escape_merkle_root=exp_root,
                        allow_self_asserted_root=(not bool(exp_root)),
                    )
                    out["escape_proof"] = ep
                if ver_logs:
                    if not (self.rpc_url and self.clearinghouse):
                        raise ValueError("verify_from_onchain_logs requires --rpc-url and --clearinghouse")
                    evm = EvmJsonRpcClient(self.rpc_url, timeout=self.adapter.timeout)
                    try:
                        bal_u, owner_w, proof_list = reconstruct_escape_merkle_proof_from_logs(
                            evm, self.clearinghouse, aid, asset_id=asset_id
                        )
                    finally:
                        evm.close()
                    out["onchain_log_escape"] = {
                        "merkle_balance_units": bal_u,
                        "owner_wallet": owner_w,
                        "merkle_proof": proof_list,
                    }
                return self._ok_tool_result(out)

            if name == "arena_login_wallet":
                if self._static_creds_configured and not self.allow_wallet_login:
                    raise PermissionError(
                        "wallet_login_disabled: static --creds-file / --api-key credentials are configured; "
                        "pass --allow-wallet-login to permit arena_login_wallet session replacement"
                    )
                gen = _opt_strict_bool(args, "generate_ephemeral", False)
                if self._wallet_privkey_hex and not gen:
                    signer = EthWalletSigner(self._wallet_privkey_hex)
                elif gen:
                    signer = EthWalletSigner()
                else:
                    raise ValueError("No --wallet-privkey configured; pass generate_ephemeral=true or configure wallet CLI flag")
                http_c = self.adapter.http
                prev_key = http_c.api_key
                prev_sec = http_c.api_secret
                prev_creds_path = getattr(http_c, "_creds_path", None)
                prev_creds_role = getattr(http_c, "_creds_role", "trader")
                prev_creds_fb = getattr(http_c, "_creds_fallback_role", None)
                prev_creds_mtime = getattr(http_c, "_creds_mtime_ns", None)

                def _restore_http_creds() -> None:
                    http_c.set_credentials(prev_key, prev_sec)
                    if hasattr(http_c, "_creds_path"):
                        http_c._creds_path = prev_creds_path
                        http_c._creds_role = prev_creds_role
                        http_c._creds_fallback_role = prev_creds_fb
                        http_c._creds_mtime_ns = prev_creds_mtime

                try:
                    res = http_c.login_with_wallet(signer)
                    if not res.get("ok"):
                        raise RuntimeError(f"Wallet login failed: {self._scrub_obj(res)}")
                    aid = int(res["account_id"])
                    self._check_account_allowlist(aid)
                except Exception:
                    _restore_http_creds()
                    raise
                self._wallet_privkey_hex = signer.private_key_hex
                self.adapter.account_id = aid
                self._default_account_id = aid
                self.adapter._wire_key_lo64 = int(res.get("wire_key_lo64", self.adapter._wire_key_lo64)) & MASK64
                self.adapter._wire_key_hi64 = int(res.get("wire_key_hi64", self.adapter._wire_key_hi64)) & MASK64
                if self.adapter.binary is not None:
                    self.adapter.binary.close()
                    self.adapter._tcp_connected = False
                    self.adapter.binary.set_credentials(aid, self.adapter._wire_key_lo64, self.adapter._wire_key_hi64)
                return self._ok_tool_result(
                    {
                        "ok": True,
                        "account_id": aid,
                        "eth_address": res.get("eth_address", signer.address),
                        "role": res.get("role", "trader"),
                    }
                )

            if name == "arena_configure_risk_guardrails":
                aid = self._effective_account(args.get("account_id"))
                if args.get("cancel_on_disconnect") is not None and not self._has_binary_wire():
                    raise ValueError(
                        "cancel_on_disconnect requires binary wire (--tcp-port > 0)"
                    )
                results: Dict[str, Any] = {"account_id": aid}
                if args.get("drawdown_stop_usd_micro") is not None or args.get("drawdown_stop_usd") is not None:
                    dd_micro = (
                        int(args["drawdown_stop_usd_micro"])
                        if args.get("drawdown_stop_usd_micro") is not None
                        else usd_to_micro(args["drawdown_stop_usd"], allow_zero=True)
                    )
                    if dd_micro < 0:
                        raise ValueError(f"drawdown_stop_usd_micro must be >= 0, got {dd_micro}")
                    if self.require_drawdown_stop:
                        min_dd = self._effective_min_drawdown_stop_micro()
                        if dd_micro <= 0:
                            raise PermissionError(
                                "drawdown_stop_cannot_be_disabled: drawdown stop cannot be disabled while "
                                "--require-drawdown-stop / --min-drawdown-stop-usd is enabled"
                            )
                        if dd_micro < min_dd:
                            raise PermissionError(
                                f"drawdown_stop_below_minimum: requested drawdown_stop_equity_micro={dd_micro} "
                                f"is below minimum required {min_dd}"
                            )
                        cur_acct = self.adapter.http.account(aid)
                        if not cur_acct.get("ok"):
                            raise RuntimeError(f"GET /account failed before drawdown stop update: {cur_acct}")
                        cur_dd = int(cur_acct.get("drawdown_stop_equity_micro", 0))
                        if cur_dd > 0 and dd_micro < cur_dd:
                            raise PermissionError(
                                f"drawdown_stop_cannot_be_lowered: requested drawdown_stop_equity_micro={dd_micro} "
                                f"would lower active floor {cur_dd} while --require-drawdown-stop is enabled"
                            )
                    r = self.adapter.http.set_drawdown_stop(aid, dd_micro)
                    if not r.get("ok"):
                        raise RuntimeError(f"POST /drawdown_stop failed: {r}")
                    results["drawdown_stop"] = r
                if (
                    args.get("knockout_price_ticks") is not None
                    or args.get("knockout_price_usd") is not None
                ):
                    if args.get("knockout_symbol"):
                        ko_mkt = self.adapter.resolve_market(str(args["knockout_symbol"]))
                    elif args.get("knockout_market_id") is not None:
                        ko_mkt = self.adapter.resolve_market(int(args["knockout_market_id"]))
                    else:
                        raise ValueError("knockout requires knockout_symbol or knockout_market_id")
                    ko_ticks = (
                        int(args["knockout_price_ticks"])
                        if args.get("knockout_price_ticks") is not None
                        else usd_to_price_ticks(args["knockout_price_usd"], allow_zero=True)
                    )
                    r = self.adapter.http.set_knockout(aid, int(ko_mkt["market_id"]), ko_ticks)
                    if not r.get("ok"):
                        raise RuntimeError(f"POST /knockout failed: {r}")
                    results["knockout"] = r
                if any(
                    args.get(k) is not None
                    for k in ("mmp_window_wal_seqs", "mmp_max_fill_lots", "mmp_max_delta_lots", "mmp_cooldown_wal_seqs")
                ):
                    r = self.adapter.http.configure_mmp(
                        account_id=aid,
                        window_wal_seqs=int(args.get("mmp_window_wal_seqs", 0)),
                        max_fill_lots=int(args.get("mmp_max_fill_lots", 0)),
                        max_delta_lots=int(args.get("mmp_max_delta_lots", 0)),
                        cooldown_wal_seqs=int(args.get("mmp_cooldown_wal_seqs", 0)),
                    )
                    if not r.get("ok"):
                        raise RuntimeError(f"POST /account/mmp failed: {r}")
                    results["mmp"] = r
                if args.get("cancel_on_disconnect") is not None:
                    cod_enable = _strict_bool(args["cancel_on_disconnect"], "cancel_on_disconnect")
                    bin_cli = self.adapter._ensure_binary(account_id=aid)
                    wres = bin_cli.set_cancel_on_disconnect(
                        market_id=int(args.get("cod_market_id", 0)),
                        enable=cod_enable,
                        timeout_ms=int(args.get("cod_timeout_ms", 0)),
                    )
                    if wres.status_code != WireStatusCode.OK:
                        raise RuntimeError(f"Wire SetCancelOnDisconnect rejected ({wres.status_code.name})")
                    results["cancel_on_disconnect"] = {"ok": True, "wal_seq": int(wres.wal_seq)}
                if len(results) == 1:
                    raise ValueError("No guardrail settings specified")
                return self._ok_tool_result(results)

            if name == "arena_manage_prime_subaccount":
                act = str(args["action"]).strip().lower()
                if act in ("link", "unlink"):
                    master = self._effective_account(args.get("master_account_id"))
                    if args.get("sub_account_id") is None:
                        raise ValueError("sub_account_id required for link/unlink")
                    sub_id = int(args["sub_account_id"])
                    self._check_account_allowlist(sub_id)
                    if act == "unlink":
                        g_micro = -2
                    else:
                        if args.get("max_guaranty_usd_micro") is not None:
                            g_micro = int(args["max_guaranty_usd_micro"])
                        elif args.get("max_guaranty_usd") is not None:
                            g_micro = usd_to_micro(args["max_guaranty_usd"], allow_zero=True)
                        else:
                            g_micro = 0
                        if g_micro < 0:
                            raise ValueError(f"max_guaranty_usd_micro must be >= 0, got {g_micro}")
                        if self.max_order_notional_micro > 0:
                            if g_micro == 0:
                                raise PermissionError(
                                    "max_order_notional_exceeded: unlimited max_guaranty_usd_micro=0 is disallowed when --max-order-notional-usd is enabled"
                                )
                            if g_micro > self.max_order_notional_micro:
                                raise PermissionError(
                                    f"max_order_notional_exceeded: prime guaranty ${micro_to_usd_str(g_micro)} "
                                    f"exceeds cap ${micro_to_usd_str(self.max_order_notional_micro)}"
                                )
                        self._preflight_risk_and_builder(master, risk_increasing=True)
                    res = self.adapter.http.link_sub_account(master, sub_id, max_guaranty_usd_micro=g_micro)
                    if not res.get("ok"):
                        raise RuntimeError(f"POST /prime/link_sub failed: {res}")
                    return self._ok_tool_result(res)
                if act == "transfer":
                    from_aid = self._effective_account(args.get("from_account_id"))
                    if args.get("to_account_id") is None:
                        raise ValueError("to_account_id required for transfer")
                    to_aid = int(args["to_account_id"])
                    self._check_account_allowlist(to_aid)
                    asset_id = int(args.get("asset_id", 0))
                    if args.get("amount") is not None:
                        amt_raw = int(args["amount"])
                    elif asset_id == 0 and args.get("amount_usd") is not None:
                        amt_raw = usd_to_micro(args["amount_usd"])
                    elif asset_id > 0 and args.get("amount_base") is not None:
                        amt_raw = base_to_qty_lots(args["amount_base"])
                    else:
                        raise ValueError("Specify amount, amount_usd (asset_id=0), or amount_base (asset_id>0)")
                    self._enforce_transfer_or_withdrawal_guardrails(
                        aid=from_aid, asset_id=asset_id, raw_amount=amt_raw, op_label="prime_internal_transfer"
                    )
                    res = self.adapter.http.prime_internal_transfer(from_aid, to_aid, amt_raw, asset_id=asset_id)
                    if not res.get("ok"):
                        raise RuntimeError(f"POST /prime/transfer failed: {res}")
                    return self._ok_tool_result(res)
                raise ValueError(f"Unknown action: {act!r}")

            if name == "arena_bind_builder":
                aid = self._effective_account(args.get("trader_account_id"))
                b_aid = int(args["builder_account_id"])
                bps = int(args["builder_fee_share_bps"])
                if self.default_builder_account > 0 and (
                    b_aid != self.default_builder_account or bps != self.default_builder_bps
                ):
                    raise PermissionError(
                        "builder_binding_locked: --default-builder-account is enforced by operator policy"
                    )
                res = self.adapter.http.bind_builder_code(aid, b_aid, bps)
                if not res.get("ok"):
                    raise RuntimeError(f"POST /account/builder failed: {res}")
                if b_aid > 0 and bps > 0:
                    self._builder_bound_accounts.add(aid)
                return self._ok_tool_result(res)

            if name == "arena_place_order":
                aid = self._effective_account(args.get("account_id"))
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                side_raw = str(args["side"]).strip().lower()
                is_market = _opt_strict_bool(args, "is_market", False)
                reduce_only = _opt_strict_bool(args, "reduce_only", False)
                primary_peg_flag = _opt_strict_bool(args, "primary_peg", False)
                midpoint_peg_flag = _opt_strict_bool(args, "midpoint_peg", False)
                mark_peg_flag = _opt_strict_bool(args, "mark_peg", False)
                trailing_peg_flag = _opt_strict_bool(args, "trailing_peg", False)
                dark_flag = _opt_strict_bool(args, "dark_midpoint", False)
                is_pegged = any(
                    (primary_peg_flag, midpoint_peg_flag, mark_peg_flag, trailing_peg_flag, dark_flag)
                )
                is_spread = str(m.get("kind", "")).lower() == "spread_book"
                px_ticks = self._resolve_price_ticks(
                    args, m, allow_zero=(is_market or is_pegged or is_spread)
                )
                qty_lots = self._resolve_qty_lots(args)
                margin_spot_flag = _opt_strict_bool(args, "margin_spot", False)
                post_only_slide_flag = _opt_strict_bool(args, "post_only_slide", False)
                oco_linked_flag = _opt_strict_bool(args, "oco_linked", False)
                stp_dc_flag = _opt_strict_bool(args, "stp_decrement_and_cancel", False)
                use_bin_arg = _opt_strict_bool(args, "use_binary_wire", False)
                disp_lots = int(args.get("display_qty_lots", 0))
                jit_mult = int(args.get("jit_elastic_mult", 0))
                peg_off = int(args.get("peg_offset_ticks", 0))
                self._enforce_notional_cap(
                    market=m,
                    side_str=side_raw,
                    price_ticks=px_ticks,
                    qty_lots=qty_lots,
                    reduce_only=reduce_only,
                    is_pegged_or_market=(is_market or is_pegged),
                    jit_elastic_mult=jit_mult,
                    margin_spot=margin_spot_flag,
                    is_visible_iceberg=(disp_lots > 0 and not dark_flag),
                    peg_offset_ticks=peg_off,
                )
                self._preflight_risk_and_builder(aid, risk_increasing=(not reduce_only))

                use_bin = use_bin_arg and self._has_binary_wire()
                params: Dict[str, Any] = {
                    "account_id": aid,
                    "price_ticks": px_ticks,
                    "tif": str(args.get("tif", "ioc" if is_market else "gtc")),
                    "stp": str(args.get("stp", "cancel_resting")),
                    "reduce_only": reduce_only,
                    "margin_spot": margin_spot_flag,
                    "post_only_slide": post_only_slide_flag,
                    "primary_peg": primary_peg_flag,
                    "midpoint_peg": midpoint_peg_flag,
                    "mark_peg": mark_peg_flag,
                    "trailing_peg": trailing_peg_flag,
                    "dark_midpoint": dark_flag,
                    "oco_linked": oco_linked_flag,
                    "stp_decrement_and_cancel": stp_dc_flag,
                    "client_tag": int(args.get("client_tag", 0)),
                    "min_qty_lots": int(args.get("min_qty_lots", 0)),
                    "display_qty_lots": disp_lots,
                    "auto_skew_ticks": int(args.get("auto_skew_ticks", 0)),
                    "auto_flip_ticks": int(args.get("auto_flip_ticks", 0)),
                    "peg_offset_ticks": int(args.get("peg_offset_ticks", 0)),
                    "max_lifetime_wal_seqs": int(args.get("max_lifetime_wal_seqs", 0)),
                    "jit_elastic_mult": jit_mult,
                    "priority_fee_ppm": int(args.get("priority_fee_ppm", 0)),
                    "use_binary_wire": use_bin,
                }
                if "post_only" in args and args["post_only"] is not None:
                    params["post_only"] = _strict_bool(args["post_only"], "post_only")
                res = self.adapter.create_order(
                    mid,
                    "market" if is_market else "limit",
                    side_raw,
                    qty_lots_to_base_str(qty_lots),
                    None,
                    params=params,
                )
                return self._ok_tool_result(res)

            if name == "arena_replace_two_sided_quote":
                aid = self._effective_account(args.get("account_id"))
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                q_peg_mode = int(args.get("quote_peg_mode", 0))
                is_spread = str(m.get("kind", "")).lower() == "spread_book"
                bid_ticks = self._resolve_price_ticks(
                    args, m, usd_key="bid_price_usd", ticks_key="bid_price_ticks", allow_zero=(q_peg_mode > 0 or is_spread)
                )
                ask_ticks = self._resolve_price_ticks(
                    args, m, usd_key="ask_price_usd", ticks_key="ask_price_ticks", allow_zero=(q_peg_mode > 0 or is_spread)
                )
                bid_lots = self._resolve_qty_lots(args, base_key="bid_amount_base", lots_key="bid_qty_lots", allow_zero=True)
                ask_lots = self._resolve_qty_lots(args, base_key="ask_amount_base", lots_key="ask_qty_lots", allow_zero=True)
                q_margin_spot = _opt_strict_bool(args, "margin_spot", False)
                q_post_only_slide = _opt_strict_bool(args, "post_only_slide", False)
                q_oco_linked = _opt_strict_bool(args, "oco_linked", False)
                q_ladder_by_tag = _opt_strict_bool(args, "ladder_by_tag", False)
                q_use_bin_arg = _opt_strict_bool(args, "use_binary_wire", False)
                q_jit_mult = int(args.get("jit_elastic_mult", 0))
                q_peg_off = int(args.get("peg_offset_ticks", 0))
                bid_not = self._enforce_notional_cap(
                    market=m,
                    side_str="bid",
                    price_ticks=bid_ticks,
                    qty_lots=bid_lots,
                    reduce_only=False,
                    is_pegged_or_market=(q_peg_mode > 0),
                    jit_elastic_mult=q_jit_mult,
                    margin_spot=q_margin_spot,
                    is_visible_iceberg=False,
                    peg_offset_ticks=q_peg_off,
                )
                ask_not = self._enforce_notional_cap(
                    market=m,
                    side_str="ask",
                    price_ticks=ask_ticks,
                    qty_lots=ask_lots,
                    reduce_only=False,
                    is_pegged_or_market=(q_peg_mode > 0),
                    jit_elastic_mult=q_jit_mult,
                    margin_spot=q_margin_spot,
                    is_visible_iceberg=False,
                    peg_offset_ticks=q_peg_off,
                )
                if self.max_order_notional_micro > 0 and (bid_not + ask_not) > self.max_order_notional_micro:
                    raise PermissionError(
                        f"max_order_notional_exceeded: combined quote notional "
                        f"${micro_to_usd_str(bid_not + ask_not)} exceeds cap "
                        f"${micro_to_usd_str(self.max_order_notional_micro)}"
                    )
                self._preflight_risk_and_builder(aid, risk_increasing=True)
                use_bin = q_use_bin_arg and self._has_binary_wire()
                tif_s = str(args.get("tif", "gtc")).strip().lower()
                stp_s = str(args.get("stp", "cancel_resting")).strip().lower()
                if use_bin:
                    bin_cli = self.adapter._ensure_binary(account_id=aid)
                    tif_map_q = {
                        "gtc": TimeInForce.GTC,
                        "post_only": TimeInForce.POST_ONLY,
                        "postonly": TimeInForce.POST_ONLY,
                        "ioc": TimeInForce.IOC,
                        "fok": TimeInForce.FOK,
                    }
                    if tif_s not in tif_map_q:
                        raise ValueError(f"Unsupported tif {tif_s!r}")
                    tif_val = tif_map_q[tif_s]
                    stp_map = {
                        "cancel_resting": StpMode.CANCEL_RESTING,
                        "cancel_incoming": StpMode.CANCEL_INCOMING,
                        "cancel_aggressor": StpMode.CANCEL_INCOMING,
                        "cancel_both": StpMode.CANCEL_BOTH,
                        "none": StpMode.NONE,
                    }
                    if stp_s not in stp_map:
                        raise ValueError(f"Unsupported stp {stp_s!r}")
                    wres = bin_cli.quote_replace(
                        market_id=mid,
                        bid_price_ticks=bid_ticks,
                        bid_qty_lots=bid_lots,
                        ask_price_ticks=ask_ticks,
                        ask_qty_lots=ask_lots,
                        tif=tif_val,
                        stp=stp_map[stp_s],
                        post_only_slide=q_post_only_slide,
                        margin_spot=q_margin_spot,
                        auto_skew_ticks=int(args.get("auto_skew_ticks", 0)),
                        oco_linked=q_oco_linked,
                        max_lifetime_wal_seqs=int(args.get("max_lifetime_wal_seqs", 0)),
                        jit_elastic_mult=int(args.get("jit_elastic_mult", 0)),
                        auto_flip_ticks=int(args.get("auto_flip_ticks", 0)),
                        quote_peg_mode=q_peg_mode,
                        peg_offset_ticks=int(args.get("peg_offset_ticks", 0)),
                        client_tag=int(args.get("client_tag", 0)),
                        ladder_by_tag=q_ladder_by_tag,
                        account_id=aid,
                    )
                    if wres.status_code != WireStatusCode.OK:
                        raise RuntimeError(f"Wire quote_replace rejected ({wres.status_code.name})")
                    return self._ok_tool_result(
                        {
                            "ok": True,
                            "status": wres.status_code.name,
                            "order_status": wres.order_status.name,
                            "wal_seq": int(wres.wal_seq),
                            "order_id": int(wres.order_id),
                            "filled_lots": int(wres.filled_lots),
                            "resting_lots": int(wres.resting_lots),
                        }
                    )
                res = self.adapter.http.quote_replace(
                    account_id=aid,
                    market_id=mid,
                    bid_price_ticks=bid_ticks,
                    bid_qty_lots=bid_lots,
                    ask_price_ticks=ask_ticks,
                    ask_qty_lots=ask_lots,
                    tif=tif_s,
                    stp=stp_s,
                    post_only_slide=q_post_only_slide,
                    margin_spot=q_margin_spot,
                    client_tag=int(args.get("client_tag", 0)),
                    auto_skew_ticks=int(args.get("auto_skew_ticks", 0)),
                    oco_linked=q_oco_linked,
                    max_lifetime_wal_seqs=int(args.get("max_lifetime_wal_seqs", 0)),
                    jit_elastic_mult=int(args.get("jit_elastic_mult", 0)),
                    auto_flip_ticks=int(args.get("auto_flip_ticks", 0)),
                    quote_peg_mode=q_peg_mode,
                    peg_offset_ticks=int(args.get("peg_offset_ticks", 0)),
                    ladder_by_tag=q_ladder_by_tag,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /quote rejected: {res}")
                return self._ok_tool_result(res)

            if name == "arena_modify_order":
                aid = self._effective_account(args.get("account_id"))
                keep_prio_flag = _opt_strict_bool(args, "keep_priority", False)
                mod_use_bin_arg = _opt_strict_bool(args, "use_binary_wire", False)
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                oid = int(args["order_id"])
                new_ticks = self._resolve_price_ticks(args, m)
                new_lots = self._resolve_qty_lots(args)
                acct_snap = self.adapter.http.account(aid)
                if not isinstance(acct_snap, dict) or not acct_snap.get("ok"):
                    raise RuntimeError(f"GET /account failed: {acct_snap}")
                old_order = None
                for oo in list((acct_snap or {}).get("open_orders", [])):
                    if int(oo.get("order_id", 0)) == oid and int(oo.get("market_id", 0)) == mid:
                        old_order = oo
                        break
                if old_order is None:
                    raise ValueError(f"open order {oid} on market {mid} not found on account {aid}")
                orig_side_raw = str(old_order.get("side", "")).strip().lower()
                if orig_side_raw not in ("bid", "buy", "ask", "sell"):
                    raise ValueError(f"Invalid side {orig_side_raw!r} on open order {oid}")
                orig_side_wire = "ask" if orig_side_raw in ("ask", "sell") else "bid"
                orig_side_ccxt = "sell" if orig_side_wire == "ask" else "buy"
                is_reduce = bool(old_order.get("reduce_only", False))
                old_jit_mult = int(old_order.get("jit_elastic_mult", 0))
                if "dark_hidden" in old_order and "display_qty_lots" in old_order:
                    old_vis_iceberg = (not bool(old_order.get("dark_hidden", False))) and (
                        int(old_order.get("display_qty_lots", 0)) > 0
                    )
                else:
                    old_vis_iceberg = False
                old_is_pegged = (int(old_order.get("peg_mode", 0)) > 0) or bool(old_order.get("dark_hidden", False))
                self._enforce_notional_cap(
                    market=m,
                    side_str=orig_side_wire,
                    price_ticks=new_ticks,
                    qty_lots=new_lots,
                    reduce_only=is_reduce,
                    is_pegged_or_market=old_is_pegged,
                    jit_elastic_mult=old_jit_mult,
                    margin_spot=False,
                    is_visible_iceberg=old_vis_iceberg,
                    peg_offset_ticks=int(old_order.get("peg_offset_ticks", 0)),
                )
                self._preflight_risk_and_builder(aid, risk_increasing=(not is_reduce))
                res = self.adapter.edit_order(
                    oid,
                    mid,
                    "limit",
                    orig_side_ccxt,
                    qty_lots_to_base_str(new_lots),
                    price_ticks_to_usd_str(new_ticks),
                    params={
                        "account_id": aid,
                        "keep_priority": keep_prio_flag,
                        "use_binary_wire": mod_use_bin_arg and self._has_binary_wire(),
                    },
                )
                return self._ok_tool_result(res)

            if name == "arena_cancel_orders":
                aid = self._effective_account(args.get("account_id"))
                oid = int(args.get("order_id", 0))
                do_all = _opt_strict_bool(args, "cancel_all", False) or oid <= 0
                use_bin = _opt_strict_bool(args, "use_binary_wire", False) and self._has_binary_wire()
                mid = int(self._resolve_market_args(args)["market_id"]) if (args.get("symbol") or args.get("market_id", 0) > 0) else 0
                if do_all:
                    res = self.adapter.cancel_all_orders(
                        mid if mid > 0 else None,
                        params={
                            "account_id": aid,
                            "client_tag_filter": int(args.get("client_tag_filter", 0)),
                            "market_bitmask": int(args.get("market_bitmask", 0)),
                            "side": str(args.get("side", "")),
                            "use_binary_wire": use_bin,
                        },
                    )
                else:
                    if mid <= 0:
                        raise ValueError("market_id or symbol required when cancelling a single order_id")
                    res = self.adapter.cancel_order(
                        oid, mid, params={"account_id": aid, "use_binary_wire": use_bin}
                    )
                return self._ok_tool_result(res)

            if name == "arena_execute_atomic_basket":
                aid = self._effective_account(args.get("account_id"))
                basket_margin_spot = _opt_strict_bool(args, "margin_spot", False)
                raw_legs = list(args["legs"])
                resolved_legs: List[Dict[str, Any]] = []
                any_risk_inc = False
                total_notional_micro = 0
                for lg in raw_legs:
                    m = self._resolve_market_args(lg)
                    is_mkt = _opt_strict_bool(lg, "is_market", False)
                    red_only = _opt_strict_bool(lg, "reduce_only", False)
                    lg_margin_spot = _opt_strict_bool(lg, "margin_spot", False)
                    is_spread = str(m.get("kind", "")).lower() == "spread_book"
                    px_t = self._resolve_price_ticks(lg, m, allow_zero=(is_mkt or is_spread))
                    qty_l = self._resolve_qty_lots(lg)
                    side_raw = str(lg["side"]).strip().lower()
                    side_s = "bid" if side_raw in ("buy", "bid") else "ask"
                    if not red_only:
                        any_risk_inc = True
                    total_notional_micro += self._enforce_notional_cap(
                        market=m,
                        side_str=side_s,
                        price_ticks=px_t,
                        qty_lots=qty_l,
                        reduce_only=red_only,
                        is_pegged_or_market=is_mkt,
                    )
                    resolved_legs.append(
                        {
                            "market_id": int(m["market_id"]),
                            "side": side_s,
                            "price_ticks": px_t,
                            "qty_lots": qty_l,
                            "is_market": is_mkt,
                            "reduce_only": red_only,
                            "margin_spot": lg_margin_spot,
                        }
                    )
                if self.max_order_notional_micro > 0 and total_notional_micro > self.max_order_notional_micro:
                    raise PermissionError(
                        f"max_order_notional_exceeded: atomic basket notional "
                        f"${micro_to_usd_str(total_notional_micro)} exceeds cap "
                        f"${micro_to_usd_str(self.max_order_notional_micro)}"
                    )
                exp_bid_bps = int(args.get("express_surplus_bid_bps", 0))
                if not (0 <= exp_bid_bps <= 5000):
                    raise ValueError(f"express_surplus_bid_bps {exp_bid_bps} out of [0, 5000]")
                self._preflight_risk_and_builder(aid, risk_increasing=any_risk_inc)
                res = self.adapter.http.execute_basket(
                    account_id=aid,
                    legs=resolved_legs,
                    stp=str(args.get("stp", "cancel_resting")),
                    margin_spot=basket_margin_spot,
                    client_tag=int(args.get("client_tag", 0)),
                    express_surplus_bid_bps=exp_bid_bps,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /basket rejected: {res}")
                return self._ok_tool_result(res)

            if name == "arena_portfolio_delta_hedge":
                aid = self._effective_account(args.get("account_id"))
                hedge_margin_spot = _opt_strict_bool(args, "margin_spot", False)
                base_aid = int(args.get("base_asset_id", 0))
                pref_mid = int(args.get("preferred_market_id", 0))
                max_qty_l = int(args.get("max_qty_lots", 0))
                max_slip_bps = int(args.get("max_slippage_bps", 200))
                self._enforce_delta_hedge_notional_cap(
                    aid=aid,
                    acct_snap=None,
                    base_asset_id=base_aid,
                    preferred_market_id=pref_mid,
                    max_qty_lots=max_qty_l,
                    max_slippage_bps=max_slip_bps,
                )
                self._preflight_risk_and_builder(aid, risk_increasing=True)
                res = self.adapter.http.auto_delta_hedge(
                    account_id=aid,
                    base_asset_id=base_aid,
                    preferred_market_id=pref_mid,
                    max_slippage_bps=max_slip_bps,
                    max_qty_lots=max_qty_l,
                    margin_spot=hedge_margin_spot,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /auto_delta_hedge failed: {res}")
                return self._ok_tool_result(res)

            if name == "arena_request_withdrawal":
                if not self.allow_withdrawals:
                    return self._err_tool_result(
                        "withdrawals_disabled: start arena_mcp_server.py with --allow-withdrawals to enable withdrawals"
                    )
                aid = self._effective_account(args.get("account_id"))
                recip = _norm_eth_address(str(args["recipient_eth_address"]))
                if self.allowed_withdrawal_recipients is not None and recip not in self.allowed_withdrawal_recipients:
                    return self._err_tool_result(
                        f"withdrawal_recipient_not_allowed: {recip} is not in --allowed-withdrawal-recipients"
                    )
                asset_id = int(args.get("asset_id", 0))
                if args.get("amount") is not None:
                    raw_amt = int(args["amount"])
                elif asset_id == 0 and args.get("amount_usd") is not None:
                    raw_amt = usd_to_micro(args["amount_usd"])
                elif asset_id > 0 and args.get("amount_base") is not None:
                    raw_amt = base_to_qty_lots(args["amount_base"])
                else:
                    raise ValueError("Specify amount, amount_usd (asset_id=0), or amount_base (asset_id>0)")
                self._enforce_transfer_or_withdrawal_guardrails(
                    aid=aid, asset_id=asset_id, raw_amount=raw_amt, op_label="withdraw"
                )
                res = self.adapter.http.withdraw(
                    account_id=aid,
                    amount=raw_amt,
                    asset_id=asset_id,
                    recipient_eth_address=recip,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /withdraw rejected: {res}")
                return self._ok_tool_result(res)

            if name == "arena_subscribe_express_port":
                aid = self._effective_account(args.get("account_id"))
                ep_use_bin_arg = _opt_strict_bool(args, "use_binary_wire", False)
                dur_epochs = int(args.get("duration_epochs", 1))
                max_fee_micro = int(args.get("max_fee_usd_micro", 0))
                if not (1 <= dur_epochs <= 1_051_200):
                    raise ValueError("duration_epochs out of [1, 1051200]")
                if max_fee_micro < 0:
                    raise ValueError("max_fee_usd_micro must be >= 0")
                eff_max_fee_micro = max_fee_micro
                if self.max_order_notional_micro > 0:
                    if max_fee_micro > self.max_order_notional_micro:
                        raise PermissionError(
                            f"max_order_notional_exceeded: express port max_fee_usd_micro "
                            f"${micro_to_usd_str(max_fee_micro)} exceeds cap "
                            f"${micro_to_usd_str(self.max_order_notional_micro)}"
                        )
                    health_fn = getattr(self.adapter.http, "health", None)
                    if callable(health_fn):
                        h = health_fn()
                        if isinstance(h, dict):
                            fee_per_ep = int(h.get("express_port_fee_per_epoch_usd_micro", 0))
                            est_cost = dur_epochs * fee_per_ep
                            if fee_per_ep > 0 and est_cost > self.max_order_notional_micro:
                                raise PermissionError(
                                    f"max_order_notional_exceeded: express port lease cost "
                                    f"${micro_to_usd_str(est_cost)} exceeds cap "
                                    f"${micro_to_usd_str(self.max_order_notional_micro)}"
                                )
                    eff_max_fee_micro = (
                        self.max_order_notional_micro
                        if max_fee_micro == 0
                        else min(max_fee_micro, self.max_order_notional_micro)
                    )
                self._preflight_risk_and_builder(aid, risk_increasing=True)
                use_bin = ep_use_bin_arg and self._has_binary_wire()
                res = self.adapter.subscribe_express_port(
                    duration_epochs=dur_epochs,
                    max_fee_usd_micro=eff_max_fee_micro,
                    params={"account_id": aid, "use_binary_wire": use_bin},
                )
                return self._ok_tool_result(res)

            if name == "arena_preview_order":
                explicit_aid = args.get("account_id")
                if self._public_unauth_http_mode:
                    aid = 0
                    is_unauth_zero_key = True
                else:
                    is_unauth_zero_key = (
                        explicit_aid is not None and int(explicit_aid) == 0
                    ) or (
                        explicit_aid is None
                        and int(self.adapter.account_id) <= 0
                        and not self._has_authenticated_credentials()
                    )
                    if is_unauth_zero_key:
                        aid = 0
                    else:
                        aid = self._effective_account(explicit_aid)
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                side_raw = str(args["side"]).strip().lower()
                is_market = _opt_strict_bool(args, "is_market", False)
                prev_primary_peg = _opt_strict_bool(args, "primary_peg", False)
                prev_midpoint_peg = _opt_strict_bool(args, "midpoint_peg", False)
                prev_mark_peg = _opt_strict_bool(args, "mark_peg", False)
                prev_trailing_peg = _opt_strict_bool(args, "trailing_peg", False)
                prev_dark_midpoint = _opt_strict_bool(args, "dark_midpoint", False)
                prev_reduce_only = _opt_strict_bool(args, "reduce_only", False)
                prev_margin_spot = _opt_strict_bool(args, "margin_spot", False)
                prev_post_only_slide = _opt_strict_bool(args, "post_only_slide", False)
                prev_oco_linked = _opt_strict_bool(args, "oco_linked", False)
                prev_stp_dc = _opt_strict_bool(args, "stp_decrement_and_cancel", False)
                is_pegged = any(
                    (prev_primary_peg, prev_midpoint_peg, prev_mark_peg, prev_trailing_peg, prev_dark_midpoint)
                )
                is_spread = str(m.get("kind", "")).lower() == "spread_book"
                if is_spread and args.get("differential_usd") is not None:
                    px_ticks = int(m.get("offset_ticks", 1_000_000)) + usd_to_price_ticks(
                        args["differential_usd"], allow_zero=True, allow_negative=True
                    )
                else:
                    px_ticks = self._resolve_price_ticks(
                        args, m, allow_zero=(is_market or is_pegged or is_spread)
                    )
                qty_lots = self._resolve_qty_lots(args)
                params = {
                    "account_id": aid,
                    "price_ticks": px_ticks,
                    "tif": str(args.get("tif", "ioc" if is_market else "gtc")),
                    "stp": str(args.get("stp", "cancel_resting")),
                    "reduce_only": prev_reduce_only,
                    "margin_spot": prev_margin_spot,
                    "post_only_slide": prev_post_only_slide,
                    "primary_peg": prev_primary_peg,
                    "midpoint_peg": prev_midpoint_peg,
                    "mark_peg": prev_mark_peg,
                    "trailing_peg": prev_trailing_peg,
                    "dark_midpoint": prev_dark_midpoint,
                    "oco_linked": prev_oco_linked,
                    "stp_decrement_and_cancel": prev_stp_dc,
                    "client_tag": int(args.get("client_tag", 0)),
                    "min_qty_lots": int(args.get("min_qty_lots", 0)),
                    "display_qty_lots": int(args.get("display_qty_lots", 0)),
                    "auto_skew_ticks": int(args.get("auto_skew_ticks", 0)),
                    "auto_flip_ticks": int(args.get("auto_flip_ticks", 0)),
                    "peg_offset_ticks": int(args.get("peg_offset_ticks", 0)),
                    "max_lifetime_wal_seqs": int(args.get("max_lifetime_wal_seqs", 0)),
                    "jit_elastic_mult": int(args.get("jit_elastic_mult", 0)),
                    "priority_fee_ppm": int(args.get("priority_fee_ppm", 0)),
                }
                if "post_only" in args and args["post_only"] is not None:
                    params["post_only"] = _strict_bool(args["post_only"], "post_only")
                preview_hint = (
                    "POST /order/preview simulates account-bound Eigen-SPAN margin (IMR/MMR/free collateral) "
                    "on backends requiring an authenticated account. Run `uvx feraterra-sdk --testnet` locally and "
                    "call `arena_onboard_and_deposit` (`generate_ephemeral=true`) to spin up an ephemeral "
                    "EIP-191 wallet for full pre-trade margin simulation."
                )
                allow_unauth_hint = is_unauth_zero_key and (
                    self._public_unauth_http_mode or not self._has_authenticated_credentials()
                )
                try:
                    res = self.adapter.preview_order(
                        mid,
                        "market" if is_market else "limit",
                        side_raw,
                        qty_lots_to_base_str(qty_lots),
                        None,
                        params=params,
                    )
                except Exception as prev_exc:
                    exc_lc = str(prev_exc).lower()
                    if allow_unauth_hint and (
                        "missing_auth_headers" in exc_lc
                        or "missing_auth" in exc_lc
                        or "unauthorized" in exc_lc
                        or "invalid_account_id" in exc_lc
                        or "401" in exc_lc
                        or "400" in exc_lc
                    ):
                        inferred_st = 400 if ("400" in exc_lc and "401" not in exc_lc) else 401
                        return self._ok_tool_result(
                            {
                                "ok": False,
                                "preview": True,
                                "would_accept": False,
                                "auth_required": True,
                                "http_status": inferred_st,
                                "error": "missing_auth_headers" if inferred_st == 401 else "invalid_account_id",
                                "symbol": self.adapter._unified_symbol_for_market(m),
                                "market_id": mid,
                                "side": "buy" if side_raw in ("buy", "bid") else "sell",
                                "price_ticks": px_ticks,
                                "qty_lots": qty_lots,
                                "local_mcp_command": "uvx feraterra-sdk --testnet",
                                "hint": preview_hint,
                            }
                        )
                    raise
                info_obj = res.get("info") if isinstance(res.get("info"), dict) else res
                err_code_lc = str(info_obj.get("error") or res.get("error") or "").strip().lower()
                http_st = int(info_obj.get("http_status") or res.get("http_status") or 0)
                if (
                    allow_unauth_hint
                    and not bool(info_obj.get("ok", False))
                    and (
                        http_st in (400, 401)
                        or err_code_lc
                        in (
                            "missing_auth_headers",
                            "missing_auth",
                            "unauthorized",
                            "invalid_account_id",
                            "account_id_required",
                        )
                    )
                ):
                    return self._ok_tool_result(
                        {
                            "ok": False,
                            "preview": True,
                            "would_accept": False,
                            "auth_required": True,
                            "http_status": http_st or 401,
                            "error": str(info_obj.get("error") or res.get("error") or "missing_auth_headers"),
                            "symbol": res.get("symbol") or self.adapter._unified_symbol_for_market(m),
                            "market_id": mid,
                            "side": "buy" if side_raw in ("buy", "bid") else "sell",
                            "price_ticks": px_ticks,
                            "qty_lots": qty_lots,
                            "local_mcp_command": "uvx feraterra-sdk --testnet",
                            "hint": preview_hint,
                        }
                    )
                res["would_accept"] = bool(res.get("wouldAccept", False))
                return self._ok_tool_result(res)

            if name == "arena_flash_arbitrage":
                aid = self._effective_account(args.get("account_id"))
                m = self._resolve_market_args(args)
                mid = int(m["market_id"])
                side_raw = str(args["side"]).strip().lower()
                if side_raw in ("buy", "bid", "mint", "mint_and_sell"):
                    side_str = "bid"
                elif side_raw in ("sell", "ask", "redeem", "buy_and_redeem"):
                    side_str = "ask"
                else:
                    raise ValueError(
                        f"Invalid flash_arbitrage side {side_raw!r}; expected buy|sell|bid|ask|mint|redeem"
                    )
                qty_lots = self._resolve_qty_lots(args)
                is_market = _opt_strict_bool(args, "is_market", True)
                fa_use_bin_arg = _opt_strict_bool(args, "use_binary_wire", False)
                lim_px = (
                    usd_to_price_ticks(args["limit_price_usd"])
                    if args.get("limit_price_usd") is not None
                    else int(args.get("limit_price_ticks", 0))
                )
                min_prof_micro = (
                    usd_to_micro(args["min_profit_usd"], allow_zero=True, allow_negative=True)
                    if args.get("min_profit_usd") is not None
                    else int(args.get("min_profit_micro", 0))
                )
                exp_bid_bps = int(args.get("express_surplus_bid_bps", 0))
                if not (0 <= exp_bid_bps <= 5000):
                    raise ValueError(f"express_surplus_bid_bps {exp_bid_bps} out of [0, 5000]")
                flash_px_hint = max(abs(lim_px), int(m.get("claim_cap_ticks", 0)))
                self._enforce_notional_cap(
                    market=m,
                    side_str=side_str,
                    price_ticks=flash_px_hint,
                    qty_lots=qty_lots,
                    reduce_only=False,
                    is_pegged_or_market=True,
                )
                self._preflight_risk_and_builder(aid, risk_increasing=True)
                stp_s = str(args.get("stp", "cancel_resting")).strip().lower()
                if fa_use_bin_arg and self._has_binary_wire():
                    bin_cli = self.adapter._ensure_binary(account_id=aid)
                    stp_map_fa = {
                        "cancel_resting": StpMode.CANCEL_RESTING,
                        "cancel_incoming": StpMode.CANCEL_INCOMING,
                        "cancel_both": StpMode.CANCEL_BOTH,
                        "none": StpMode.NONE,
                    }
                    wres = bin_cli.flash_arbitrage(
                        market_id=mid,
                        side=OrderSide.BID if side_str == "bid" else OrderSide.ASK,
                        qty_lots=qty_lots,
                        limit_price_ticks=lim_px,
                        min_profit_micro=min_prof_micro,
                        is_market=is_market,
                        stp=stp_map_fa[stp_s],
                        express_surplus_bid_bps=exp_bid_bps,
                        account_id=aid,
                    )
                    if wres.status_code != WireStatusCode.OK:
                        raise RuntimeError(f"Wire flash_arbitrage rejected ({wres.status_code.name})")
                    return self._ok_tool_result(
                        {
                            "ok": True,
                            "status": wres.status_code.name,
                            "wal_seq": int(wres.wal_seq),
                            "filled_lots": int(wres.filled_lots),
                            "avg_price_ticks": int(wres.avg_price_ticks),
                            "net_profit_micro": int(wres.fee_or_position),
                        }
                    )
                res = self.adapter.http.flash_arbitrage(
                    account_id=aid,
                    market_id=mid,
                    side=side_str,
                    qty_lots=qty_lots,
                    limit_price_ticks=lim_px,
                    min_profit_micro=min_prof_micro,
                    is_market=is_market,
                    stp=stp_s,
                    express_surplus_bid_bps=exp_bid_bps,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /flash_arb rejected: {res}")
                return self._ok_tool_result(res)

            if name == "arena_auto_liquidate":
                liq_aid = self._effective_account(args.get("liquidator_account_id"))
                mid = int(args.get("market_id", 0))
                target_aid = int(args.get("target_account_id", 0))
                max_lots = int(args.get("max_lots", 0))
                if max_lots < 0:
                    raise ValueError(f"max_lots must be >= 0, got {max_lots}")
                min_bounty_micro = (
                    usd_to_micro(args["min_bounty_usd"], allow_zero=True)
                    if args.get("min_bounty_usd") is not None
                    else int(args.get("min_bounty_micro", 0))
                )
                if min_bounty_micro < 0:
                    raise ValueError(f"min_bounty_micro must be >= 0, got {min_bounty_micro}")
                flash_offload = _opt_strict_bool(args, "flash_offload_to_book", True)
                hedge_margin_spot_liq = _opt_strict_bool(args, "hedge_margin_spot", False)
                bounty_bid_bps = int(args.get("bounty_rebate_bid_bps", 0))
                if not (0 <= bounty_bid_bps <= 9000):
                    raise ValueError(f"bounty_rebate_bid_bps {bounty_bid_bps} out of [0, 9000]")
                if self.max_order_notional_micro > 0:
                    if mid <= 0 or max_lots <= 0:
                        raise PermissionError(
                            "max_order_notional_exceeded: auto_liquidate requires explicit market_id > 0 and max_lots > 0 when --max-order-notional-usd is enabled"
                        )
                    m = self.adapter.resolve_market(mid)
                    self._enforce_notional_cap(
                        market=m,
                        side_str="bid",
                        price_ticks=0,
                        qty_lots=max_lots,
                        reduce_only=False,
                        is_pegged_or_market=True,
                    )
                self._preflight_risk_and_builder(liq_aid, risk_increasing=True)
                res = self.adapter.http.auto_liquidate(
                    liquidator_account_id=liq_aid,
                    market_id=mid,
                    target_account_id=target_aid,
                    max_lots=max_lots,
                    min_bounty_micro=min_bounty_micro,
                    flash_offload_to_book=flash_offload,
                    stp=str(args.get("stp", "cancel_resting")).strip().lower(),
                    hedge_margin_spot=hedge_margin_spot_liq,
                    bounty_rebate_bid_bps=bounty_bid_bps,
                )
                if not res.get("ok"):
                    raise RuntimeError(f"POST /auto_liquidate rejected: {res}")
                return self._ok_tool_result(res)

            if name == "arena_onboard_and_deposit":
                gen = _opt_strict_bool(args, "generate_ephemeral", False)
                req_faucet = (
                    _strict_bool(args["request_faucet"], "request_faucet")
                    if ("request_faucet" in args and args["request_faucet"] is not None)
                    else _opt_strict_bool(args, "claim_faucet", True)
                )
                drip_gas_flag = _opt_strict_bool(args, "drip_gas", True)
                explicit_deposit_onchain = (
                    _strict_bool(args["deposit_onchain"], "deposit_onchain")
                    if ("deposit_onchain" in args and args["deposit_onchain"] is not None)
                    else None
                )
                wait_credit_flag = _opt_strict_bool(args, "wait_for_credit", True)
                eff_rpc = self._validate_caller_rpc_url(str(args.get("rpc_url") or "").strip())
                out_onb: Dict[str, Any] = {"ok": True}
                if gen or not self.adapter.account_id:
                    login_res = self.call_tool("arena_login_wallet", {"generate_ephemeral": gen})
                    if login_res.get("isError"):
                        return login_res
                    out_onb["login"] = json.loads(login_res["content"][0]["text"])
                if not self._wallet_privkey_hex:
                    raise ValueError(
                        "No wallet private key available; pass generate_ephemeral=true or configure --wallet-privkey"
                    )
                signer = EthWalletSigner(self._wallet_privkey_hex)
                aid = self._effective_account(None)
                out_onb["account_id"] = aid
                out_onb["eth_address"] = signer.address
                asset_sym = str(args.get("asset_symbol") or "USD").strip().upper()
                if req_faucet:
                    faucet_amt = args.get("faucet_amount", "10000")
                    f_res = self.adapter.http.request_testnet_faucet(
                        recipient=signer.address,
                        amount=faucet_amt,
                        asset=asset_sym,
                        drip_gas=drip_gas_flag,
                    )
                    if not f_res.get("ok"):
                        raise RuntimeError(f"POST /faucet rejected: {f_res}")
                    out_onb["faucet"] = f_res
                base_u_lc = str(getattr(self.adapter, "base_url", "") or "").rstrip("/").lower()
                is_testnet = (
                    bool(getattr(self.adapter, "sandbox", False))
                    or base_u_lc == PUBLIC_TESTNET_ARENA_URL.rstrip("/").lower()
                    or "testnet." in base_u_lc
                )
                if explicit_deposit_onchain is not None:
                    do_deposit = explicit_deposit_onchain
                else:
                    do_deposit = bool(req_faucet or is_testnet)
                if do_deposit:
                    dep_amt = args.get("deposit_amount")
                    if dep_amt is None:
                        dep_amt = args.get("faucet_amount", "10000")
                    # Moving the user's own wallet collateral into non-custodial L2 collateral vault margin
                    # is not an order exposure risk; exempt self-deposit from max_order_notional_micro.
                    d_res = self.adapter.http.deposit_onchain_margin(
                        signer=signer,
                        amount=dep_amt,
                        account_id=aid,
                        asset_symbol=asset_sym,
                        rpc_url=eff_rpc,
                        clearinghouse_address=self.clearinghouse,
                        wait_for_credit=wait_credit_flag,
                        poll_timeout_sec=float(args.get("poll_timeout_sec", 30.0)),
                    )
                    if isinstance(d_res, dict) and d_res.get("ok") is False:
                        raise RuntimeError(f"deposit_onchain_margin rejected: {d_res}")
                    out_onb["deposit"] = d_res
                return self._ok_tool_result(out_onb)

            raise KeyError(f"Unhandled tool: {name!r}")
        except Exception as exc:
            return self._err_tool_result(self._scrub_secret_text(str(exc)))

    def handle_jsonrpc_message(self, msg: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        has_id = "id" in msg
        req_id = msg.get("id")
        if msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            if not has_id:
                return None
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}
        method = msg["method"]
        params = msg.get("params")
        if params is not None and not isinstance(params, dict):
            if not has_id:
                return None
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params"}}
        p = params or {}

        if not has_id:
            if method == "notifications/initialized":
                self._initialized = True
            return None

        if method == "initialize":
            client_ver = str(p.get("protocolVersion") or MCP_PROTOCOL_VERSION)
            negotiated_ver = (
                client_ver if client_ver in SUPPORTED_MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_ver,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}

        if method == "tools/call":
            tname = p.get("name")
            targs = p.get("arguments")
            if not isinstance(tname, str) or not tname:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing tool name"}}
            if targs is not None and not isinstance(targs, dict):
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Tool arguments must be object"}}
            try:
                res = self.call_tool(tname, targs)
            except KeyError:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown tool: {tname}"}}
            return {"jsonrpc": "2.0", "id": req_id, "result": res}

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": self.list_resources()}}

        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": self.list_resource_templates()}}

        if method == "resources/read":
            uri = p.get("uri")
            if not isinstance(uri, str) or not uri:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing resource uri"}}
            try:
                res = self.read_resource(uri)
            except ValueError as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": self._scrub_secret_text(str(exc))}}
            except Exception as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": self._scrub_secret_text(str(exc))}}
            return {"jsonrpc": "2.0", "id": req_id, "result": res}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": self.list_prompts()}}

        if method == "prompts/get":
            pname = p.get("name")
            pargs = p.get("arguments")
            if not isinstance(pname, str) or not pname:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing prompt name"}}
            if pargs is not None and not isinstance(pargs, dict):
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Prompt arguments must be object"}}
            try:
                res = self.get_prompt(pname, pargs)
            except (KeyError, ValueError) as exc:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": self._scrub_secret_text(str(exc))}}
            return {"jsonrpc": "2.0", "id": req_id, "result": res}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    def _message_needs_dispatch_lock(self, msg: Any) -> bool:
        if self.read_only:
            return False
        if not isinstance(msg, dict):
            return False
        method = msg.get("method")
        if not isinstance(method, str):
            return False
        if "id" not in msg:
            return False
        if method in _LOCK_FREE_METHODS:
            return False
        return True

    def dispatch_raw_payload(self, raw_bytes: bytes) -> Any:
        try:
            decoded = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if isinstance(decoded, list):
            if not decoded:
                return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
            if len(decoded) > 64:
                return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Batch exceeds 64 requests"}}
            needs_lock = any(self._message_needs_dispatch_lock(item) for item in decoded)
            if needs_lock:
                with self._dispatch_lock:
                    replies = [rep for item in decoded if (rep := self.handle_jsonrpc_message(item)) is not None]
            else:
                replies = [rep for item in decoded if (rep := self.handle_jsonrpc_message(item)) is not None]
            return replies if replies else None
        if self._message_needs_dispatch_lock(decoded):
            with self._dispatch_lock:
                return self.handle_jsonrpc_message(decoded)
        return self.handle_jsonrpc_message(decoded)

    def create_http_server(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        bearer_token: Optional[str] = None,
    ) -> http.server.ThreadingHTTPServer:
        gw_ref = self
        expected_tok = (
            str(self.http_bearer_token or "").strip()
            if bearer_token is None
            else str(bearer_token).strip()
        )
        self.http_bearer_token = expected_tok
        listen_is_loopback = _is_loopback_bind_host(host)
        inflight_sem = threading.BoundedSemaphore(HTTP_MAX_INFLIGHT_REQUESTS)
        server_card_routes = (
            "/mcp/server-card",
            "/.well-known/mcp/server-card.json",
            "/.well-known/mcp.json",
        )
        health_routes = ("/mcp/health", "/health")

        class _McpHttpServer(http.server.ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            request_queue_size = 64

        class _McpHttpHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 15.0
            server_ref = gw_ref

            def log_message(self, fmt: str, *args: Any) -> None:
                _ = (fmt, args)

            def _effective_bearer_token(self) -> str:
                return expected_tok if bearer_token is not None else str(self.server_ref.http_bearer_token or "").strip()

            def _check_bearer(self) -> bool:
                tok = self._effective_bearer_token()
                if not tok:
                    return True
                auth_hdr = str(self.headers.get("Authorization", "")).strip()
                if not auth_hdr.lower().startswith("bearer "):
                    return False
                got = auth_hdr[7:].strip()
                return hmac.compare_digest(got.encode("utf-8"), tok.encode("utf-8"))

            def _is_trusted_local_host(self) -> bool:
                host_vals = self.headers.get_all("Host")
                if not host_vals or len(host_vals) != 1:
                    return False
                raw_host = str(host_vals[0]).strip()
                if not raw_host or "," in raw_host or any(c.isspace() or ord(c) < 32 for c in raw_host):
                    return False
                try:
                    parsed = urllib.parse.urlsplit(f"http://{raw_host}")
                    _ = parsed.port
                except ValueError:
                    return False
                if (
                    parsed.username is not None
                    or parsed.password is not None
                    or parsed.path != ""
                    or parsed.query != ""
                    or parsed.fragment != ""
                ):
                    return False
                host_lc = (parsed.hostname or "").strip().lower()
                return host_lc in ("127.0.0.1", "localhost", "::1")

            def _is_trusted_local_origin(self) -> bool:
                origin_vals = self.headers.get_all("Origin")
                if not origin_vals:
                    return True
                if len(origin_vals) != 1:
                    return False
                raw_val = str(origin_vals[0])
                if "," in raw_val or any(ord(c) < 32 for c in raw_val):
                    return False
                raw_origin = raw_val.strip()
                if not raw_origin:
                    return True
                if raw_origin.lower() == "null":
                    return False
                try:
                    parsed = urllib.parse.urlsplit(raw_origin)
                    _ = parsed.port
                except ValueError:
                    return False
                if parsed.scheme.lower() not in ("http", "https"):
                    return False
                if parsed.username or parsed.password or parsed.query or parsed.fragment:
                    return False
                if parsed.path not in ("", "/"):
                    return False
                host_lc = (parsed.hostname or "").strip().lower()
                return host_lc in ("127.0.0.1", "localhost", "::1")

            def _enforce_local_http_guards(self, *, head_only: bool = False) -> bool:
                if self.server_ref.public_http_mode:
                    return True
                if listen_is_loopback and not self._is_trusted_local_host():
                    self._send_json_bytes(
                        403,
                        b'{"ok":false,"error":"Untrusted Host header on local MCP server"}',
                        head_only=head_only,
                    )
                    return False
                if not self._is_trusted_local_origin():
                    self._send_json_bytes(
                        403,
                        b'{"ok":false,"error":"Untrusted Origin header on local MCP server"}',
                        head_only=head_only,
                    )
                    return False
                return True

            def _drain_unconsumed_body(self) -> None:
                if getattr(self, "_body_consumed", False):
                    return
                self._body_consumed = True
                if self.headers is None or self.headers.get("Transfer-Encoding") is not None:
                    return
                cl_all = self.headers.get_all("Content-Length") or []
                if len(cl_all) != 1 or "," in str(cl_all[0]):
                    return
                try:
                    clen = int(cl_all[0])
                except ValueError:
                    return
                if clen <= 0 or clen > (MAX_HTTP_MESSAGE_BYTES * 4):
                    return
                prev_timeout = self.connection.gettimeout()
                try:
                    self.connection.settimeout(0.5)
                    rem = clen
                    while rem > 0:
                        chunk = self.rfile.read(min(rem, 16_384))
                        if not chunk:
                            break
                        rem -= len(chunk)
                except OSError:
                    return
                finally:
                    try:
                        self.connection.settimeout(prev_timeout)
                    except OSError as restore_err:
                        _ = restore_err

            def _send_cors_headers(self) -> None:
                if self.server_ref.public_http_mode:
                    self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID",
                )
                self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS, DELETE")
                self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version")
                self.send_header("Access-Control-Max-Age", "86400")

            def _send_json_bytes(
                self,
                status_code: int,
                body_bytes: bytes,
                extra_headers: Optional[Dict[str, str]] = None,
                content_type: str = "application/json; charset=utf-8",
                *,
                head_only: bool = False,
            ) -> None:
                self._drain_unconsumed_body()
                self.send_response(status_code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body_bytes)))
                self.send_header("Cache-Control", "no-store")
                self._send_cors_headers()
                self.send_header("Connection", "close")
                if extra_headers:
                    for hk, hv in extra_headers.items():
                        self.send_header(hk, hv)
                self.end_headers()
                if body_bytes and not head_only and getattr(self, "command", "") != "HEAD":
                    self.wfile.write(body_bytes)
                try:
                    self.wfile.flush()
                except OSError as flush_err:
                    _ = flush_err
                self.close_connection = True

            def do_OPTIONS(self) -> None:
                if not self._enforce_local_http_guards():
                    return
                self._send_json_bytes(204, b"")

            def do_DELETE(self) -> None:
                if not self._enforce_local_http_guards():
                    return
                path_clean = self.path.split("?", 1)[0]
                allow_hdr = (
                    "GET, HEAD, OPTIONS"
                    if path_clean in (health_routes + server_card_routes)
                    else "POST, OPTIONS"
                )
                self._send_json_bytes(
                    405,
                    b'{"ok":false,"error":"method_not_allowed"}',
                    extra_headers={"Allow": allow_hdr},
                )

            def _handle_get_or_head(self, *, head_only: bool) -> None:
                if not self._enforce_local_http_guards(head_only=head_only):
                    return
                path_clean = self.path.split("?", 1)[0]
                if path_clean in server_card_routes:
                    accept_sc = str(self.headers.get("Accept", "")).lower()
                    sc_ct = (
                        "application/mcp-server-card+json; charset=utf-8"
                        if "application/mcp-server-card+json" in accept_sc and "application/json" not in accept_sc
                        else "application/json; charset=utf-8"
                    )
                    card_bytes = _json_dumps(_build_server_card()).encode("utf-8")
                    self._send_json_bytes(200, card_bytes, content_type=sc_ct, head_only=head_only)
                    return
                if path_clean in health_routes:
                    body = _json_dumps(
                        {
                            "ok": True,
                            "server": SERVER_NAME,
                            "version": SERVER_VERSION,
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "supportedProtocolVersions": list(SUPPORTED_MCP_PROTOCOL_VERSIONS),
                            "transport": "streamable-http",
                            "read_only": gw_ref.read_only,
                            "public_http_mode": gw_ref._public_unauth_http_mode,
                            "tool_count": len(gw_ref.list_tools()),
                        }
                    ).encode("utf-8")
                    self._send_json_bytes(200, body, head_only=head_only)
                    return
                if path_clean in ("/mcp", "/"):
                    accept_hdr = str(self.headers.get("Accept", "")).lower()
                    err_code = (
                        "sse_stream_not_supported_use_post"
                        if "text/event-stream" in accept_hdr
                        else "method_not_allowed_use_post"
                    )
                    self._send_json_bytes(
                        405,
                        _json_dumps({"ok": False, "error": err_code}).encode("utf-8"),
                        extra_headers={"Allow": "POST, OPTIONS"},
                        head_only=head_only,
                    )
                    return
                self._send_json_bytes(404, b'{"ok":false,"error":"not_found"}', head_only=head_only)

            def do_GET(self) -> None:
                self._handle_get_or_head(head_only=False)

            def do_HEAD(self) -> None:
                self._handle_get_or_head(head_only=True)

            def do_POST(self) -> None:
                if not self._enforce_local_http_guards():
                    return
                path_clean = self.path.split("?", 1)[0]
                if path_clean not in ("/mcp", "/"):
                    self._send_json_bytes(404, b'{"ok":false,"error":"not_found"}')
                    return
                if not self._check_bearer():
                    self._send_json_bytes(401, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Unauthorized"}}')
                    return
                if self.headers.get("Transfer-Encoding") is not None:
                    self._send_json_bytes(400, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Transfer-Encoding unsupported"}}')
                    return
                clen_all = self.headers.get_all("Content-Length") or []
                if len(clen_all) > 1 or any("," in str(v) for v in clen_all):
                    self._send_json_bytes(400, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Duplicate Content-Length"}}')
                    return
                clen_str = clen_all[0] if clen_all else "0"
                try:
                    clen = int(clen_str)
                except ValueError:
                    self._send_json_bytes(400, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid Content-Length"}}')
                    return
                if clen < 0 or clen > MAX_HTTP_MESSAGE_BYTES:
                    self._send_json_bytes(413, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Payload Too Large"}}')
                    return
                if not inflight_sem.acquire(blocking=False):
                    self._send_json_bytes(
                        503,
                        b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"mcp_server_busy"},"id":null}',
                        extra_headers={"Retry-After": "1"},
                    )
                    return
                try:
                    self._body_consumed = True
                    raw_payload = self.rfile.read(clen) if clen > 0 else b""
                    reply = gw_ref.dispatch_raw_payload(raw_payload)
                    if reply is None:
                        self._send_json_bytes(202, b"")
                        return
                    out_bytes = _json_dumps(reply).encode("utf-8")
                    self._send_json_bytes(200, out_bytes)
                finally:
                    inflight_sem.release()

        srv = _McpHttpServer((host, int(port)), _McpHttpHandler)
        srv._inflight_semaphore = inflight_sem  # type: ignore[attr-defined]
        return srv

    def serve_http(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        bearer_token: str = "",
    ) -> int:
        srv = self.create_http_server(host=host, port=port, bearer_token=bearer_token)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            srv.server_close()
        return 0

    def serve_stdio(self, stdin_stream: BinaryIO, stdout_stream: BinaryIO) -> int:
        transport = McpStdioTransport(stdin_stream, stdout_stream)
        while True:
            use_cl = False
            try:
                raw_payload, use_cl = transport.read_message()
            except ValueError as exc:
                err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": self._scrub_secret_text(str(exc))}}
                transport.write_message(err_resp, use_cl)
                continue
            if raw_payload is None:
                return 0
            reply = self.dispatch_raw_payload(raw_payload)
            if reply is not None:
                transport.write_message(reply, use_cl)


def resolve_arena_base_url(
    explicit_url: str = "",
    *,
    testnet: bool = False,
    network: str = "",
    env: Optional[Dict[str, str]] = None,
) -> str:
    env_map = os.environ if env is None else env
    raw_url = str(explicit_url or "").strip()
    if raw_url:
        return raw_url.rstrip("/")
    cli_net = str(network or "").strip().lower()
    if bool(testnet) or cli_net in ("testnet", "public-testnet", "base-sepolia", "sepolia", "feraterra"):
        return PUBLIC_TESTNET_ARENA_URL
    if cli_net in ("local", "localhost"):
        return DEFAULT_LOCAL_ARENA_URL
    if cli_net:
        raise ValueError(f"Unknown --network preset: {cli_net!r}")
    for env_k in ("ARENA_URL", "ARENA_BASE_URL"):
        env_v = str(env_map.get(env_k, "")).strip()
        if env_v:
            return env_v.rstrip("/")
    env_net = str(env_map.get("ARENA_NETWORK", "")).strip().lower()
    env_testnet = str(env_map.get("ARENA_TESTNET", "")).strip().lower() in ("1", "true", "yes", "on")
    if env_testnet or env_net in ("testnet", "public-testnet", "base-sepolia", "sepolia", "feraterra"):
        return PUBLIC_TESTNET_ARENA_URL
    if env_net in ("", "local", "localhost"):
        return DEFAULT_LOCAL_ARENA_URL
    raise ValueError(f"Unknown ARENA_NETWORK preset: {env_net!r}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Arena Exchange v4.9 MCP JSON-RPC 2.0 stdio & Streamable HTTP Gateway")
    p.add_argument("--arena-url", "--http-url", "--base-url", "--url", dest="arena_url", default="")
    p.add_argument("--testnet", action="store_true", default=False, help=f"Connect to the live public Base Sepolia testnet ({PUBLIC_TESTNET_ARENA_URL})")
    p.add_argument("--network", default="", help="Optional network preset: local or testnet")
    p.add_argument("--tcp-host", default=os.environ.get("ARENA_TCP_HOST", ""))
    p.add_argument("--tcp-port", type=int, default=int(os.environ.get("ARENA_TCP_PORT", "0") or 0))
    p.add_argument("--http-listen-host", default=os.environ.get("ARENA_MCP_HTTP_HOST", "127.0.0.1"))
    p.add_argument("--http-listen-port", type=int, default=int(os.environ.get("ARENA_MCP_HTTP_PORT", "0") or 0))
    p.add_argument("--http-bearer-token", default=os.environ.get("ARENA_MCP_HTTP_BEARER_TOKEN", ""))
    p.add_argument("--account-id", type=int, default=int(os.environ.get("ARENA_ACCOUNT_ID", "0") or 0))
    p.add_argument("--api-key", default=os.environ.get("ARENA_API_KEY", ""))
    p.add_argument("--api-secret", default=os.environ.get("ARENA_API_SECRET", ""))
    p.add_argument("--creds-file", default=os.environ.get("ARENA_CREDS_FILE", ""))
    p.add_argument("--wallet-privkey", default=os.environ.get("ARENA_WALLET_PRIVKEY", ""))
    p.add_argument("--wallet-privkey-file", default=os.environ.get("ARENA_WALLET_PRIVKEY_FILE", ""))
    p.add_argument("--rpc-url", default=os.environ.get("ARENA_RPC_URL", ""))
    p.add_argument("--clearinghouse", default=os.environ.get("ARENA_CLEARINGHOUSE", ""))
    p.add_argument("--expected-operator-address", default=os.environ.get("ARENA_EXPECTED_OPERATOR_ADDRESS", ""))
    p.add_argument("--read-only", action="store_true", default=_env_truthy("ARENA_MCP_READ_ONLY", False))
    p.add_argument("--public-http-mode", action="store_true", default=_env_truthy("ARENA_MCP_PUBLIC_HTTP_MODE", False))
    p.add_argument("--allowed-accounts", default=os.environ.get("ARENA_MCP_ALLOWED_ACCOUNTS", ""))
    p.add_argument("--max-order-notional-usd", default=os.environ.get("ARENA_MCP_MAX_ORDER_NOTIONAL_USD", "0"))
    p.add_argument("--require-drawdown-stop", action="store_true", default=_env_truthy("ARENA_MCP_REQUIRE_DRAWDOWN_STOP", False))
    p.add_argument("--min-drawdown-stop-usd", default=os.environ.get("ARENA_MCP_MIN_DRAWDOWN_STOP_USD", "0"))
    p.add_argument("--default-builder-account", type=int, default=int(os.environ.get("ARENA_MCP_DEFAULT_BUILDER_ACCOUNT", "0") or 0))
    p.add_argument("--default-builder-bps", type=int, default=int(os.environ.get("ARENA_MCP_DEFAULT_BUILDER_BPS", "0") or 0))
    p.add_argument("--allow-withdrawals", action="store_true", default=_env_truthy("ARENA_MCP_ALLOW_WITHDRAWALS", False))
    p.add_argument("--allowed-withdrawal-recipients", default=os.environ.get("ARENA_MCP_ALLOWED_WITHDRAWAL_RECIPIENTS", ""))
    p.add_argument("--allow-wallet-login", action="store_true", default=_env_truthy("ARENA_MCP_ALLOW_WALLET_LOGIN", False))
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--self-test", action="store_true")
    ns = p.parse_args(argv)
    if ns.public_http_mode:
        ns.read_only = True
    ns.arena_url = resolve_arena_base_url(ns.arena_url, testnet=bool(ns.testnet), network=str(ns.network))
    return ns


def _run_mcp_self_test() -> None:
    # 1. Fixed-point Decimal conversions (exact without rounding)
    assert usd_to_price_ticks("70000.25") == 7_000_025
    assert price_ticks_to_usd_str(7_000_025) == "70000.25"
    assert price_ticks_to_usd_str(10_000_000) == "100000"
    assert base_to_qty_lots("1.2500") == 12_500
    assert qty_lots_to_base_str(12_500) == "1.25"
    assert usd_to_micro("25000.123456") == 25_000_123_456
    assert micro_to_usd_str(25_000_123_456) == "25000.123456"
    for bad_fn, bad_val in ((usd_to_price_ticks, "100.005"), (base_to_qty_lots, "0.00001"), (usd_to_micro, "1.0000001")):
        try:
            bad_fn(bad_val)
            raise AssertionError(f"Expected ValueError for {bad_val}")
        except ValueError as err:
            assert "exact multiple" in str(err)

    # 2. Dual JSONL + Content-Length stdio framing + batch notifications + parse/method errors
    gw = ArenaMcpGateway(
        account_id=2,
        read_only=False,
        allowed_accounts=frozenset({2, 3}),
        max_order_notional_micro=usd_to_micro("25000"),
        require_drawdown_stop=True,
        default_builder_account=9,
        default_builder_bps=1000,
        allow_withdrawals=False,
    )
    gw.adapter.markets_by_symbol = {
        "BTC-USD-PERP": {
            "id": "1",
            "numericId": 1,
            "symbol": "BTC/USD:USD",
            "nativeSymbol": "BTC-USD-PERP",
            "kind": "linear_perpetual",
            "info": {"market_id": 1, "symbol": "BTC-USD-PERP", "kind": "linear_perpetual", "base_asset_id": 1},
        },
        "ETH-USD-PERP": {
            "id": "2",
            "numericId": 2,
            "symbol": "ETH/USD:USD",
            "nativeSymbol": "ETH-USD-PERP",
            "kind": "linear_perpetual",
            "info": {"market_id": 2, "symbol": "ETH-USD-PERP", "kind": "linear_perpetual", "base_asset_id": 2},
        },
        "BTC-ETH-SPRD": {
            "id": "17",
            "numericId": 17,
            "symbol": "BTC-ETH-SPRD",
            "nativeSymbol": "BTC-ETH-SPRD",
            "kind": "spread_book",
            "info": {"market_id": 17, "symbol": "BTC-ETH-SPRD", "kind": "spread_book", "base_asset_id": 1},
        },
        "BTC-BASIS-SPRD": {
            "id": "18",
            "numericId": 18,
            "symbol": "BTC-BASIS-SPRD",
            "nativeSymbol": "BTC-BASIS-SPRD",
            "kind": "spread_book",
            "info": {
                "market_id": 18,
                "symbol": "BTC-BASIS-SPRD",
                "kind": "spread_book",
                "base_asset_id": 1,
                "ref_market_1": 1,
                "ref_market_2": 2,
                "ref_markets": [1, 2, 0],
            },
        },
    }
    gw.adapter.markets_by_id = {
        1: gw.adapter.markets_by_symbol["BTC-USD-PERP"],
        2: gw.adapter.markets_by_symbol["ETH-USD-PERP"],
        17: gw.adapter.markets_by_symbol["BTC-ETH-SPRD"],
        18: gw.adapter.markets_by_symbol["BTC-BASIS-SPRD"],
    }
    gw.adapter.unified_to_native = {
        "BTC-USD-PERP": "BTC-USD-PERP",
        "BTC/USD:USD": "BTC-USD-PERP",
        "1": "BTC-USD-PERP",
        "ETH-USD-PERP": "ETH-USD-PERP",
        "ETH/USD:USD": "ETH-USD-PERP",
        "2": "ETH-USD-PERP",
        "BTC-ETH-SPRD": "BTC-ETH-SPRD",
        "17": "BTC-ETH-SPRD",
        "BTC-BASIS-SPRD": "BTC-BASIS-SPRD",
        "18": "BTC-BASIS-SPRD",
    }

    class _StubHttp:
        def __init__(self) -> None:
            self.api_key = ""
            self.api_secret = ""
            self.bound: List[tuple[int, int, int]] = []
            self.dd_micro = 0
            self.orders: List[Dict[str, Any]] = []
            self.open_orders: List[Dict[str, Any]] = []
            self.perp_positions: List[Dict[str, Any]] = []
            self.base_balances: List[Dict[str, Any]] = []
            self.quotes: List[Dict[str, Any]] = []
            self.edits: List[Dict[str, Any]] = []
            self.baskets: List[Dict[str, Any]] = []
            self.hedges: List[Dict[str, Any]] = []

        def account(self, aid: int) -> Dict[str, Any]:
            return {
                "ok": True,
                "account_id": aid,
                "drawdown_stop_equity_micro": self.dd_micro,
                "builder_account_id": 0,
                "open_orders": list(self.open_orders),
                "perp_positions": list(self.perp_positions),
                "base_balances": list(self.base_balances),
            }

        def set_drawdown_stop(self, aid: int, drawdown_stop_usd_micro: int) -> Dict[str, Any]:
            _ = aid
            self.dd_micro = int(drawdown_stop_usd_micro)
            return {"ok": True, "drawdown_stop_equity_micro": self.dd_micro}

        def bind_builder_code(self, trader_aid: int, builder_aid: int, bps: int) -> Dict[str, Any]:
            self.bound.append((trader_aid, builder_aid, bps))
            return {"ok": True}

        def health(self) -> Dict[str, Any]:
            return {"ok": True, "express_port_fee_per_epoch_usd_micro": 250_000}

        def get_leaderboard(self, limit: int = 25, sort: str = "equity") -> Dict[str, Any]:
            return {
                "ok": True,
                "wal_seq": 100,
                "sort": sort,
                "limit": int(limit),
                "total_ranked_accounts": 1,
                "entries": [
                    {
                        "rank": 1,
                        "account_id": 2,
                        "wallet_masked": "0x1234...abcd",
                        "total_equity_micro": 12_500_000_000,
                        "total_equity_usd": "12500.00",
                        "net_pnl_micro": 2_500_000_000,
                        "net_pnl_usd": "2500.00",
                    }
                ],
            }

        def book(self, mid: int, depth: int = 20) -> Dict[str, Any]:
            _ = depth
            if int(mid) == 17:
                return {"ok": True, "market_id": 17, "mark_price_ticks": 0, "best_ask_ticks": 0, "best_bid_ticks": 0}
            if int(mid) == 18:
                return {"ok": True, "market_id": 18, "mark_price_ticks": 1_000_000, "best_ask_ticks": 1_000_050, "best_bid_ticks": 999_950}
            if int(mid) == 2:
                return {"ok": True, "market_id": 2, "mark_price_ticks": 300_000, "best_ask_ticks": 300_050, "best_bid_ticks": 299_950}
            return {"ok": True, "market_id": mid, "mark_price_ticks": 6_000_000, "best_ask_ticks": 6_000_100, "best_bid_ticks": 5_999_900}

        def ticker(self, mid: int) -> Dict[str, Any]:
            if int(mid) == 17:
                return {"ok": True, "ticker": {"mark_price_ticks": 0, "best_ask_ticks": 0, "best_bid_ticks": 0, "last_trade_price_ticks": 0}}
            if int(mid) == 18:
                return {"ok": True, "ticker": {"mark_price_ticks": 1_000_000, "best_ask_ticks": 1_000_050, "best_bid_ticks": 999_950}}
            if int(mid) == 2:
                return {"ok": True, "ticker": {"mark_price_ticks": 300_000, "best_ask_ticks": 300_050, "best_bid_ticks": 299_950}}
            return {"ok": True, "ticker": {"mark_price_ticks": 6_000_000, "best_ask_ticks": 6_000_100, "best_bid_ticks": 5_999_900}}

        def place_order(self, **kwargs: Any) -> Dict[str, Any]:
            self.orders.append(kwargs)
            return {"ok": True, "order_id": 77, "order_status": "resting", "filled_lots": 0, "resting_lots": kwargs["qty_lots"], "wal_seq": 101}

        def preview_order(self, **kwargs: Any) -> Dict[str, Any]:
            return {
                "ok": True,
                "preview": True,
                "would_accept": True,
                "status": "Ok",
                "wal_seq": 100,
                "effective_price_ticks": kwargs["price_ticks"],
                "estimated_filled_lots": kwargs["qty_lots"],
                "estimated_resting_lots": 0,
                "estimated_avg_price_ticks": kwargs["price_ticks"],
                "estimated_net_fee_micro": 0,
                "pre_imr_micro": 0,
                "post_imr_micro": 250_000_000,
                "post_free_margin_micro": 9_750_000_000,
            }

        def flash_arbitrage(self, **kwargs: Any) -> Dict[str, Any]:
            return {"ok": True, "status": "Ok", "wal_seq": 108, "filled_lots": kwargs["qty_lots"], "net_profit_micro": 50_000}

        def auto_liquidate(self, **kwargs: Any) -> Dict[str, Any]:
            _ = kwargs
            return {"ok": True, "status": "Ok", "wal_seq": 109, "liquidated_accounts": 1, "bounty_earned_micro": 125_000}

        def login_with_wallet(self, signer: EthWalletSigner) -> Dict[str, Any]:
            self.api_key = "ephem_k"
            self.api_secret = "ephem_s"
            return {"ok": True, "account_id": 3, "eth_address": signer.address, "role": "trader", "wire_key_lo64": 11, "wire_key_hi64": 22}

        def request_testnet_faucet(self, recipient: str, amount: Any = "10000", asset: str = "USD", drip_gas: bool = False) -> Dict[str, Any]:
            return {"ok": True, "recipient": recipient, "amount": str(amount), "asset": asset, "drip_gas": bool(drip_gas), "tx_hash": "0x" + ("33" * 32)}

        def deposit_onchain_margin(
            self,
            signer: EthWalletSigner,
            amount: Any,
            *,
            account_id: int = 0,
            asset_symbol: str = "USD",
            rpc_url: str = "",
            clearinghouse_address: str = "",
            wait_for_credit: bool = True,
            poll_timeout_sec: float = 30.0,
        ) -> Dict[str, Any]:
            _ = (rpc_url, clearinghouse_address, poll_timeout_sec)
            return {
                "ok": True,
                "account_id": int(account_id),
                "eth_address": signer.address,
                "amount": str(amount),
                "asset_symbol": asset_symbol,
                "credited": bool(wait_for_credit),
                "deposit_tx_hash": "0x" + ("44" * 32),
            }

        def quote_replace(self, **kwargs: Any) -> Dict[str, Any]:
            self.quotes.append(kwargs)
            return {"ok": True, "order_id": 88, "wal_seq": 104}

        def modify_order(self, **kwargs: Any) -> Dict[str, Any]:
            self.edits.append(kwargs)
            return {"ok": True, "order_id": kwargs["order_id"], "resting_lots": kwargs["qty_lots"], "wal_seq": 105}

        def execute_basket(self, **kwargs: Any) -> Dict[str, Any]:
            self.baskets.append(kwargs)
            return {"ok": True, "wal_seq": 106}

        def auto_delta_hedge(self, **kwargs: Any) -> Dict[str, Any]:
            self.hedges.append(kwargs)
            return {"ok": True, "hedged_lots": 100, "wal_seq": 107}

        def cancel_all(self, **kwargs: Any) -> Dict[str, Any]:
            return {"ok": True, "canceled_orders": 1, "wal_seq": 102}

        def subscribe_express_port(
            self, account_id: int, duration_epochs: int = 1, max_fee_usd_micro: int = 0
        ) -> Dict[str, Any]:
            fee = int(duration_epochs) * 250_000
            if max_fee_usd_micro > 0 and fee > max_fee_usd_micro:
                return {"ok": False, "status": "RejectInsufficient"}
            return {
                "ok": True,
                "status": "Ok",
                "wal_seq": 103,
                "account_id": account_id,
                "epochs_purchased": int(duration_epochs),
                "lease_epochs_remaining": int(duration_epochs),
                "fee_paid_usd_micro": fee,
                "fee_per_epoch_usd_micro": 250_000,
                "free_usd_after_micro": 10_000_000 - fee,
            }

        def close(self) -> None:
            return None

    stub = _StubHttp()
    gw.adapter.http.close()
    gw.adapter.http = stub  # type: ignore[assignment]

    try:
        # Check framing loop on real BytesIO streams
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}).encode("utf-8")
        notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode("utf-8")
        cl_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode("utf-8")
        cl_frame = f"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {len(cl_req)}\r\n\r\n".encode("ascii") + cl_req
        in_stream = io.BytesIO(init_req + b"\n" + notif + b"\n" + cl_frame)
        out_stream = io.BytesIO()
        assert gw.serve_stdio(in_stream, out_stream) == 0
        raw_out = out_stream.getvalue()
        nl_idx = raw_out.index(b"\n")
        resp1 = json.loads(raw_out[:nl_idx].decode("utf-8"))
        assert resp1["result"]["serverInfo"]["name"] == SERVER_NAME
        rest_out = raw_out[nl_idx + 1 :]
        assert rest_out.startswith(b"Content-Length: ")
        hdr_end = rest_out.index(b"\r\n\r\n")
        cl_len = int(rest_out[:hdr_end].decode("ascii").split(":", 1)[1].strip())
        resp2 = json.loads(rest_out[hdr_end + 4 : hdr_end + 4 + cl_len].decode("utf-8"))
        assert len(resp2["result"]["tools"]) == 24
        assert len(READ_ONLY_TOOLS) == 9

        parsed_alias = parse_args(["--http-url", "http://127.0.0.1:18080", "--http-listen-port", "8765"])
        assert parsed_alias.arena_url == "http://127.0.0.1:18080" and parsed_alias.http_listen_port == 8765
        assert resolve_arena_base_url("", testnet=False, network="", env={}) == "http://127.0.0.1:8080"
        assert resolve_arena_base_url("", testnet=True, network="", env={"ARENA_URL": "http://127.0.0.1:9999"}) == "https://testnet.feraterra.app"
        assert resolve_arena_base_url("", testnet=False, network="", env={"ARENA_NETWORK": "testnet"}) == "https://testnet.feraterra.app"
        assert parse_args(["--testnet"]).arena_url == "https://testnet.feraterra.app"

        # Verify real ArenaHttpClient.get_leaderboard signature compatibility on restricted gateway
        real_lb_gw = ArenaMcpGateway(allowed_accounts=frozenset({2}), read_only=True)
        try:
            real_lb_gw.adapter.http._get = lambda path, params=None: {  # type: ignore[method-assign]
                "ok": True,
                "path": path,
                "sort": (params or {}).get("sort"),
                "limit": (params or {}).get("limit"),
                "entries": [{"rank": 1, "account_id": 7, "wallet_masked": "0xabcd...1234"}],
            }
            real_lb_res = real_lb_gw.call_tool("arena_get_leaderboard", {"limit": 10, "sort": "streak"})
            assert not real_lb_res["isError"], real_lb_res
            real_lb_obj = json.loads(real_lb_res["content"][0]["text"])
            assert real_lb_obj["path"] == "/leaderboard" and real_lb_obj["sort"] == "streak" and real_lb_obj["limit"] == 10
        finally:
            real_lb_gw.close()

        lb_ok = gw.call_tool("arena_get_leaderboard", {"limit": 5, "sort": "pnl"})
        assert not lb_ok["isError"], lb_ok
        lb_payload = json.loads(lb_ok["content"][0]["text"])
        assert lb_payload["ok"] is True and lb_payload["sort"] == "pnl" and lb_payload["entries"][0]["rank"] == 1

        # Check allowlist, drawdown gate, auto-builder, notional cap, reduce_only exemption, withdrawal block
        unauth = gw.call_tool("arena_get_account_portfolio", {"account_id": 99})
        assert unauth["isError"] and "account_not_in_allowed_accounts" in unauth["content"][0]["text"]

        no_dd = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"})
        assert no_dd["isError"] and "drawdown_stop_required_before_trading" in no_dd["content"][0]["text"]

        ep_no_dd = gw.call_tool("arena_subscribe_express_port", {"duration_epochs": 1})
        assert ep_no_dd["isError"] and "drawdown_stop_required_before_trading" in ep_no_dd["content"][0]["text"]

        stub.dd_micro = usd_to_micro("1000")
        over_cap = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "60000", "amount_base": "1"})
        assert over_cap["isError"] and "max_order_notional_exceeded" in over_cap["content"][0]["text"]

        over_mkt = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "buy", "is_market": True, "amount_base": "1"})
        assert over_mkt["isError"] and "max_order_notional_exceeded" in over_mkt["content"][0]["text"]

        ok_ord = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1", "priority_fee_ppm": 2500})
        assert not ok_ord["isError"], ok_ord
        assert stub.orders[-1]["priority_fee_ppm"] == 2500
        assert stub.bound == [(2, 9, 1000)]

        bad_prio = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1", "priority_fee_ppm": 50001})
        assert bad_prio["isError"]

        bad_bid_hi = gw.call_tool("arena_execute_atomic_basket", {"legs": [{"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.01"}, {"symbol": "BTC/USD", "side": "sell", "price_usd": "50100", "amount_base": "0.01"}], "express_surplus_bid_bps": 5001})
        assert bad_bid_hi["isError"] and "express_surplus_bid_bps" in bad_bid_hi["content"][0]["text"]
        bad_bid_lo = gw.call_tool("arena_execute_atomic_basket", {"legs": [{"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.01"}, {"symbol": "BTC/USD", "side": "sell", "price_usd": "50100", "amount_base": "0.01"}], "express_surplus_bid_bps": -1})
        assert bad_bid_lo["isError"] and "express_surplus_bid_bps" in bad_bid_lo["content"][0]["text"]

        ro_ok = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "sell", "price_usd": "60000", "amount_base": "1", "reduce_only": True})
        assert not ro_ok["isError"], ro_ok

        cancel_ok = gw.call_tool("arena_cancel_orders", {"cancel_all": True})
        assert not cancel_ok["isError"], cancel_ok

        w_blocked = gw.call_tool("arena_request_withdrawal", {"amount_usd": "10", "recipient_eth_address": "0x" + ("11" * 20)})
        assert w_blocked["isError"] and "withdrawals_disabled" in w_blocked["content"][0]["text"]

        ep_ok = gw.call_tool("arena_subscribe_express_port", {"duration_epochs": 4})
        assert not ep_ok["isError"], ep_ok
        ep_payload = json.loads(ep_ok["content"][0]["text"])
        assert ep_payload["epochs_purchased"] == 4 and ep_payload["fee_paid_usd_micro"] == 1_000_000

        ep_over_cap = gw.call_tool("arena_subscribe_express_port", {"duration_epochs": 120_000})
        assert ep_over_cap["isError"] and "max_order_notional_exceeded" in ep_over_cap["content"][0]["text"]

        ep_bad = gw.call_tool("arena_subscribe_express_port", {"duration_epochs": 0})
        assert ep_bad["isError"] and "duration_epochs" in ep_bad["content"][0]["text"]

        # Read-only gateway check
        ro_gw = ArenaMcpGateway(read_only=True)
        assert {t["name"] for t in ro_gw.list_tools()} == READ_ONLY_TOOLS
        ro_mut = ro_gw.call_tool("arena_place_order", {"market_id": 1, "side": "buy", "price_ticks": 100, "qty_lots": 1})
        assert ro_mut["isError"] and "read_only_mode_enabled" in ro_mut["content"][0]["text"]
        ro_gw.close()

        # Withdrawal allowlist check
        gw.allow_withdrawals = True
        gw.allowed_withdrawal_recipients = frozenset({"0x" + ("aa" * 20)})
        bad_recip = gw.call_tool("arena_request_withdrawal", {"amount_usd": "10", "recipient_eth_address": "0x" + ("bb" * 20)})
        assert bad_recip["isError"] and "withdrawal_recipient_not_allowed" in bad_recip["content"][0]["text"]

        # Secret scrubbing check (dict + error text redaction)
        scrubbed = _scrub_secrets({"api_secret": "s3cr3t", "wire_key_lo64": 123, "nested": {"wallet_privkey": "0x99", "ok": True}})
        assert scrubbed["api_secret"] == "[REDACTED]" and scrubbed["wire_key_lo64"] == "[REDACTED]"
        assert scrubbed["nested"]["wallet_privkey"] == "[REDACTED]" and scrubbed["nested"]["ok"] is True

        # Batch 3.1 MCP risk/cap/framing/redaction hardening checks
        stub.dd_micro = 0
        hedge_no_dd = gw.call_tool("arena_portfolio_delta_hedge", {"max_qty_lots": 100})
        assert hedge_no_dd["isError"] and "drawdown_stop_required_before_trading" in hedge_no_dd["content"][0]["text"]

        stub.dd_micro = usd_to_micro("1000")
        sprd_no_ref = gw.call_tool("arena_place_order", {"symbol": "BTC-ETH-SPRD", "side": "buy", "amount_base": "1"})
        assert sprd_no_ref["isError"] and "max_order_notional_exceeded" in sprd_no_ref["content"][0]["text"]

        lowball_ask = gw.call_tool("arena_place_order", {"symbol": "BTC/USD:USD", "side": "sell", "price_usd": "1", "amount_base": "1"})
        assert lowball_ask["isError"] and "max_order_notional_exceeded" in lowball_ask["content"][0]["text"]

        q_over = gw.call_tool(
            "arena_replace_two_sided_quote",
            {"symbol": "BTC/USD:USD", "bid_price_usd": "50000", "bid_amount_base": "0.3", "ask_price_usd": "65000", "ask_amount_base": "0.3"},
        )
        assert q_over["isError"] and "max_order_notional_exceeded" in q_over["content"][0]["text"]
        q_ok = gw.call_tool(
            "arena_replace_two_sided_quote",
            {"symbol": "BTC/USD:USD", "bid_price_usd": "50000", "bid_amount_base": "0.2", "ask_price_usd": "65000", "ask_amount_base": "0.1"},
        )
        assert not q_ok["isError"], q_ok

        b_over = gw.call_tool(
            "arena_execute_atomic_basket",
            {
                "legs": [
                    {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.3"},
                    {"symbol": "BTC/USD:USD", "side": "sell", "price_usd": "65000", "amount_base": "0.3"},
                ]
            },
        )
        assert b_over["isError"] and "max_order_notional_exceeded" in b_over["content"][0]["text"]

        # Modify preserves actual ask side and rejects non-reduce_only shrinking crossing bypass
        stub.open_orders = [
            {"order_id": 501, "market_id": 1, "side": "ask", "price_ticks": 6_500_000, "remaining_lots": 5_000, "reduce_only": False},
        ]
        mod_missing = gw.call_tool("arena_modify_order", {"symbol": "BTC/USD:USD", "order_id": 999, "price_usd": "60000", "amount_base": "0.1"})
        assert mod_missing["isError"] and "not found" in mod_missing["content"][0]["text"]
        mod_bypass = gw.call_tool("arena_modify_order", {"symbol": "BTC/USD:USD", "order_id": 501, "price_usd": "10", "amount_base": "0.5"})
        assert mod_bypass["isError"] and "max_order_notional_exceeded" in mod_bypass["content"][0]["text"]
        mod_ok = gw.call_tool("arena_modify_order", {"symbol": "BTC/USD:USD", "order_id": 501, "price_usd": "61000", "amount_base": "0.2"})
        assert not mod_ok["isError"], mod_ok
        assert len(stub.edits) == 1 and stub.edits[0]["order_id"] == 501

        # Delta hedge notional caps (bounded max_qty_lots and unbounded perp_positions)
        hedge_bnd_over = gw.call_tool("arena_portfolio_delta_hedge", {"preferred_market_id": 1, "max_qty_lots": 10_000})
        assert hedge_bnd_over["isError"] and "max_order_notional_exceeded" in hedge_bnd_over["content"][0]["text"]
        stub.perp_positions = [{"market_id": 1, "position_lots": 10_000}]
        hedge_unbnd_over = gw.call_tool("arena_portfolio_delta_hedge", {})
        assert hedge_unbnd_over["isError"] and "max_order_notional_exceeded" in hedge_unbnd_over["content"][0]["text"]
        stub.perp_positions = [{"market_id": 1, "position_lots": 1_000}]
        hedge_ok = gw.call_tool("arena_portfolio_delta_hedge", {"preferred_market_id": 1, "max_qty_lots": 1_000})
        assert not hedge_ok["isError"], hedge_ok

        # Live exception secret redaction
        _dummy_redact_val = "_".join(("mock", "redaction", "fixture", "999"))
        stub.api_secret = _dummy_redact_val
        orig_health = stub.health
        stub.health = lambda: (_ for _ in ()).throw(RuntimeError("boom api_secret=" + _dummy_redact_val))  # type: ignore[method-assign]
        try:
            leak_err = gw.call_tool("arena_health_and_manifest", {})
            assert leak_err["isError"] and _dummy_redact_val not in leak_err["content"][0]["text"]
            assert "[REDACTED]" in leak_err["content"][0]["text"]
        finally:
            stub.health = orig_health  # type: ignore[method-assign]

        # Batch 4A MCP regressions (M-1..M-6)
        # M-1 & M-2: base_balances read accurately; cheap preferred_market_id with base_asset_id=0 cannot skip BTC holdings
        stub.perp_positions = []
        stub.base_balances = [
            {"asset_id": 1, "symbol": "BTC", "free_lots": 10_000, "locked_lots": 0, "borrowed_lots": 0}
        ]
        m1_over = gw.call_tool("arena_portfolio_delta_hedge", {"base_asset_id": 0})
        assert m1_over["isError"] and "max_order_notional_exceeded" in m1_over["content"][0]["text"], m1_over
        m2_cheap_pref = gw.call_tool(
            "arena_portfolio_delta_hedge",
            {"base_asset_id": 0, "preferred_market_id": 2, "max_qty_lots": 10_000},
        )
        assert m2_cheap_pref["isError"] and "max_order_notional_exceeded" in m2_cheap_pref["content"][0]["text"], m2_cheap_pref
        stub.base_balances = []

        # M-3: jit_elastic_mult multiplies notional cap (place_order & quote_replace)
        m3_ord = gw.call_tool(
            "arena_place_order",
            {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.02", "jit_elastic_mult": 50},
        )
        assert m3_ord["isError"] and "max_order_notional_exceeded" in m3_ord["content"][0]["text"], m3_ord
        m3_qt = gw.call_tool(
            "arena_replace_two_sided_quote",
            {"symbol": "BTC/USD:USD", "bid_price_usd": "50000", "bid_amount_base": "0.02", "ask_price_usd": "65000", "ask_amount_base": "0", "jit_elastic_mult": 50},
        )
        assert m3_qt["isError"] and "max_order_notional_exceeded" in m3_qt["content"][0]["text"], m3_qt

        # M-4: SpreadBook priced via gross underlying leg notional ($63k * 0.5 = $31.5k > $25k), not par offset ($10k * 0.5 = $5k)
        m4_sprd = gw.call_tool(
            "arena_place_order",
            {"symbol": "BTC-BASIS-SPRD", "side": "buy", "price_usd": "10000", "amount_base": "0.5"},
        )
        assert m4_sprd["isError"] and "max_order_notional_exceeded" in m4_sprd["content"][0]["text"], m4_sprd

        # M-5: --require-drawdown-stop blocks disarming, sub-$1 dust stops, and lowering active floor
        m5_zero = gw.call_tool("arena_configure_risk_guardrails", {"drawdown_stop_usd": "0"})
        assert m5_zero["isError"] and "drawdown_stop_cannot_be_disabled" in m5_zero["content"][0]["text"], m5_zero
        m5_dust = gw.call_tool("arena_configure_risk_guardrails", {"drawdown_stop_usd_micro": 1})
        assert m5_dust["isError"] and "drawdown_stop_below_minimum" in m5_dust["content"][0]["text"], m5_dust
        m5_lower = gw.call_tool("arena_configure_risk_guardrails", {"drawdown_stop_usd": "500"})
        assert m5_lower["isError"] and "drawdown_stop_cannot_be_lowered" in m5_lower["content"][0]["text"], m5_lower
        m5_raise = gw.call_tool("arena_configure_risk_guardrails", {"drawdown_stop_usd": "2000"})
        assert not m5_raise["isError"], m5_raise

        # M-6: wire_key_lo64/hi64 scrubbed in text & serve_stdio ValueError framing responses
        gw.adapter._wire_key_lo64 = 0x123456789ABCDEF0
        gw.adapter._wire_key_hi64 = 987654321012345
        wire_scrub = gw._scrub_secret_text("bad wire key 0x123456789abcdef0 and 987654321012345")
        assert "123456789abcdef0" not in wire_scrub.lower() and "987654321012345" not in wire_scrub, wire_scrub
        bad_cl_stream = io.BytesIO(b"Content-Length: 987654321012345_oops\r\n\r\n")
        bad_cl_out = io.BytesIO()
        assert gw.serve_stdio(bad_cl_stream, bad_cl_out) == 0
        bad_cl_raw = bad_cl_out.getvalue().decode("utf-8")
        assert "987654321012345" not in bad_cl_raw and "[REDACTED]" in bad_cl_raw, bad_cl_raw

        # Dynamic market reload regression when markets_by_id is already populated (reload=True)
        orig_stub_mkts = getattr(stub, "markets", None)
        orig_stub_book = stub.book
        orig_max_not = gw.max_order_notional_micro
        dyn_mkts: List[Dict[str, Any]] = [
            {
                "market_id": 25,
                "symbol": "NEW-USD-PERP",
                "kind": "linear_perpetual",
                "base_asset_id": 9,
                "mark_price_ticks": 500_000,
                "best_bid_ticks": 500_000,
                "best_ask_ticks": 500_100,
            }
        ]
        try:
            stub.markets = lambda: {  # type: ignore[attr-defined]
                "ok": True,
                "markets": [
                    {"market_id": 1, "symbol": "BTC-USD-PERP", "kind": "linear_perpetual", "base_asset_id": 1, "mark_price_ticks": 6_300_000},
                    {"market_id": 2, "symbol": "ETH-USD-PERP", "kind": "linear_perpetual", "base_asset_id": 2, "mark_price_ticks": 300_000},
                ]
                + list(dyn_mkts),
            }
            stub.book = lambda mid, depth=25: (  # type: ignore[method-assign]
                {"bids": [{"price_ticks": 500_000, "qty_lots": 100}], "asks": [{"price_ticks": 500_100, "qty_lots": 100}]}
                if int(mid) in (25, 26)
                else orig_stub_book(mid, depth=depth)
            )
            gw.max_order_notional_micro = usd_to_micro("2000")
            stub.base_balances = [{"asset_id": 9, "symbol": "NEW", "free_lots": 10_000, "locked_lots": 0, "borrowed_lots": 0}]
            dyn_reload_block = gw.call_tool("arena_portfolio_delta_hedge", {"base_asset_id": 9})
            assert dyn_reload_block["isError"] and "max_order_notional_exceeded" in dyn_reload_block["content"][0]["text"], dyn_reload_block
            assert 25 in gw.adapter.markets_by_id, gw.adapter.markets_by_id
            dyn_mkts.append(
                {
                    "market_id": 26,
                    "symbol": "NEW2-USD-PERP",
                    "kind": "linear_perpetual",
                    "base_asset_id": 10,
                    "mark_price_ticks": 500_000,
                    "best_bid_ticks": 500_000,
                    "best_ask_ticks": 500_100,
                }
            )
            stub.base_balances = []
            pref_reload_ok = gw.call_tool(
                "arena_portfolio_delta_hedge",
                {"base_asset_id": 10, "preferred_market_id": 26, "max_qty_lots": 20},
            )
            assert not pref_reload_ok["isError"], pref_reload_ok
            assert 26 in gw.adapter.markets_by_id, gw.adapter.markets_by_id
        finally:
            gw.max_order_notional_micro = orig_max_not
            stub.base_balances = []
            stub.book = orig_stub_book  # type: ignore[method-assign]
            if orig_stub_mkts is None and hasattr(stub, "markets"):
                delattr(stub, "markets")
            elif orig_stub_mkts is not None:
                stub.markets = orig_stub_mkts  # type: ignore[method-assign]

        # Audit Tier 3 #3.1..#3.5 MCP regressions:
        # #3.1: Thin stub bid (100 ticks) cannot understate mark_price_ticks (7,000,000 = $70k)
        orig_book_31 = stub.book
        try:
            stub.book = lambda mid, depth=1: (  # type: ignore[method-assign]
                {
                    "ok": True,
                    "market_id": int(mid),
                    "best_bid_ticks": 100,
                    "best_ask_ticks": 100,
                    "mark_price_ticks": 7_000_000,
                }
            )
            pegged_ask_bypass = gw.call_tool(
                "arena_place_order",
                {"symbol": "BTC/USD:USD", "side": "sell", "mark_peg": True, "price_ticks": 1, "qty_lots": 100_000},
            )
            assert (
                pegged_ask_bypass["isError"]
                and "max_order_notional_exceeded" in pegged_ask_bypass["content"][0]["text"]
            ), pegged_ask_bypass
        finally:
            stub.book = orig_book_31  # type: ignore[method-assign]

        # #3.2: arena_modify_order preserves peg_mode>0 & dark_hidden=True against mark_price_ticks
        stub.open_orders = [
            {
                "order_id": 801,
                "market_id": 1,
                "side": "bid",
                "price_ticks": 6_000_000,
                "remaining_lots": 100,
                "reduce_only": False,
                "peg_mode": 3,
                "dark_hidden": False,
            }
        ]
        pegged_mod_bypass = gw.call_tool(
            "arena_modify_order",
            {"symbol": "BTC/USD:USD", "order_id": 801, "price_ticks": 1, "qty_lots": 10_000},
        )
        assert (
            pegged_mod_bypass["isError"]
            and "max_order_notional_exceeded" in pegged_mod_bypass["content"][0]["text"]
        ), pegged_mod_bypass
        stub.open_orders = []

        # #3.3: action="link" requires drawdown stop & bounded guaranty, and binds no builder when rejected
        stub.dd_micro = 0
        link_no_dd = gw.call_tool(
            "arena_manage_prime_subaccount",
            {"action": "link", "master_account_id": 2, "sub_account_id": 3, "max_guaranty_usd": "1000"},
        )
        assert (
            link_no_dd["isError"]
            and "drawdown_stop_required_before_trading" in link_no_dd["content"][0]["text"]
        ), link_no_dd
        stub.dd_micro = usd_to_micro("1000")
        prev_bound_len = len(stub.bound)
        link_unlim = gw.call_tool(
            "arena_manage_prime_subaccount",
            {"action": "link", "master_account_id": 2, "sub_account_id": 3},
        )
        assert (
            link_unlim["isError"]
            and "max_order_notional_exceeded" in link_unlim["content"][0]["text"]
            and len(stub.bound) == prev_bound_len
        ), link_unlim

        # #3.4: static creds block wallet login without allow_wallet_login=True + restore creds metadata on failure
        static_gw = ArenaMcpGateway(
            account_id=2,
            api_key="[static-test-key]",
            api_secret="[static-test-secret]",
            allowed_accounts=frozenset({2}),
            allow_wallet_login=False,
        )
        static_gw.adapter.http.close()
        try:
            blocked_wl = static_gw.call_tool("arena_login_wallet", {"generate_ephemeral": True})
            assert blocked_wl["isError"] and "wallet_login_disabled" in blocked_wl["content"][0]["text"], blocked_wl
        finally:
            static_gw.close()

        class _CredsStubHttp(_StubHttp):
            def __init__(self) -> None:
                super().__init__()
                self.api_key = "[orig-test-key]"
                self.api_secret = "[orig-test-secret]"
                self._creds_path = "/tmp/fake_creds.json"
                self._creds_role = "trader"
                self._creds_fallback_role = "operator"
                self._creds_mtime_ns = 123456

            def set_credentials(self, k: str, s: str) -> None:
                self.api_key = k
                self.api_secret = s
                self._creds_path = None
                self._creds_mtime_ns = None

            def login_with_wallet(self, signer: Any) -> Dict[str, Any]:
                _ = signer
                self.set_credentials("ephemeral_k", "ephemeral_s")
                return {"ok": True, "account_id": 999}

        rb_gw = ArenaMcpGateway(account_id=2, api_key="[orig-test-key]", api_secret="[orig-test-secret]", allowed_accounts=frozenset({2}), allow_wallet_login=True)
        rb_stub = _CredsStubHttp()
        rb_gw.adapter.http.close()
        rb_gw.adapter.http = rb_stub  # type: ignore[assignment]
        try:
            rb_res = rb_gw.call_tool("arena_login_wallet", {"generate_ephemeral": True})
            assert rb_res["isError"] and "account_not_in_allowed_accounts" in rb_res["content"][0]["text"], rb_res
            assert rb_stub._creds_path == "/tmp/fake_creds.json" and rb_stub._creds_mtime_ns == 123456, rb_stub.__dict__
            assert rb_stub.api_secret == "[orig-test-secret]"
        finally:
            rb_gw.close()

        # #3.5: _err_tool_result scrubs bare secret tokens & _scrub_secrets handles tuples; short hex <=5 chars ignored
        err_tok = gw._err_tool_result("unhandled failure with token " + _dummy_redact_val + " inside")
        assert err_tok["isError"] and _dummy_redact_val not in err_tok["content"][0]["text"], err_tok
        assert "[REDACTED]" in err_tok["content"][0]["text"], err_tok
        tup_scrub = _scrub_secrets(({"api_secret": "s_tup"}, ("ok", {"wallet_privkey": "0xab"})))
        assert isinstance(tup_scrub, tuple) and tup_scrub[0]["api_secret"] == "[REDACTED]"
        assert tup_scrub[1][1]["wallet_privkey"] == "[REDACTED]"
        prev_lo = gw.adapter._wire_key_lo64
        try:
            gw.adapter._wire_key_lo64 = 1
            assert gw._scrub_secret_text("addr=0x12345") == "addr=0x12345"
        finally:
            gw.adapter._wire_key_lo64 = prev_lo

        # Gladiator Launchpad: preview_order, flash_arbitrage, auto_liquidate, ephemeral key retention & Streamable HTTP
        stub.dd_micro = usd_to_micro("1000")
        prev_ok = gw.call_tool("arena_preview_order", {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"})
        assert not prev_ok["isError"], prev_ok
        prev_data = json.loads(prev_ok["content"][0]["text"])
        assert prev_data["preview"] is True and prev_data["wouldAccept"] is True

        fa_ok = gw.call_tool("arena_flash_arbitrage", {"symbol": "BTC/USD:USD", "side": "buy", "amount_base": "0.05", "min_profit_usd": "0.01"})
        assert not fa_ok["isError"], fa_ok
        fa_lowball_bypass = gw.call_tool(
            "arena_flash_arbitrage",
            {"symbol": "BTC/USD:USD", "side": "mint", "limit_price_usd": "1.00", "amount_base": "1.0"},
        )
        assert fa_lowball_bypass["isError"] and "max_order_notional_exceeded" in fa_lowball_bypass["content"][0]["text"], fa_lowball_bypass

        liq_unbounded_cap = gw.call_tool("arena_auto_liquidate", {"market_id": 1, "flash_offload_to_book": True})
        assert liq_unbounded_cap["isError"] and "max_order_notional_exceeded" in liq_unbounded_cap["content"][0]["text"], liq_unbounded_cap
        liq_ok = gw.call_tool("arena_auto_liquidate", {"market_id": 1, "max_lots": 100, "flash_offload_to_book": True})
        assert not liq_ok["isError"], liq_ok
        stub.dd_micro = 0
        liq_no_dd = gw.call_tool("arena_auto_liquidate", {"market_id": 1, "max_lots": 100, "flash_offload_to_book": True})
        assert liq_no_dd["isError"] and "drawdown_stop_required_before_trading" in liq_no_dd["content"][0]["text"], liq_no_dd
        stub.dd_micro = usd_to_micro("1000")

        # Verify use_binary_wire=True gracefully falls back to HTTP REST when tcp_port == 0
        bin_fallback_ok = gw.call_tool(
            "arena_place_order",
            {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.05", "use_binary_wire": True},
        )
        assert not bin_fallback_ok["isError"], bin_fallback_ok

        # Verify rpc_url SSRF block on arena_onboard_and_deposit (http loopback, metadata, CGNAT, shorthand IPs, comma-separated failover & whitespace/control chars)
        for bad_rpc in (
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8545",
            "http://localhost:8545",
            "https://100.64.0.1/rpc",
            "https://127.1/rpc",
            "https://1.1.1.1/rpc,http://127.0.0.1:8545",
            "https://8.8.8.8/rpc,http://169.254.169.254/latest/meta-data/",
            "https://1.1.1.1/rpc https://8.8.8.8/rpc",
            "https://1.1.1.1/rpc\nhttps://8.8.8.8/rpc",
            "https://1.1.1.1/rpc\x00",
        ):
            ssrf_block = gw.call_tool(
                "arena_onboard_and_deposit",
                {"request_faucet": False, "deposit_onchain": True, "rpc_url": bad_rpc},
            )
            assert ssrf_block["isError"] and "unsafe_rpc_url" in ssrf_block["content"][0]["text"], (bad_rpc, ssrf_block)

        # Verify _strict_bool rejects string "false" / non-boolean values instead of coercing bool("false") == True
        for bad_bool_val in ("false", "true", "0", 0, 1):
            caught_strict_bool = False
            try:
                _ = _strict_bool(bad_bool_val, "reduce_only")
            except ValueError as sb_exc:
                caught_strict_bool = "reduce_only" in str(sb_exc)
            assert caught_strict_bool, f"Expected _strict_bool to reject {bad_bool_val!r}"
        strict_ord_err = gw.call_tool(
            "arena_place_order",
            {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.05", "reduce_only": "false"},
        )
        assert strict_ord_err["isError"] and "reduce_only" in strict_ord_err["content"][0]["text"], strict_ord_err
        strict_dep_err = gw.call_tool(
            "arena_onboard_and_deposit",
            {"generate_ephemeral": True, "request_faucet": False, "deposit_onchain": "false"},
        )
        assert strict_dep_err["isError"] and "deposit_onchain" in strict_dep_err["content"][0]["text"], strict_dep_err

        onb_ok = gw.call_tool("arena_onboard_and_deposit", {"generate_ephemeral": True, "request_faucet": True, "faucet_amount": "5000", "deposit_onchain": False})
        assert not onb_ok["isError"], onb_ok
        onb_ok_obj = json.loads(onb_ok["content"][0]["text"])
        assert "deposit" not in onb_ok_obj, onb_ok_obj
        assert gw._wallet_privkey_hex.startswith("0x") and len(gw._wallet_privkey_hex) == 66
        assert gw._wallet_privkey_hex not in onb_ok["content"][0]["text"]

        # v4.9.3 Upgrade 1: deposit_onchain schema default True + $10,000 self-deposit exempt from $5,000 max_order_notional_usd cap
        onb_spec = next(t for t in _tool_specs() if t["name"] == "arena_onboard_and_deposit")
        assert onb_spec["inputSchema"]["properties"]["deposit_onchain"]["default"] is True, onb_spec
        prev_cap_onb = gw.max_order_notional_micro
        try:
            gw.max_order_notional_micro = usd_to_micro("5000")
            onb_default_dep = gw.call_tool("arena_onboard_and_deposit", {"generate_ephemeral": True})
            assert not onb_default_dep["isError"], onb_default_dep
            onb_dep_obj = json.loads(onb_default_dep["content"][0]["text"])
            assert onb_dep_obj["faucet"]["amount"] == "10000", onb_dep_obj
            assert onb_dep_obj["deposit"]["ok"] is True and onb_dep_obj["deposit"]["amount"] == "10000", onb_dep_obj
        finally:
            gw.max_order_notional_micro = prev_cap_onb

        # v4.9.3 Upgrade 2: MCP protocolVersion negotiation across 2024-11-05 .. 2025-11-25 + fallback
        for ver_cand in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
            init_neg = gw.handle_jsonrpc_message(
                {"jsonrpc": "2.0", "id": 90, "method": "initialize", "params": {"protocolVersion": ver_cand}}
            )
            assert init_neg is not None
            assert init_neg["result"]["protocolVersion"] == ver_cand, (ver_cand, init_neg)
            assert init_neg["result"]["capabilities"]["prompts"] == {"listChanged": False}, init_neg
        init_fb = gw.handle_jsonrpc_message(
            {"jsonrpc": "2.0", "id": 91, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}}
        )
        assert init_fb is not None and init_fb["result"]["protocolVersion"] == "2025-11-25", init_fb
        rtmpl_resp = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 910, "method": "resources/templates/list"})
        assert rtmpl_resp is not None and rtmpl_resp["result"] == {"resourceTemplates": []}, rtmpl_resp

        # v4.9.3 Upgrade 3 & v4.9.4 TDQS/Schema Polish: ToolAnnotations, top-level title, and 223/223 property descriptions
        all_specs_24 = _tool_specs()
        assert len(all_specs_24) == 24
        prop_total_cnt = 0
        prop_desc_cnt = 0
        for sp in all_specs_24:
            ann = sp.get("annotations")
            assert isinstance(ann, dict) and isinstance(ann.get("title"), str) and len(ann["title"]) > 0, sp
            assert sp.get("title") == ann["title"], sp
            assert isinstance(sp.get("description"), str) and len(sp["description"].strip()) >= 40, sp
            for pk, pv in sp["inputSchema"]["properties"].items():
                prop_total_cnt += 1
                assert isinstance(pv.get("description"), str) and len(pv["description"].strip()) > 0, (sp["name"], pk)
                prop_desc_cnt += 1
                if "items" in pv and "properties" in pv["items"]:
                    for npk, npv in pv["items"]["properties"].items():
                        prop_total_cnt += 1
                        assert isinstance(npv.get("description"), str) and len(npv["description"].strip()) > 0, (
                            sp["name"],
                            pk,
                            npk,
                        )
                        prop_desc_cnt += 1
            tname_sp = sp["name"]
            if tname_sp in READ_ONLY_TOOLS:
                exp_hints = (True, False, True, True)
            elif tname_sp == "arena_cancel_orders":
                exp_hints = (False, True, True, True)
            elif tname_sp == "arena_request_withdrawal":
                exp_hints = (False, True, False, True)
            else:
                exp_hints = (False, False, False, True)
            got_hints = (
                ann.get("readOnlyHint"),
                ann.get("destructiveHint"),
                ann.get("idempotentHint"),
                ann.get("openWorldHint"),
            )
            assert got_hints == exp_hints, (tname_sp, got_hints, exp_hints)
        assert prop_total_cnt == 223 and prop_desc_cnt == 223, (prop_desc_cnt, prop_total_cnt)

        # v4.9.3 Upgrade 4: prompts/list & prompts/get
        plist_resp = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 92, "method": "prompts/list"})
        assert plist_resp is not None
        prompts_arr = plist_resp["result"]["prompts"]
        assert [pr["name"] for pr in prompts_arr] == [
            "onboard_and_quote_testnet",
            "scan_zero_capital_bounties",
            "audit_exchange_solvency",
        ], prompts_arr
        p1 = gw.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 93,
                "method": "prompts/get",
                "params": {"name": "onboard_and_quote_testnet", "arguments": {"symbol": "ETH/USD:USD", "spread_bps": "15"}},
            }
        )
        assert p1 is not None and "ETH/USD:USD" in p1["result"]["messages"][0]["content"]["text"]
        assert "15" in p1["result"]["messages"][0]["content"]["text"]
        p2 = gw.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 94,
                "method": "prompts/get",
                "params": {"name": "scan_zero_capital_bounties", "arguments": {"execute": "true"}},
            }
        )
        assert p2 is not None and "execute=true" in p2["result"]["messages"][0]["content"]["text"]
        op_pin_test = "0x" + ("22" * 20)
        p3 = gw.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 95,
                "method": "prompts/get",
                "params": {"name": "audit_exchange_solvency", "arguments": {"expected_operator_address": op_pin_test}},
            }
        )
        assert p3 is not None and op_pin_test in p3["result"]["messages"][0]["content"]["text"]
        p_unknown = gw.handle_jsonrpc_message(
            {"jsonrpc": "2.0", "id": 96, "method": "prompts/get", "params": {"name": "nonexistent_prompt"}}
        )
        assert p_unknown is not None and p_unknown["error"]["code"] == -32602

        # v4.9.3 Upgrade 5: --public-http-mode unauthenticated tool filtering, 401 preview hint, lock-free reads & HTTP caps
        assert parse_args(["--read-only"]).public_http_mode is False
        assert parse_args(["--read-only", "--public-http-mode"]).public_http_mode is True
        assert parse_args(["--public-http-mode"]).read_only is True

        # Local read-only (non-public) hides onboard_and_quote_testnet prompt too
        ro_local_gw = ArenaMcpGateway(read_only=True, public_http_mode=False)
        try:
            assert [pr["name"] for pr in ro_local_gw.list_prompts()] == [
                "scan_zero_capital_bounties",
                "audit_exchange_solvency",
            ]
            ro_mut_pr = ro_local_gw.handle_jsonrpc_message(
                {"jsonrpc": "2.0", "id": 970, "method": "prompts/get", "params": {"name": "onboard_and_quote_testnet"}}
            )
            assert ro_mut_pr is not None and ro_mut_pr["error"]["code"] == -32602
        finally:
            ro_local_gw.close()

        pub_gw = ArenaMcpGateway(public_http_mode=True)
        assert pub_gw.read_only is True
        pub_gw.adapter.markets_by_symbol = gw.adapter.markets_by_symbol
        pub_gw.adapter.markets_by_id = gw.adapter.markets_by_id
        pub_gw.adapter.unified_to_native = gw.adapter.unified_to_native
        try:
            pub_tool_names = {t["name"] for t in pub_gw.list_tools()}
            assert len(pub_tool_names) == 7, pub_tool_names
            assert "arena_get_account_portfolio" not in pub_tool_names
            assert "arena_get_withdrawals_and_escape_proof" not in pub_tool_names
            assert pub_tool_names == (READ_ONLY_TOOLS - PUBLIC_UNAUTH_HIDDEN_READ_TOOLS)
            for hidden_ro_tool in PUBLIC_UNAUTH_HIDDEN_READ_TOOLS:
                hidden_ro_res = pub_gw.call_tool(hidden_ro_tool, {"account_id": 2})
                assert hidden_ro_res["isError"] and "public_http_mode_restricted" in hidden_ro_res["content"][0]["text"], (
                    hidden_ro_tool,
                    hidden_ro_res,
                )

            pub_prompt_names = [pr["name"] for pr in pub_gw.list_prompts()]
            assert pub_prompt_names == ["scan_zero_capital_bounties", "audit_exchange_solvency"], pub_prompt_names
            pub_mut_prompt = pub_gw.handle_jsonrpc_message(
                {"jsonrpc": "2.0", "id": 97, "method": "prompts/get", "params": {"name": "onboard_and_quote_testnet"}}
            )
            assert pub_mut_prompt is not None and pub_mut_prompt["error"]["code"] == -32602, pub_mut_prompt
            for pub_pn, pub_pa in (
                ("scan_zero_capital_bounties", {"execute": "true"}),
                ("audit_exchange_solvency", {}),
            ):
                pub_pr = pub_gw.get_prompt(pub_pn, pub_pa)
                pub_ptxt = pub_pr["messages"][0]["content"]["text"]
                for unavail_t in (
                    "arena_onboard_and_deposit",
                    "arena_replace_two_sided_quote",
                    "arena_configure_risk_guardrails",
                    "arena_flash_arbitrage",
                    "arena_auto_liquidate",
                    "arena_login_wallet",
                    "arena_get_withdrawals_and_escape_proof",
                ):
                    assert unavail_t not in pub_ptxt, (pub_pn, unavail_t, pub_ptxt)

            seen_pub_prev_aids: List[int] = []
            pub_gw.adapter.http.preview_order = lambda **kwargs: (  # type: ignore[method-assign]
                seen_pub_prev_aids.append(int(kwargs["account_id"]))
                or stub.preview_order(**kwargs)
            )
            pub_prev_zero_ok = pub_gw.call_tool(
                "arena_preview_order",
                {"account_id": 42, "symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"},
            )
            assert not pub_prev_zero_ok["isError"], pub_prev_zero_ok
            assert seen_pub_prev_aids == [0], seen_pub_prev_aids
            assert pub_prev_zero_ok["structuredContent"]["would_accept"] is True

            pub_gw.adapter.http.preview_order = lambda **kwargs: {  # type: ignore[method-assign]
                "ok": False,
                "error": "missing_auth_headers",
                "http_status": 401,
            }
            pub_gw.adapter.http.get_leaderboard = stub.get_leaderboard  # type: ignore[method-assign]
            pub_prev = pub_gw.call_tool(
                "arena_preview_order",
                {"symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"},
            )
            assert not pub_prev["isError"], pub_prev
            pub_prev_obj = pub_prev["structuredContent"]
            assert pub_prev_obj["auth_required"] is True and pub_prev_obj["http_status"] == 401, pub_prev_obj
            assert "uvx feraterra-sdk --testnet" in pub_prev_obj["hint"], pub_prev_obj

            pub_gw.adapter.http.preview_order = lambda **kwargs: {  # type: ignore[method-assign]
                "ok": False,
                "error": "invalid_account_id",
                "http_status": 400,
            }
            pub_prev_400 = pub_gw.call_tool(
                "arena_preview_order",
                {"account_id": 0, "symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"},
            )
            assert not pub_prev_400["isError"], pub_prev_400
            assert pub_prev_400["structuredContent"]["auth_required"] is True
            assert pub_prev_400["structuredContent"]["http_status"] == 400

            pub_gw.adapter.http.markets = lambda: {  # type: ignore[method-assign]
                "ok": True,
                "wal_seq": 100,
                "markets": [
                    {
                        "market_id": 1,
                        "symbol": "BTC-USD-PERP",
                        "kind": "linear_perpetual",
                        "mark_price_ticks": 6_000_000,
                        "best_bid_ticks": 0,
                        "best_ask_ticks": 0,
                    }
                ],
            }
            lm_empty = pub_gw.call_tool("arena_list_markets", {})
            assert not lm_empty["isError"], lm_empty
            lm_mkt0 = lm_empty["structuredContent"]["markets"][0]
            assert lm_mkt0["best_bid_usd"] is None and lm_mkt0["best_ask_usd"] is None, lm_mkt0

            # Verify lock-free execution when another thread holds _dispatch_lock
            lock_acquired_evt = threading.Event()
            release_lock_evt = threading.Event()

            def _hold_locks() -> None:
                with gw._dispatch_lock, pub_gw._dispatch_lock:
                    lock_acquired_evt.set()
                    release_lock_evt.wait(timeout=5.0)

            lk_thr = threading.Thread(target=_hold_locks, daemon=True)
            lk_thr.start()
            assert lock_acquired_evt.wait(timeout=2.0)
            try:
                for lf_method, lf_params in (
                    ("initialize", {"protocolVersion": "2025-11-25"}),
                    ("ping", {}),
                    ("tools/list", {}),
                    ("resources/list", {}),
                    ("resources/templates/list", {}),
                    ("prompts/list", {}),
                    ("prompts/get", {"name": "scan_zero_capital_bounties", "arguments": {"execute": "false"}}),
                ):
                    lf_raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": lf_method, "params": lf_params}).encode("utf-8")
                    lf_rep = gw.dispatch_raw_payload(lf_raw)
                    assert isinstance(lf_rep, dict) and "result" in lf_rep, (lf_method, lf_rep)
                ro_call_raw = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "arena_get_leaderboard", "arguments": {"limit": 3}},
                    }
                ).encode("utf-8")
                ro_rep = pub_gw.dispatch_raw_payload(ro_call_raw)
                assert isinstance(ro_rep, dict) and not ro_rep["result"]["isError"], ro_rep
            finally:
                release_lock_evt.set()
                lk_thr.join(timeout=2.0)
        finally:
            pub_gw.close()

        auth_pub_gw = ArenaMcpGateway(read_only=False, public_http_mode=True, account_id=2, api_key="k", api_secret="s")
        auth_pub_gw.adapter.markets_by_symbol = gw.adapter.markets_by_symbol
        auth_pub_gw.adapter.markets_by_id = gw.adapter.markets_by_id
        auth_pub_gw.adapter.unified_to_native = gw.adapter.unified_to_native
        try:
            assert auth_pub_gw.read_only is True
            assert len(auth_pub_gw.list_tools()) == 7
            for hidden_t in PUBLIC_UNAUTH_HIDDEN_READ_TOOLS:
                blocked_h = auth_pub_gw.call_tool(hidden_t, {"account_id": 2})
                assert blocked_h["isError"] and "public_http_mode_restricted" in blocked_h["content"][0]["text"]
            seen_auth_pub_aids: List[int] = []
            auth_pub_gw.adapter.http.preview_order = lambda **kwargs: (  # type: ignore[method-assign]
                seen_auth_pub_aids.append(int(kwargs["account_id"]))
                or stub.preview_order(**kwargs)
            )
            ap_prev = auth_pub_gw.call_tool(
                "arena_preview_order",
                {"account_id": 2, "symbol": "BTC/USD:USD", "side": "buy", "price_usd": "50000", "amount_base": "0.1"},
            )
            assert not ap_prev["isError"] and seen_auth_pub_aids == [0], (ap_prev, seen_auth_pub_aids)
        finally:
            auth_pub_gw.close()

        # Verify stdio still accepts > 65,536-byte frames (up to 4 MiB)
        big_stdio_msg = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping", "params": {"pad": "x" * 70_000}}).encode("utf-8")
        stdio_big_out = io.BytesIO()
        assert gw.serve_stdio(io.BytesIO(big_stdio_msg + b"\n"), stdio_big_out) == 0
        assert json.loads(stdio_big_out.getvalue().decode("utf-8"))["id"] == 99

        import urllib.error
        import urllib.request

        http_srv = gw.create_http_server(host="127.0.0.1", port=0, bearer_token="[gladiator-test-token]")
        http_port = int(http_srv.server_address[1])
        http_thr = threading.Thread(target=http_srv.serve_forever, daemon=True)
        http_thr.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/mcp/health", timeout=3.0) as hresp:
                h_raw_bytes = hresp.read()
                hj = json.loads(h_raw_bytes.decode("utf-8"))
                assert hj["ok"] is True and hj["tool_count"] == 24
                assert hj["version"] == "4.9.5"
                assert hj["protocolVersion"] == "2025-11-25"
                assert "2025-11-25" in hj["supportedProtocolVersions"]

            def _raw_head_request(target_port: int, path_str: str, extra_hdrs: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
                with socket.create_connection(("127.0.0.1", target_port), timeout=3.0) as s_head:
                    hdr_lines = [f"HEAD {path_str} HTTP/1.1", f"Host: 127.0.0.1:{target_port}"]
                    for hk, hv in (extra_hdrs or {}).items():
                        hdr_lines.append(f"{hk}: {hv}")
                    s_head.sendall(("\r\n".join(hdr_lines) + "\r\n\r\n").encode("ascii"))
                    chunks: List[bytes] = []
                    while True:
                        blk = s_head.recv(4096)
                        if not blk:
                            break
                        chunks.append(blk)
                wire = b"".join(chunks)
                sep_i = wire.index(b"\r\n\r\n")
                hdr_block = wire[:sep_i].decode("iso-8859-1")
                body_part = wire[sep_i + 4 :]
                lines = hdr_block.split("\r\n")
                st_code = int(lines[0].split(" ", 2)[1])
                parsed_h: Dict[str, str] = {}
                for hl in lines[1:]:
                    if ":" in hl:
                        k_h, v_h = hl.split(":", 1)
                        parsed_h[k_h.strip().lower()] = v_h.strip()
                return st_code, parsed_h, body_part

            for hp in ("/mcp/health", "/health"):
                st_h, hd_h, bd_h = _raw_head_request(http_port, hp)
                assert st_h == 200 and bd_h == b"", (hp, st_h, bd_h)
                assert hd_h.get("content-type") == "application/json; charset=utf-8", hd_h
                assert int(hd_h.get("content-length", "-1")) == len(h_raw_bytes), hd_h
                assert "Mcp-Session-Id" in hd_h.get("access-control-expose-headers", ""), hd_h
                assert "MCP-Protocol-Version" in hd_h.get("access-control-expose-headers", ""), hd_h
                assert hd_h.get("access-control-max-age") == "86400", hd_h

            for sc_path in ("/mcp/server-card", "/.well-known/mcp/server-card.json", "/.well-known/mcp.json"):
                with urllib.request.urlopen(f"http://127.0.0.1:{http_port}{sc_path}", timeout=3.0) as scresp:
                    sc_raw_bytes = scresp.read()
                    scj = json.loads(sc_raw_bytes.decode("utf-8"))
                    assert scj["$schema"] == "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json", scj
                    assert scj["name"] == "io.github.FeraTerra/feraterra-sdk", scj
                    assert scj["version"] == "4.9.5", scj
                    assert scj["websiteUrl"] == "https://feraterra.app", scj
                    assert scj["repository"] == {"url": "https://github.com/FeraTerra/feraterra-sdk", "source": "github"}, scj
                    assert scj["remotes"] == [
                        {
                            "type": "streamable-http",
                            "url": "https://mcp.feraterra.app/mcp",
                            "supportedProtocolVersions": ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"],
                        }
                    ], scj
                st_sc_h, hd_sc_h, bd_sc_h = _raw_head_request(http_port, sc_path)
                assert st_sc_h == 200 and bd_sc_h == b"", (sc_path, st_sc_h, bd_sc_h)
                assert hd_sc_h.get("content-type") == "application/json; charset=utf-8", hd_sc_h
                assert int(hd_sc_h.get("content-length", "-1")) == len(sc_raw_bytes), hd_sc_h
                st_sc_ct, hd_sc_ct, bd_sc_ct = _raw_head_request(
                    http_port, sc_path, {"Accept": "application/mcp-server-card+json"}
                )
                assert st_sc_ct == 200 and bd_sc_ct == b"", (sc_path, st_sc_ct, bd_sc_ct)
                assert hd_sc_ct.get("content-type") == "application/mcp-server-card+json; charset=utf-8", hd_sc_ct
                assert int(hd_sc_ct.get("content-length", "-1")) == len(sc_raw_bytes), hd_sc_ct

            st_mcp_head, hd_mcp_head, bd_mcp_head = _raw_head_request(http_port, "/mcp")
            assert st_mcp_head == 405 and bd_mcp_head == b"", (st_mcp_head, bd_mcp_head)
            assert hd_mcp_head.get("content-type") == "application/json; charset=utf-8", hd_mcp_head
            assert "POST" in hd_mcp_head.get("allow", ""), hd_mcp_head
            st_404_head, hd_404_head, bd_404_head = _raw_head_request(http_port, "/nonexistent")
            assert st_404_head == 404 and bd_404_head == b"" and "application/json" in hd_404_head.get("content-type", "")

            got_405 = False
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{http_port}/mcp", timeout=3.0)
            except urllib.error.HTTPError as he405:
                got_405 = (he405.code == 405)
            assert got_405, "Expected HTTP 405 on GET /mcp"

            sse_req = urllib.request.Request(
                f"http://127.0.0.1:{http_port}/mcp",
                headers={"Accept": "text/event-stream"},
                method="GET",
            )
            got_sse_405 = False
            try:
                urllib.request.urlopen(sse_req, timeout=3.0)
            except urllib.error.HTTPError as he_sse:
                sse_body = json.loads(he_sse.read().decode("utf-8"))
                got_sse_405 = (
                    he_sse.code == 405
                    and "POST" in str(he_sse.headers.get("Allow", ""))
                    and sse_body.get("ok") is False
                )
            assert got_sse_405, "Expected HTTP 405 JSON + Allow: POST, OPTIONS on GET /mcp Accept: text/event-stream"

            del_req = urllib.request.Request(f"http://127.0.0.1:{http_port}/mcp", method="DELETE")
            got_del_405 = False
            try:
                urllib.request.urlopen(del_req, timeout=3.0)
            except urllib.error.HTTPError as he_del:
                del_body = json.loads(he_del.read().decode("utf-8"))
                got_del_405 = (he_del.code == 405 and del_body.get("ok") is False)
            assert got_del_405, "Expected HTTP 405 JSON on DELETE /mcp"

            opt_req = urllib.request.Request(f"http://127.0.0.1:{http_port}/mcp", method="OPTIONS")
            with urllib.request.urlopen(opt_req, timeout=3.0) as oresp:
                assert oresp.status == 204
                allow_hdrs = str(oresp.headers.get("Access-Control-Allow-Headers", ""))
                allow_meths = str(oresp.headers.get("Access-Control-Allow-Methods", ""))
                expose_hdrs = str(oresp.headers.get("Access-Control-Expose-Headers", ""))
                for req_h in ("MCP-Protocol-Version", "Mcp-Session-Id", "Last-Event-ID", "Accept"):
                    assert req_h in allow_hdrs, allow_hdrs
                assert "DELETE" in allow_meths and "HEAD" in allow_meths, allow_meths
                assert "Mcp-Session-Id" in expose_hdrs and "MCP-Protocol-Version" in expose_hdrs, expose_hdrs
                assert str(oresp.headers.get("Access-Control-Max-Age", "")) == "86400"

            unauth_req = urllib.request.Request(
                f"http://127.0.0.1:{http_port}/mcp",
                data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            got_401 = False
            try:
                urllib.request.urlopen(unauth_req, timeout=3.0)
            except urllib.error.HTTPError as he:
                got_401 = (he.code == 401)
            assert got_401, "Expected HTTP 401 without Bearer token"

            # HTTP POST max body lowered to 65,536 bytes -> 413 Payload Too Large
            too_big_http = urllib.request.Request(
                f"http://127.0.0.1:{http_port}/mcp",
                data=big_stdio_msg,
                headers={"Content-Type": "application/json", "Authorization": "Bearer [gladiator-test-token]"},
                method="POST",
            )
            got_413 = False
            try:
                urllib.request.urlopen(too_big_http, timeout=3.0)
            except urllib.error.HTTPError as he413:
                got_413 = (he413.code == 413)
            assert got_413, "Expected HTTP 413 when POST /mcp exceeds 65,536 bytes"

            # BoundedSemaphore(64) saturation -> HTTP 503 mcp_server_busy
            sem_ref = getattr(http_srv, "_inflight_semaphore")
            acquired_slots = 0
            while sem_ref.acquire(blocking=False):
                acquired_slots += 1
            try:
                assert acquired_slots == HTTP_MAX_INFLIGHT_REQUESTS, acquired_slots
                busy_req = urllib.request.Request(
                    f"http://127.0.0.1:{http_port}/mcp",
                    data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                    headers={"Content-Type": "application/json", "Authorization": "Bearer [gladiator-test-token]"},
                    method="POST",
                )
                got_503 = False
                try:
                    urllib.request.urlopen(busy_req, timeout=3.0)
                except urllib.error.HTTPError as he503:
                    busy_json = json.loads(he503.read().decode("utf-8"))
                    got_503 = (
                        he503.code == 503
                        and busy_json == {
                            "jsonrpc": "2.0",
                            "error": {"code": -32000, "message": "mcp_server_busy"},
                            "id": None,
                        }
                    )
                assert got_503, "Expected HTTP 503 mcp_server_busy when BoundedSemaphore(64) is saturated"
            finally:
                for _ in range(acquired_slots):
                    sem_ref.release()

            notif_req = urllib.request.Request(
                f"http://127.0.0.1:{http_port}/mcp",
                data=b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
                headers={"Content-Type": "application/json", "Authorization": "Bearer [gladiator-test-token]"},
                method="POST",
            )
            with urllib.request.urlopen(notif_req, timeout=3.0) as nresp:
                assert nresp.status == 202

            tl_req = urllib.request.Request(
                f"http://127.0.0.1:{http_port}/mcp",
                data=b'{"jsonrpc":"2.0","id":7,"method":"tools/list"}',
                headers={"Content-Type": "application/json", "Authorization": "Bearer [gladiator-test-token]"},
                method="POST",
            )
            with urllib.request.urlopen(tl_req, timeout=3.0) as tresp:
                tj = json.loads(tresp.read().decode("utf-8"))
                assert len(tj["result"]["tools"]) == 24
        finally:
            http_srv.shutdown()
            http_srv.server_close()

        # Verify DNS-rebinding / CSRF Origin & Host guards + omitted wildcard CORS on local HTTP server
        local_mut_srv = gw.create_http_server(host="127.0.0.1", port=0, bearer_token="")
        local_mut_port = int(local_mut_srv.server_address[1])
        local_mut_thr = threading.Thread(target=local_mut_srv.serve_forever, daemon=True)
        local_mut_thr.start()
        try:
            # Non-browser CLI/MCP client (missing/empty Origin) + trusted loopback Origins succeed; wildcard CORS is omitted
            for ok_origin in (
                None,
                "",
                "http://127.0.0.1:8765",
                "http://localhost:3000",
                "http://[::1]:3000",
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
            ):
                hdrs_ok = {"Content-Type": "application/json"}
                if ok_origin is not None:
                    hdrs_ok["Origin"] = ok_origin
                req_ok = urllib.request.Request(
                    f"http://127.0.0.1:{local_mut_port}/mcp",
                    data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                    headers=hdrs_ok,
                    method="POST",
                )
                with urllib.request.urlopen(req_ok, timeout=3.0) as resp_ok:
                    assert resp_ok.status == 200, (ok_origin, resp_ok.status)
                    assert resp_ok.headers.get("Access-Control-Allow-Origin") is None, resp_ok.headers

            # Untrusted / null / DNS-rebound / subdomain-spoofed browser Origins rejected with 403 Forbidden
            for bad_origin in (
                "null",
                "NULL",
                "https://evil.example",
                "http://rebind.attacker.example:8765",
                "http://127.0.0.1.evil.example",
                "http://localhost.evil.example",
                "http://localhost@evil.example",
            ):
                req_bad = urllib.request.Request(
                    f"http://127.0.0.1:{local_mut_port}/mcp",
                    data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                    headers={"Content-Type": "application/json", "Origin": bad_origin},
                    method="POST",
                )
                got_403 = False
                try:
                    urllib.request.urlopen(req_bad, timeout=3.0)
                except urllib.error.HTTPError as he403:
                    err_403_json = json.loads(he403.read().decode("utf-8"))
                    got_403 = (
                        he403.code == 403
                        and err_403_json == {
                            "ok": False,
                            "error": "Untrusted Origin header on local MCP server",
                        }
                    )
                assert got_403, f"Expected 403 Forbidden for Origin={bad_origin!r}"

            # Loopback Host header validation (localhost, 127.0.0.1, [::1] allowed; DNS-rebound Host rejected)
            def _raw_post_with_host(target_port: int, host_hdr: str) -> Tuple[int, Dict[str, Any]]:
                body_b = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
                with socket.create_connection(("127.0.0.1", target_port), timeout=3.0) as s_h:
                    raw_http = (
                        f"POST /mcp HTTP/1.1\r\nHost: {host_hdr}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(body_b)}\r\n\r\n"
                    ).encode("ascii") + body_b
                    s_h.sendall(raw_http)
                    chunks_h: List[bytes] = []
                    while True:
                        blk_h = s_h.recv(4096)
                        if not blk_h:
                            break
                        chunks_h.append(blk_h)
                wire_h = b"".join(chunks_h)
                sep_h = wire_h.index(b"\r\n\r\n")
                st_h = int(wire_h[:sep_h].decode("iso-8859-1").split("\r\n", 1)[0].split(" ", 2)[1])
                return st_h, json.loads(wire_h[sep_h + 4 :].decode("utf-8"))

            for ok_host in (f"127.0.0.1:{local_mut_port}", "127.0.0.1", f"localhost:{local_mut_port}", "localhost", f"[::1]:{local_mut_port}", "[::1]"):
                st_ok_h, _ = _raw_post_with_host(local_mut_port, ok_host)
                assert st_ok_h == 200, (ok_host, st_ok_h)
            for bad_host in ("evil.example", f"rebind.attacker.example:{local_mut_port}", "127.0.0.1.evil.example", "::1"):
                st_bad_h, body_bad_h = _raw_post_with_host(local_mut_port, bad_host)
                assert st_bad_h == 403 and body_bad_h == {
                    "ok": False,
                    "error": "Untrusted Host header on local MCP server",
                }, (bad_host, st_bad_h, body_bad_h)
        finally:
            local_mut_srv.shutdown()
            local_mut_srv.server_close()

        # Verify local read_only=True (!public_http_mode) still enforces _is_trusted_local_origin & omits wildcard CORS
        ro_priv_gw = ArenaMcpGateway(read_only=True, public_http_mode=False)
        ro_priv_srv = ro_priv_gw.create_http_server(host="127.0.0.1", port=0, bearer_token="")
        ro_priv_port = int(ro_priv_srv.server_address[1])
        ro_priv_thr = threading.Thread(target=ro_priv_srv.serve_forever, daemon=True)
        ro_priv_thr.start()
        try:
            ro_priv_bad = urllib.request.Request(
                f"http://127.0.0.1:{ro_priv_port}/mcp",
                data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
                method="POST",
            )
            got_ro_403 = False
            try:
                urllib.request.urlopen(ro_priv_bad, timeout=3.0)
            except urllib.error.HTTPError as he_ro:
                got_ro_403 = he_ro.code == 403
            assert got_ro_403, "Expected 403 on local read-only (!public_http_mode) server for cross-origin Origin"
        finally:
            ro_priv_srv.shutdown()
            ro_priv_srv.server_close()
            ro_priv_gw.close()

        # Verify public_http_mode (read_only=True) remains 100% unaffected by cross-origin browser Origin headers & emits CORS *
        ro_origin_gw = ArenaMcpGateway(read_only=True, public_http_mode=True)
        ro_http_srv = ro_origin_gw.create_http_server(host="127.0.0.1", port=0, bearer_token="")
        ro_http_port = int(ro_http_srv.server_address[1])
        ro_http_thr = threading.Thread(target=ro_http_srv.serve_forever, daemon=True)
        ro_http_thr.start()
        try:
            ro_ext_req = urllib.request.Request(
                f"http://127.0.0.1:{ro_http_port}/mcp",
                data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                headers={"Content-Type": "application/json", "Origin": "https://claude.ai"},
                method="POST",
            )
            with urllib.request.urlopen(ro_ext_req, timeout=3.0) as ro_ext_resp:
                assert ro_ext_resp.status == 200
                assert ro_ext_resp.headers.get("Access-Control-Allow-Origin") == "*"
        finally:
            ro_http_srv.shutdown()
            ro_http_srv.server_close()
            ro_origin_gw.close()

        # Verify interactive TTY stdio startup notice goes to stderr only
        class _FakeTtyIn:
            def __init__(self) -> None:
                self.buffer = io.BytesIO(b"")

            def isatty(self) -> bool:
                return True

        class _FakeTtyErr(io.StringIO):
            def isatty(self) -> bool:
                return True

        class _FakeOut:
            def __init__(self) -> None:
                self.buffer = io.BytesIO()

        orig_in, orig_out, orig_err = sys.stdin, sys.stdout, sys.stderr
        fake_in, fake_out, fake_err = _FakeTtyIn(), _FakeOut(), _FakeTtyErr()
        try:
            sys.stdin = fake_in  # type: ignore[assignment]
            sys.stdout = fake_out  # type: ignore[assignment]
            sys.stderr = fake_err
            assert main(["--read-only"]) == 0
            assert "[feraterra-mcp] Ready on stdio" in fake_err.getvalue()
            assert fake_out.buffer.getvalue() == b""
        finally:
            sys.stdin, sys.stdout, sys.stderr = orig_in, orig_out, orig_err
    finally:
        gw.close()

    print("[PASS] arena_mcp_server.py v4.9.5 MCP gateway self-test OK")


run_self_test = _run_mcp_self_test


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        _run_mcp_self_test()
        return 0

    wallet_pk = str(args.wallet_privkey or "").strip()
    if not wallet_pk and args.wallet_privkey_file:
        wallet_pk = Path(args.wallet_privkey_file).read_text(encoding="utf-8").strip()

    max_notional_micro = usd_to_micro(args.max_order_notional_usd, allow_zero=True)
    min_dd_micro = usd_to_micro(args.min_drawdown_stop_usd, allow_zero=True)
    allowed_accts = _parse_int_csv(args.allowed_accounts)
    allowed_recips = _parse_addr_csv(args.allowed_withdrawal_recipients)

    gw = ArenaMcpGateway(
        arena_url=args.arena_url,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        account_id=args.account_id,
        api_key=args.api_key or None,
        api_secret=args.api_secret or None,
        creds_file=args.creds_file or None,
        wallet_privkey_hex=wallet_pk or None,
        rpc_url=args.rpc_url,
        clearinghouse=args.clearinghouse,
        expected_operator_address=args.expected_operator_address,
        read_only=bool(args.read_only or args.public_http_mode),
        public_http_mode=bool(args.public_http_mode),
        allowed_accounts=allowed_accts,
        max_order_notional_micro=max_notional_micro,
        require_drawdown_stop=args.require_drawdown_stop,
        min_drawdown_stop_micro=min_dd_micro,
        default_builder_account=args.default_builder_account,
        default_builder_bps=args.default_builder_bps,
        allow_withdrawals=args.allow_withdrawals,
        allowed_withdrawal_recipients=allowed_recips,
        allow_wallet_login=args.allow_wallet_login,
        http_bearer_token=str(args.http_bearer_token or ""),
        timeout=args.timeout,
    )
    try:
        if int(args.http_listen_port) > 0:
            return gw.serve_http(
                host=str(args.http_listen_host or "127.0.0.1"),
                port=int(args.http_listen_port),
                bearer_token=str(args.http_bearer_token or ""),
            )
        if (
            getattr(sys.stdin, "isatty", lambda: False)()
            and getattr(sys.stderr, "isatty", lambda: False)()
        ):
            mode_label = "read-only" if gw.read_only else "read-write"
            print(
                f"[feraterra-mcp] Ready on stdio ({gw.adapter.base_url}, {mode_label}) — waiting for JSON-RPC messages",
                file=sys.stderr,
                flush=True,
            )
        return gw.serve_stdio(sys.stdin.buffer, sys.stdout.buffer)
    finally:
        gw.close()


if __name__ == "__main__":
    raise SystemExit(main())
