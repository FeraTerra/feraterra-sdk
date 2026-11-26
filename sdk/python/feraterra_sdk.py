"""
FeraTerra / Arena Exchange v4.9.3 — Official Python SDK & AI Agent Framework Connector
(`sdk/python/feraterra_sdk.py`)

Re-exports the complete zero-dependency `arena_sdk` surface (`ArenaHttpClient`,
`ArenaCcxtAdapter`, `ArenaBinaryClient`, `ArenaWsClient`, `ArenaItchClient`,
`EthWalletSigner`, `EvmJsonRpcClient`, fixed-point helpers, and cryptographic
verifiers) so `import feraterra_sdk` works out-of-the-box with Python's standard
library alone.

Also provides optional, lazy-imported agent-framework tool builders with zero
mandatory runtime dependencies:
  - `create_langchain_tools(client=None, account_id=0)`
  - `create_pydantic_ai_toolset(client=None, account_id=0)`
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

_SDK_DIR = Path(__file__).resolve().parent
if str(_SDK_DIR) not in sys.path:
    sys.path.insert(0, str(_SDK_DIR))

import arena_sdk as _arena_sdk  # noqa: E402
from arena_sdk import *  # noqa: E402,F401,F403

__version__: str = str(getattr(_arena_sdk, "__version__", "4.9.3"))
_arena_verify_ledger_tip = _arena_sdk.verify_ledger_tip


def _canonical_market_kind(raw_kind: object) -> str:
    k = str(raw_kind or "").strip().lower()
    if k in ("perp", "linear_perp", "linear_perpetual"):
        return "perp"
    if k in ("formula_perp", "formula_perpetual"):
        return "formula_perp"
    return k


def _resolve_agent_http_and_adapter(
    client: Optional[ArenaHttpClient] = None,
    account_id: int = 0,
) -> Tuple[ArenaHttpClient, ArenaCcxtAdapter, int]:
    if isinstance(client, ArenaCcxtAdapter):
        http_client = client.http
        eff_aid = int(account_id) if int(account_id) > 0 else int(client.account_id)
        return http_client, client, eff_aid
    if client is None:
        env_url = os.environ.get("ARENA_URL", "").strip() or PUBLIC_TESTNET_URL
        http_client = ArenaHttpClient(
            base_url=env_url,
            api_key=os.environ.get("ARENA_API_KEY") or None,
            api_secret=os.environ.get("ARENA_API_SECRET") or None,
            timeout=10.0,
        )
    else:
        http_client = client
    env_aid_raw = os.environ.get("ARENA_ACCOUNT_ID", "0").strip() or "0"
    eff_aid = int(account_id) if int(account_id) > 0 else int(env_aid_raw)
    adapter = ArenaCcxtAdapter(http_client, account_id=eff_aid)
    adapter.http.close()
    adapter.http = http_client
    return http_client, adapter, eff_aid


def _build_core_agent_tools(
    client: Optional[ArenaHttpClient] = None,
    account_id: int = 0,
) -> List[Tuple[Callable[..., Dict[str, Any]], str, str]]:
    http_client, adapter, default_account_id = _resolve_agent_http_and_adapter(
        client=client,
        account_id=account_id,
    )

    def list_markets(kind: str = "", active_only: bool = True) -> Dict[str, Any]:
        """List FeraTerra / Arena Exchange markets with unified symbols, USD mark prices, and BBOs."""
        resp = http_client.markets()
        if not resp.get("ok"):
            raise RuntimeError(f"GET /markets failed: {resp}")
        kind_filter = _canonical_market_kind(kind)
        markets_out: List[Dict[str, Any]] = []
        for m in list(resp.get("markets", [])):
            if kind_filter and _canonical_market_kind(m.get("kind", "")) != kind_filter:
                continue
            if active_only and str(m.get("trading_status", "live")).lower() == "halted":
                continue
            item = dict(m)
            item["unified_symbol"] = adapter._unified_symbol_for_market(m)
            item["mark_price_usd"] = price_ticks_to_usd_str(int(m.get("mark_price_ticks", 0)))
            item["best_bid_usd"] = price_ticks_to_usd_str(int(m.get("best_bid_ticks", 0)))
            item["best_ask_usd"] = price_ticks_to_usd_str(int(m.get("best_ask_ticks", 0)))
            markets_out.append(item)
        return {
            "ok": True,
            "wal_seq": int(resp.get("wal_seq", 0)),
            "count": len(markets_out),
            "markets": markets_out,
        }

    def get_orderbook(
        symbol: str = "BTC/USD:USD",
        market_id: int = 0,
        depth: int = 20,
    ) -> Dict[str, Any]:
        """Fetch live L2/L3 order book snapshot by unified/native symbol or integer market_id."""
        target: str | int = int(market_id) if int(market_id) > 0 else (str(symbol or "").strip() or 1)
        mkt = adapter.resolve_market(target)
        mid = int(mkt["market_id"])
        eff_depth = max(1, min(200, int(depth)))
        book = http_client.book(mid, depth=eff_depth)
        if not book.get("ok"):
            raise RuntimeError(f"GET /book failed: {book}")
        out = dict(book)
        out["unified_symbol"] = adapter._unified_symbol_for_market(mkt)
        return out

    def get_leaderboard(limit: int = 25, sort: str = "equity") -> Dict[str, Any]:
        """Fetch the ranked Gladiator Leaderboard sorted by equity, pnl, streak, volume, or roi."""
        eff_limit = max(1, min(100, int(limit)))
        eff_sort = str(sort or "equity").strip().lower() or "equity"
        resp = http_client.get_leaderboard(limit=eff_limit, sort=eff_sort)
        if not resp.get("ok"):
            raise RuntimeError(f"GET /leaderboard failed: {resp}")
        return resp

    def preview_order(
        symbol: str = "BTC/USD:USD",
        order_type: str = "limit",
        side: str = "buy",
        amount: float = 0.01,
        price: Optional[float] = None,
        reduce_only: bool = False,
        post_only: bool = False,
        account_id: int = 0,
    ) -> Dict[str, Any]:
        """Run a stateless zero-mutation dry-run order simulation returning fill, fee, and Eigen-SPAN margin impact."""
        eff_aid = int(account_id) if int(account_id) > 0 else int(default_account_id or adapter.account_id)
        return adapter.preview_order(
            symbol=symbol,
            order_type=order_type,
            side=side,
            amount=amount,
            price=price,
            params={
                "account_id": eff_aid,
                "reduceOnly": bool(reduce_only),
                "postOnly": bool(post_only),
            },
        )

    def verify_ledger_tip(expected_operator_address: str = "") -> Dict[str, Any]:
        """Fetch `GET /ledger/tip` and cryptographically verify its Keccak-256 + secp256k1 operator signature."""
        tip = http_client.ledger_tip()
        if not tip.get("ok", True) and "wal_seq" not in tip:
            raise RuntimeError(f"GET /ledger/tip failed: {tip}")
        pinned = str(expected_operator_address or "").strip()
        verified = _arena_verify_ledger_tip(
            tip,
            expected_operator_address=pinned,
            allow_self_asserted_signer=(not bool(pinned)),
        )
        out = dict(tip)
        out["signature_verified"] = bool(verified)
        out["pinned_operator_checked"] = bool(pinned)
        return out

    return [
        (list_markets, "list_markets", list_markets.__doc__ or ""),
        (get_orderbook, "get_orderbook", get_orderbook.__doc__ or ""),
        (get_leaderboard, "get_leaderboard", get_leaderboard.__doc__ or ""),
        (preview_order, "preview_order", preview_order.__doc__ or ""),
        (verify_ledger_tip, "verify_ledger_tip", verify_ledger_tip.__doc__ or ""),
    ]


def create_langchain_tools(
    client: Optional[ArenaHttpClient] = None,
    account_id: int = 0,
) -> list:
    """Wrap the 5 core FeraTerra / Arena Exchange tools as LangChain `StructuredTool` instances."""
    try:
        from langchain_core.tools import StructuredTool  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "Install langchain-core: pip install 'feraterra-sdk[langchain]'"
        ) from exc

    tool_defs = _build_core_agent_tools(client=client, account_id=account_id)
    tools_out: list = []
    for fn, name, description in tool_defs:
        if hasattr(StructuredTool, "from_function"):
            tools_out.append(
                StructuredTool.from_function(func=fn, name=name, description=description)
            )
        else:
            tools_out.append(StructuredTool(name=name, description=description, func=fn))
    return tools_out


def create_pydantic_ai_toolset(
    client: Optional[ArenaHttpClient] = None,
    account_id: int = 0,
) -> Any:
    """Wrap the 5 core FeraTerra / Arena Exchange tools in a PydanticAI `FunctionToolset` (or `Tool` list fallback)."""
    function_toolset_cls: Any = None
    pydantic_tool_cls: Any = None
    try:
        from pydantic_ai.toolsets import FunctionToolset as _FT  # type: ignore[import-not-found]

        function_toolset_cls = _FT
    except ImportError:
        try:
            from pydantic_ai import Tool as _PT  # type: ignore[import-not-found]

            pydantic_tool_cls = _PT
        except ImportError as exc:
            raise ImportError(
                "Install pydantic-ai: pip install 'feraterra-sdk[pydantic-ai]'"
            ) from exc

    tool_defs = _build_core_agent_tools(client=client, account_id=account_id)
    funcs = [fn for fn, _name, _desc in tool_defs]
    if function_toolset_cls is not None:
        try:
            return function_toolset_cls(funcs)
        except TypeError:
            ts = function_toolset_cls()
            for fn, name, description in tool_defs:
                if hasattr(ts, "add_function"):
                    ts.add_function(fn, name=name, description=description)
                elif hasattr(ts, "tool_plain"):
                    ts.tool_plain(fn)
                elif hasattr(ts, "tool"):
                    ts.tool(fn)
            return ts

    tools_out: List[Any] = []
    for fn, name, description in tool_defs:
        try:
            tools_out.append(
                pydantic_tool_cls(fn, takes_ctx=False, name=name, description=description)
            )
        except TypeError:
            tools_out.append(pydantic_tool_cls(fn))
    return tools_out


_REEXPORTED_NAMES: List[str] = [
    _name for _name in vars(_arena_sdk).keys() if not _name.startswith("_")
]
__all__: List[str] = list(
    dict.fromkeys(
        [
            "__version__",
            *_REEXPORTED_NAMES,
            "create_langchain_tools",
            "create_pydantic_ai_toolset",
        ]
    )
)


def _run_self_test() -> int:
    import types
    import typing

    # 1. Verify full re-export surface & __all__
    for sym in (
        "__version__",
        "ArenaHttpClient",
        "ArenaCcxtAdapter",
        "ArenaBinaryClient",
        "ArenaWsClient",
        "ArenaItchClient",
        "EthWalletSigner",
        "EvmJsonRpcClient",
        "verify_ledger_tip",
        "PUBLIC_TESTNET_URL",
        "create_langchain_tools",
        "create_pydantic_ai_toolset",
    ):
        if sym not in __all__ or sym not in globals():
            print(f"[FAIL] Missing exported symbol {sym} in feraterra_sdk", file=sys.stderr)
            return 1

    # 2. Build mock ArenaHttpClient + cryptographically valid ledger tip
    op_signer = EthWalletSigner("0x" + ("22" * 32))
    chain_hash = "0x" + ("aa" * 32)
    state_root = "0x" + ("bb" * 32)
    ch_addr = "0x1111111111111111111111111111111111111111"
    tip_digest = compute_ledger_tip_digest(
        42, chain_hash, state_root, chain_id=84532, clearinghouse_address=ch_addr
    )
    tip_sig = op_signer.sign_digest(tip_digest)

    cli = ArenaHttpClient("http://127.0.0.1:8080", timeout=5.0)
    try:
        cli.markets = lambda: {  # type: ignore[method-assign]
            "ok": True,
            "wal_seq": 42,
            "markets": [
                {
                    "market_id": 1,
                    "symbol": "BTC-USD-PERP",
                    "kind": "linear_perpetual",
                    "trading_status": "live",
                    "base_asset_id": 1,
                    "max_order_lots": 100_000,
                    "min_price_ticks": 1,
                    "max_price_ticks": 100_000_000,
                    "mark_price_ticks": 7_000_000,
                    "best_bid_ticks": 6_999_500,
                    "best_ask_ticks": 7_000_500,
                }
            ],
        }
        cli.book = lambda market_id=1, depth=20, include_l3=True: {  # type: ignore[method-assign]
            "ok": True,
            "wal_seq": 42,
            "market_id": market_id,
            "depth": depth,
            "bids": [[6_999_500, 10_000, 1]],
            "asks": [[7_000_500, 10_000, 1]],
        }
        cli.get_leaderboard = lambda limit=25, sort="equity", **kw: {  # type: ignore[method-assign]
            "ok": True,
            "wal_seq": 42,
            "sort_by": sort,
            "entries": [{"rank": 1, "account_id": 77, "equity_usd": "12500.00"}],
        }
        cli.preview_order = lambda **kw: {  # type: ignore[method-assign]
            "ok": True,
            "would_accept": True,
            "status": "Ok",
            "effective_price_ticks": kw["price_ticks"],
            "estimated_filled_lots": 0,
            "estimated_resting_lots": kw["qty_lots"],
            "estimated_avg_price_ticks": 0,
            "estimated_fee_micro": 0,
            "pre_imr_micro": 0,
            "post_imr_micro": 35_000_000,
            "post_free_margin_micro": 965_000_000,
            "wal_seq": 42,
        }
        cli.ledger_tip = lambda: {  # type: ignore[method-assign]
            "ok": True,
            "tip_domain": "ARENA_LEDGER_TIP_V2_1",
            "chain_id": 84532,
            "clearinghouse_address": ch_addr,
            "wal_seq": 42,
            "ledger_chain_hash": chain_hash,
            "state_root": state_root,
            "tip_digest": "0x" + tip_digest.hex(),
            "operator_eth_address": op_signer.address,
            "operator_signature": tip_sig,
        }

        core_defs = _build_core_agent_tools(cli, account_id=77)
        expected_names = [
            "list_markets",
            "get_orderbook",
            "get_leaderboard",
            "preview_order",
            "verify_ledger_tip",
        ]
        if [n for _fn, n, _d in core_defs] != expected_names:
            print(f"[FAIL] Core tool names mismatch: {[n for _, n, _ in core_defs]}", file=sys.stderr)
            return 1
        for fn, name, _desc in core_defs:
            hints = typing.get_type_hints(fn)
            if "return" not in hints:
                print(f"[FAIL] Missing resolved type hints on {name}: {hints}", file=sys.stderr)
                return 1

        # 3. Verify friendly ImportError when optional packages are absent
        saved_mods = {
            k: sys.modules.get(k, ...)
            for k in ("langchain_core", "langchain_core.tools", "pydantic_ai", "pydantic_ai.toolsets")
        }
        try:
            for k in saved_mods:
                sys.modules[k] = None  # type: ignore[assignment]

            caught_lc = False
            try:
                _ = create_langchain_tools(cli, account_id=77)
            except ImportError as exc:
                caught_lc = str(exc) == "Install langchain-core: pip install 'feraterra-sdk[langchain]'"
            if not caught_lc:
                print("[FAIL] create_langchain_tools did not raise expected ImportError message", file=sys.stderr)
                return 1

            caught_pai = False
            try:
                _ = create_pydantic_ai_toolset(cli, account_id=77)
            except ImportError as exc:
                caught_pai = "pydantic-ai" in str(exc)
            if not caught_pai:
                print("[FAIL] create_pydantic_ai_toolset did not raise expected ImportError", file=sys.stderr)
                return 1

            # 4. Verify create_langchain_tools & create_pydantic_ai_toolset (both FunctionToolset & Tool fallback)
            lc_pkg = types.ModuleType("langchain_core")
            lc_tools_mod = types.ModuleType("langchain_core.tools")

            class _FakeStructuredTool:
                def __init__(self, func: Any, name: str, description: str) -> None:
                    self.func = func
                    self.name = name
                    self.description = description

                @classmethod
                def from_function(cls, func: Any, name: str = "", description: str = "") -> "_FakeStructuredTool":
                    return cls(func=func, name=name or func.__name__, description=description)

            lc_tools_mod.StructuredTool = _FakeStructuredTool  # type: ignore[attr-defined]
            lc_pkg.tools = lc_tools_mod  # type: ignore[attr-defined]
            sys.modules["langchain_core"] = lc_pkg
            sys.modules["langchain_core.tools"] = lc_tools_mod

            lc_tools = create_langchain_tools(cli, account_id=77)
            if [t.name for t in lc_tools] != expected_names:
                print(f"[FAIL] create_langchain_tools names mismatch: {[t.name for t in lc_tools]}", file=sys.stderr)
                return 1
            by_name = {t.name: t.func for t in lc_tools}
            if by_name["list_markets"]()["count"] != 1:
                print("[FAIL] list_markets execution failed", file=sys.stderr)
                return 1
            if by_name["get_orderbook"](symbol="BTC/USD:USD", depth=5)["unified_symbol"] != "BTC/USD:USD":
                print("[FAIL] get_orderbook execution failed", file=sys.stderr)
                return 1
            if by_name["get_leaderboard"](limit=5, sort="pnl")["sort_by"] != "pnl":
                print("[FAIL] get_leaderboard execution failed", file=sys.stderr)
                return 1
            prev_out = by_name["preview_order"](symbol="BTC/USD:USD", side="buy", amount=0.01, price=68000.0)
            if not prev_out["wouldAccept"] or abs(float(prev_out["marginDeltaUsd"]) - 35.0) > 1e-9:
                print(f"[FAIL] preview_order execution failed: {prev_out}", file=sys.stderr)
                return 1
            tip_out = by_name["verify_ledger_tip"](expected_operator_address=op_signer.address)
            if not tip_out["signature_verified"] or not tip_out["pinned_operator_checked"]:
                print(f"[FAIL] verify_ledger_tip execution failed: {tip_out}", file=sys.stderr)
                return 1

            # PydanticAI FunctionToolset path
            pai_pkg = types.ModuleType("pydantic_ai")
            pai_ts_mod = types.ModuleType("pydantic_ai.toolsets")

            class _FakeFunctionToolset:
                def __init__(self, tools: Any = ()) -> None:
                    self.tools = {fn.__name__: fn for fn in tools}

            pai_ts_mod.FunctionToolset = _FakeFunctionToolset  # type: ignore[attr-defined]
            sys.modules["pydantic_ai"] = pai_pkg
            sys.modules["pydantic_ai.toolsets"] = pai_ts_mod
            ts_obj = create_pydantic_ai_toolset(cli, account_id=77)
            if list(ts_obj.tools.keys()) != expected_names:
                print(f"[FAIL] FunctionToolset tools mismatch: {list(ts_obj.tools.keys())}", file=sys.stderr)
                return 1

            # PydanticAI legacy Tool fallback path
            sys.modules["pydantic_ai.toolsets"] = None  # type: ignore[assignment]

            class _FakePydanticTool:
                def __init__(self, fn: Any, takes_ctx: bool = False, name: str = "", description: str = "") -> None:
                    self.function = fn
                    self.takes_ctx = takes_ctx
                    self.name = name or fn.__name__
                    self.description = description

            pai_pkg.Tool = _FakePydanticTool  # type: ignore[attr-defined]
            fallback_tools = create_pydantic_ai_toolset(cli, account_id=77)
            if [t.name for t in fallback_tools] != expected_names:
                print(f"[FAIL] pydantic_ai.Tool fallback mismatch: {[t.name for t in fallback_tools]}", file=sys.stderr)
                return 1
        finally:
            for k, orig in saved_mods.items():
                if orig is ...:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = orig  # type: ignore[assignment]
    finally:
        cli.close()

    # Make sure module-level verify_ledger_tip was not shadowed
    if verify_ledger_tip is not _arena_sdk.verify_ledger_tip:
        print("[FAIL] verify_ledger_tip re-export identity broken", file=sys.stderr)
        return 1

    print("[PASS] feraterra_sdk.py self-test OK")
    return 0


if __name__ == "__main__":
    import argparse

    _ap = argparse.ArgumentParser(description="FeraTerra / Arena Exchange Official Python SDK")
    _ap.add_argument("--self-test", action="store_true", help="Run deterministic offline SDK self-test")
    _args = _ap.parse_args()
    if _args.self_test:
        raise SystemExit(_run_self_test())
    _ap.print_help()
    raise SystemExit(0)
