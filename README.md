<!-- mcp-name: io.github.FeraTerra/feraterra-sdk -->
# Arena Exchange — Official Headless Client SDK & MCP Gateway (`v4.9.2`)

Zero-dependency client connectors and 24-tool MCP gateway for trading on **Arena Exchange** (`feraterra.app`) — a 100% headless computational venue with **0 bps maker fees** (maker rebates on segmented venues), cross-margined Spot/Perps/FormulaPerps/BoundedClaims/SpreadBooks, stateless `POST /order/preview` margin dry-runs, `$0`-capital atomic flash arbitrage & liquidation bounties, live Gladiator Leaderboard (`GET /leaderboard`), and non-custodial L2 `Clearinghouse` Merkle-escape solvency.

- **Public Base Sepolia Testnet HTTPS:** `https://testnet.feraterra.app`
- **Public Base Sepolia Testnet WebSocket:** `wss://testnet.feraterra.app/ws`
- **AI Discovery & OpenAPI 3.1:** `https://testnet.feraterra.app/llms.txt` | `https://testnet.feraterra.app/openapi.json`
- **Gladiator Leaderboard:** `https://testnet.feraterra.app/leaderboard`

## Bundle Contents (14 Files)

| Path | Purpose |
| :--- | :--- |
| `sdk/python/arena_sdk.py` | Pure Python 3 stdlib client (`ArenaHttpClient`, `ArenaWsClient`, `ArenaBinaryClient`, `ArenaItchClient`, `ArenaCcxtAdapter`, `EthWalletSigner`, `EvmJsonRpcClient`, `testnet()` presets, `get_leaderboard()` & Merkle/Ledger verifiers) |
| `sdk/python/arena_mcp_server.py` | Packaged 24-tool MCP gateway module exposing `feraterra-mcp`, `feraterra-sdk`, `arena-mcp`, and `arena-sdk` CLI entry points |
| `include/arena_wire.hpp` | Canonical 64-byte `ArenaWireFrame` & `ArenaITCH` C++23 wire layout (`static_assert(sizeof == 64)`) |
| `include/arena_hft_client.hpp` | Header-only C++23 HFT TCP/UDP/ITCH client (`namespace arena::sdk`, `PUBLIC_TESTNET_HTTPS_URL`) |
| `scripts/arena_mcp_server.py` | 24-tool MCP JSON-RPC 2.0 `stdio` & Streamable HTTP (`POST /mcp`, `GET /mcp/health`) gateway script |
| `abi/Clearinghouse.abi.json` | L2 `Clearinghouse` ABI (`depositTraderMargin`, `claimWithdrawalVoucher`, `claimMerkleEmergencyEscape`, `depositPolicyConfig`) |
| `examples/quickstart_ccxt_and_preview.py` | Client-side AI discovery (`GET /llms.txt`, `GET /openapi.json`), EIP-191 wallet login, CCXT `camelCase` & `POST /order/preview` dry-run |
| `examples/algo_two_sided_quoter.py` | Client-side Market-Maker Protection (`MMP`) + inventory-skewed atomic two-sided quote replacement starter |
| `examples/ai_agent_zero_capital_scanner.py` | Client-side zero-capital atomic flash-arbitrage (`POST /flash_arb`) & auto-liquidation bounty scanner |
| `pyproject.toml` | Zero-dependency PEP 621 package manifest (`pip install feraterra-sdk` / `pip install .`) |
| `server.json` | Official MCP Registry manifest (`io.github.FeraTerra/feraterra-sdk`) |
| `.gitignore` | Clean repository ignore rules for Python bytecode, venvs, and local key files |
| `README.md` | Public trader, quant & AI-agent quickstart guide |
| `LICENSE` | MIT license for public client connectors |

## Quickstart

### 1. Install & Machine-Readable AI Discovery

```bash
pip install feraterra-sdk

# Launch the 24-tool MCP gateway directly (via pip or uvx):
arena-mcp --testnet
# or:
uvx feraterra-sdk --testnet
```

For single-click MCP clients and the Official MCP Registry (`io.github.FeraTerra/feraterra-sdk`), a zero-dependency MCP Bundle (`arena-sdk.mcpb`) is also attached to every GitHub Release (`https://github.com/FeraTerra/feraterra-sdk/releases/download/v4.9.2/feraterra-sdk.mcpb`).

Point any LLM, autonomous agent, or HTTP client at `https://testnet.feraterra.app` (or local `http://127.0.0.1:8088`):

- `GET /llms.txt` — Concise machine-readable protocol specification, fixed-point scales (`1 tick = $0.01`, `1 lot = 1e-4` base, `1 micro = $1e-6`), EIP-191 auth flow, and zero-capital endpoints.
- `GET /openapi.json` — Full OpenAPI `3.1.0` JSON schema for automatic tool/client generation.
- `GET /leaderboard` — Live Gladiator Leaderboard ranking active wallets (masked `0x1234...abcd`) by equity, PnL, maker BBO streak, volume, or ROI.
- `GET /faucet/status` — Base Sepolia (`chain_id=84532`) `Clearinghouse` contract address, collateral token address, and faucet limits.

### 2. One-Line Public Testnet Onboarding, Faucet, L2 Deposit & CCXT Adapter

```python
from arena_sdk import ArenaHttpClient, ArenaCcxtAdapter, EthWalletSigner

client = ArenaHttpClient.testnet()  # https://testnet.feraterra.app

# 1) Generate a local secp256k1 wallet & authenticate via EIP-191 (no browser or KYC)
signer = EthWalletSigner()
login = client.login_with_wallet(signer)
account_id = int(login["account_id"])

# 2) Optional: mint Base Sepolia testnet USDC + L2 gas drip, then deposit on-chain
# client.request_testnet_faucet(signer.address, amount="10000", asset="USD", drip_gas=True)
# client.deposit_onchain_margin(signer, "10000", account_id=account_id, wait_for_credit=True)

# 3) Drop-in CCXT camelCase adapter + stateless pre-trade margin/fill simulation (zero WAL mutation)
exchange = ArenaCcxtAdapter(client, account_id=account_id)
markets = exchange.loadMarkets()
print("BTC Perp   :", markets["BTC/USD:USD"]["symbol"])
print("Preview    :", exchange.previewOrder("BTC/USD:USD", "limit", "buy", "0.0100", "50000.00", {"postOnly": True}))
print("Leaderboard:", exchange.fetchLeaderboard(limit=5, sort="equity")[:3])
```

### 3. Autonomous AI Agent 24-Tool MCP Server (`stdio` & Streamable HTTP)

**Claude Desktop / Cursor / Windsurf (`mcpServers` JSON via `uvx` or `arena-mcp`):**

```json
{
  "mcpServers": {
    "arena-exchange": {
      "command": "uvx",
      "args": [
        "arena-sdk",
        "--testnet",
        "--max-order-notional-usd",
        "5000"
      ]
    }
  }
}
```

Inside the agent session, call `arena_onboard_and_deposit` (`generate_ephemeral=true`) to provision a wallet, mint testnet collateral + gas, and deposit margin in a single tool call, `arena_get_leaderboard` to check live Gladiator standings, or run Streamable HTTP mode for remote agents:

```bash
arena-mcp --testnet --http-listen-port 8765 --http-bearer-token "$MCP_SECRET"
```

### 4. C++23 Header-Only 64-Byte HFT Wire & ArenaITCH Client

Compile directly against `-Iinclude` with `-std=c++23` (when connected to direct/colocated TCP `19100`, UDP `19101`, and `ArenaITCH` L3 `19102` ports; `https://testnet.feraterra.app` exposes HTTPS REST + `wss://testnet.feraterra.app/ws` WebSockets):

```cpp
#include "arena_hft_client.hpp"
static_assert(sizeof(arena::wire::ArenaWireFrame) == 64);
```

### 5. Starter Bots & Self-Tests (`examples/`)

```bash
# Offline deterministic self-tests:
python sdk/python/arena_sdk.py --self-test
python scripts/arena_mcp_server.py --self-test
python examples/quickstart_ccxt_and_preview.py --self-test

# Live dry-run & execution against the public Base Sepolia testnet:
python examples/quickstart_ccxt_and_preview.py --testnet
python examples/quickstart_ccxt_and_preview.py --testnet --execute
python examples/algo_two_sided_quoter.py --testnet
python examples/algo_two_sided_quoter.py --testnet --live
python examples/ai_agent_zero_capital_scanner.py --testnet
python examples/ai_agent_zero_capital_scanner.py --testnet --live
```
