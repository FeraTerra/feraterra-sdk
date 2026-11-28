# `feraterra-wire` (`v4.9.5`)

Zero-dependency `#![no_std]` Rust `1.75+` codec for the **FeraTerra / Arena Exchange** (`https://feraterra.app`, public Base Sepolia testnet `https://testnet.feraterra.app`) 64-byte big-endian `ArenaWire` order-entry protocol, `ArenaITCH` v1 L3 market-data feed, and `ARENA_LEDGER_TIP_V2_1` `Keccak-256` Sovereign Ledger Tip verifier.

## Features

- **`#![no_std]` & Zero Dependencies:** Pure `const fn` Rust (`edition = "2021"`, `rust-version = "1.75"`, `[dependencies] = {}`) suitable for kernel-bypass HFT engines, embedded hardware, and WebAssembly guests.
- **64-Byte `ArenaWire` v1 Order-Entry Codec (`#[repr(C, align(64))]`):**
  - Dual SipHash-2-4 authentication (`PreSipHash40` header MAC + `TailSipHash48` payload MAC).
  - Single-leg orders (`OrderAux1Params`: `post_only_slide`, `mark_peg`, `trailing_peg`, `dark_midpoint`, `jit_elastic_mult`; plus cross-socket priority fee `priority_fee_ppm` packed in `bytes[52..=53]` via `pack_order_ext_priority_fee_ppm` rather than a field on `OrderAux1Params`).
  - Atomic two-sided market-maker quotes (`TwoSidedQuoteReplace` with 50-bit extended `ask_qty_lots`, `quote_peg_mode`, `client_tag`, and `ladder_by_tag`).
  - Atomic 2-, 3-, and 4-leg FOK spreads and baskets (`AtomicSpread`, `WireBasketLeg`, `try_pack_wire_basket_frame`, `unpack_wire_basket_legs34`, `unpack_wire_basket_frame`).
  - SipHash-2-4 stream-encrypted session key rotation (`pack_encrypted_register_session_key_frame`, `unpack_register_session_key_wire`).
  - 64-byte `ArenaWireResponse` encoder/decoder including split bid/ask quote fills.
- **64-Byte `ArenaITCH` v1 L3 Market-Data Codec:**
  - SipHash-2-4 integrity-checked `ArenaItchFrame` / `ArenaItchMessage` (`OrderAdded`, `OrderExecuted`, `OrderModified`, `OrderDeleted`, `MarkAndFunding`, `SnapshotBegin`/`SnapshotOrder`/`SnapshotEnd`, `LedgerCheckpoint`, `MarketDirectory`) and 16-byte `ArenaItchSubscribeReq` gap-recovery requests.
- **Compile-Time `Keccak-256` & `ARENA_LEDGER_TIP_V2_1` Commitment Digest:**
  - `const fn keccak256(&[u8]) -> [u8; 32]`, `sovereign_ledger_genesis_hash()`, and `compute_ledger_tip_digest(...)` matching `GET https://testnet.feraterra.app/ledger/tip`.

## Fixed-Point Scales

| Quantity | Integer Unit | Scale |
| :--- | :--- | :--- |
| **Price** | `1 tick = $0.01` | `100` ticks = `$1.00` |
| **Order / Position Size** | `1 lot = 1e-4` base | `10_000` lots = `1.0` base |
| **USD Collateral / Fees** | `1 micro = $1e-6` | `1_000_000` micro = `$1.00` |

## Quickstart

```toml
[dependencies]
feraterra-wire = "4.9.5"
```

```rust
use feraterra_wire::{
    compute_ledger_tip_digest, keccak256, pack_wire_frame, try_pack_wire_basket_frame,
    unpack_and_verify_wire_frame, unpack_wire_basket_legs34, ArenaFlags, ArenaHeader, BaseOp,
    OrderSide, StpMode, TimeInForce, WireBasketLeg, DEFAULT_DEV_KEY_HI64, DEFAULT_DEV_KEY_LO64,
    ORDER_AUX_FLAG_POST_ONLY_SLIDE,
};

// 1) Pack & verify a 64-byte PostOnly NewOrder frame
let hdr = ArenaHeader {
    op: BaseOp::NewOrder,
    flags: ArenaFlags::new(TimeInForce::PostOnly, StpMode::CancelResting),
    market_id: 1,
    account_id: 1001,
    side: OrderSide::Bid,
    seq_lo: 1,
    price_ticks: 5_000_000, // $50,000.00
    qty_lots: 10_000,       // 1.0000 BTC
};
let frame = pack_wire_frame(
    &hdr,
    42,
    ORDER_AUX_FLAG_POST_ONLY_SLIDE,
    1,
    DEFAULT_DEV_KEY_LO64,
    DEFAULT_DEV_KEY_HI64,
);
let verified = unpack_and_verify_wire_frame(
    &frame,
    1,
    DEFAULT_DEV_KEY_LO64,
    DEFAULT_DEV_KEY_HI64,
)
.unwrap();
assert_eq!(verified.header, hdr);

// 2) Pack & unpack a 3-leg atomic FOK basket in a single 64-byte wire frame
let legs = [
    WireBasketLeg::new(1, OrderSide::Bid, 5_000_000, 10_000),
    WireBasketLeg::new(2, OrderSide::Ask, 300_000, 150_000),
    WireBasketLeg::new(17, OrderSide::Bid, -1_250, 25_000),
];
let basket_frame = try_pack_wire_basket_frame(
    1001,
    &legs,
    StpMode::CancelIncoming,
    true,
    7,
    1,
    DEFAULT_DEV_KEY_LO64,
    DEFAULT_DEV_KEY_HI64,
)
.unwrap();
let unpacked_basket = unpack_and_verify_wire_frame(
    &basket_frame,
    1,
    DEFAULT_DEV_KEY_LO64,
    DEFAULT_DEV_KEY_HI64,
)
.unwrap();
let (num_legs, leg3, _leg4) = unpack_wire_basket_legs34(&basket_frame, unpacked_basket.aux_param1);
assert_eq!(num_legs, 3);
assert_eq!(leg3.market_id, 17);
assert_eq!(leg3.price_ticks, -1_250);

// 3) Compute ARENA_LEDGER_TIP_V2_1 Keccak-256 digest (const-evaluatable)
let chain_hash = keccak256(b"ARENA_SOVEREIGN_LEDGER_GENESIS_V2_0");
let state_root = keccak256(b"state_root");
let clearinghouse = [0x11u8; 20];
let digest = compute_ledger_tip_digest(100, &chain_hash, &state_root, 84532, Some(&clearinghouse));
assert_eq!(digest.len(), 32);
```

## Endpoints & Specification

- **Network Directory:** `https://feraterra.app`
- **Public Base Sepolia Testnet:** `https://testnet.feraterra.app` (`wss://testnet.feraterra.app/ws`)
- **Machine-Readable Protocol Spec:** `https://testnet.feraterra.app/llms.txt`
- **Remote Streamable HTTP MCP:** `https://mcp.feraterra.app/mcp`

## License

MIT (`Copyright (c) 2026 FeraTerra`).
