#![no_std]
#![allow(clippy::too_many_arguments, clippy::upper_case_acronyms)]

//! Zero-dependency `#![no_std]` 64-byte big-endian `ArenaWire` and `ArenaITCH` HFT binary
//! protocol codec for FeraTerra, authenticated by dual SipHash-2-4 MACs (`PreSipHash40`
//! header MAC + `TailSipHash48` payload MAC) and 64-bit SipHash-2-4 L3 market-data checksums.
//!
//! # Quick Start
//!
//! ```
//! use feraterra_wire::{
//!     pack_wire_frame, unpack_and_verify_wire_frame, ArenaFlags, ArenaHeader, BaseOp, OrderSide,
//!     StpMode, TimeInForce, DEFAULT_DEV_KEY_HI64, DEFAULT_DEV_KEY_LO64,
//!     ORDER_AUX_FLAG_POST_ONLY_SLIDE,
//! };
//!
//! let hdr = ArenaHeader {
//!     op: BaseOp::NewOrder,
//!     flags: ArenaFlags::new(TimeInForce::PostOnly, StpMode::CancelResting),
//!     market_id: 1,
//!     account_id: 1001,
//!     side: OrderSide::Bid,
//!     seq_lo: 1,
//!     price_ticks: 5_000_000,
//!     qty_lots: 10_000,
//! };
//! let frame = pack_wire_frame(
//!     &hdr,
//!     42,
//!     ORDER_AUX_FLAG_POST_ONLY_SLIDE,
//!     1,
//!     DEFAULT_DEV_KEY_LO64,
//!     DEFAULT_DEV_KEY_HI64,
//! );
//! let decoded = unpack_and_verify_wire_frame(
//!     &frame,
//!     1,
//!     DEFAULT_DEV_KEY_LO64,
//!     DEFAULT_DEV_KEY_HI64,
//! )
//! .unwrap();
//! assert_eq!(decoded.header, hdr);
//! assert_eq!(decoded.aux_param0, 42);
//! ```

// =============================================================================
// Core Protocol Constants
// =============================================================================

pub const ARENA_WIRE_BITS: usize = 512;
pub const ARENA_WIRE_BYTES: usize = 64;
pub const ARENA_WIRE_VERSION: u8 = 0x01;
pub const ARENA_WIRE_TRAILER: [u8; 2] = [0xA1, 0xE0];

pub const DEFAULT_DEV_KEY_LO64: u64 = 0x0123_4567_89AB_CDEF;
pub const DEFAULT_DEV_KEY_HI64: u64 = 0xCAFE_BABE_DEAD_BEEF;

pub const MAX_WIRE_ACCOUNT_ID: u32 = 0x00FF_FFFF;
pub const MAX_WIRE_HEADER_QTY_LOTS: u64 = 0x0000_00FF_FFFF_FFFF;
pub const MAX_WIRE_EXT_QTY_LOTS: u64 = 0x0003_FFFF_FFFF_FFFF;
pub const MIN_WIRE_PRICE_TICKS_48: i64 = -(1i64 << 47);
pub const MAX_WIRE_PRICE_TICKS_48: i64 = (1i64 << 47) - 1;

// `NewOrder` `aux_param1` bit layout
pub const ORDER_AUX_FLAG_REDUCE_ONLY: u64 = 0x0000_0000_0000_0001;
pub const ORDER_AUX_FLAG_MARKET: u64 = 1u64 << 1;
pub const ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT: u64 = 1u64 << 2;
pub const ORDER_AUX_FLAG_POST_ONLY_SLIDE: u64 = 1u64 << 3;
pub const ORDER_AUX_FLAG_PRIMARY_PEG: u64 = 1u64 << 4;
pub const ORDER_AUX_FLAG_MIDPOINT_PEG: u64 = 1u64 << 5;
pub const ORDER_AUX_FLAG_MARK_PEG_COMBO: u64 =
    ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG;
pub const ORDER_AUX_FLAG_MARGIN_SPOT: u64 = 1u64 << 6;
pub const ORDER_AUX_FLAG_ICEBERG: u64 = 1u64 << 7;
pub const ORDER_AUX_FLAG_TRAILING_PEG: u64 =
    ORDER_AUX_FLAG_MARK_PEG_COMBO | ORDER_AUX_FLAG_ICEBERG;
pub const ORDER_AUX_AUTO_SKEW_SHIFT: u32 = 8;
pub const ORDER_AUX_AUTO_SKEW_MASK: u64 = 0x03FF;
pub const ORDER_AUX_AUTO_FLIP_BIT: u64 = 0x0200;
pub const ORDER_AUX_PEG_OFFSET_MASK: u64 = 0x03FF;
pub const ORDER_AUX_FLAG_OCO_LINKED: u64 = 1u64 << 18;
pub const ORDER_AUX_FLAG_GTS_EXPIRY: u64 = 1u64 << 19;
pub const ORDER_AUX_JIT_MULT_SHIFT: u32 = 20;
pub const ORDER_AUX_JIT_MULT_MASK: u64 = 0x0F;
pub const ORDER_AUX_MIN_QTY_SHIFT: u32 = 24;
pub const ORDER_AUX_MIN_QTY_MASK: u64 = 0x0000_00FF_FFFF_FFFF;
pub const ORDER_AUX_MIN_QTY_GTS_MASK: u64 = 0x0000_0000_00FF_FFFF;
pub const ORDER_AUX_GTS_SHIFT: u32 = 48;
pub const ORDER_AUX_GTS_MASK: u64 = 0xFFFF;

// `TwoSidedQuoteReplace` `aux_param1` and 50-bit extended `ask_qty_lots` layout
pub const QUOTE_AUX_QTY_MASK: u64 = 0x0000_0007_FFFF_FFFF;
pub const QUOTE_AUX_HI16_SHIFT: u32 = 35;
pub const QUOTE_AUX_QTY_50_MASK: u64 = 0x0003_FFFF_FFFF_FFFF;
pub const QUOTE_EXT_QTY_MAX: u64 = 0x0003_FFFF_FFFF_FFFF;
pub const QUOTE_AUX_FLAG_PEG_ACTIVE: u64 = 1u64 << 35;
pub const QUOTE_AUX_PEG_MODE_SHIFT: u32 = 62;
pub const QUOTE_AUX_PEG_MODE_MASK: u64 = 0x03;
pub const QUOTE_AUX_JIT_MULT_SHIFT: u32 = 36;
pub const QUOTE_AUX_JIT_MULT_MASK: u64 = 0x0F;
pub const QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT: u64 = 1u64 << 40;
pub const QUOTE_AUX_FLAG_POST_ONLY_SLIDE: u64 = 1u64 << 41;
pub const QUOTE_AUX_FLAG_MARGIN_SPOT: u64 = 1u64 << 42;
pub const QUOTE_AUX_FLAG_OCO_LINKED: u64 = 1u64 << 43;
pub const QUOTE_AUX_GTS_LO_SHIFT: u32 = 44;
pub const QUOTE_AUX_AUTO_SKEW_SHIFT: u32 = 48;
pub const QUOTE_AUX_AUTO_SKEW_MASK: u64 = 0x03FF;
pub const QUOTE_AUX_GTS_HI_SHIFT: u32 = 58;

// `ModifyInPlace`, `CancelAllAccount`, `Heartbeat`, and `bytes[51]` extended flags
pub const MODIFY_AUX_FLAG_KEEP_PRIORITY: u64 = 0x0000_0000_0000_0001;
pub const CANCEL_ALL_FLAG_BID_ONLY: u64 = 1u64 << 62;
pub const CANCEL_ALL_FLAG_ASK_ONLY: u64 = 1u64 << 63;
pub const CANCEL_ALL_TAG_MASK: u64 = 0x3FFF_FFFF_FFFF_FFFF;

pub const WIRE_EXT51_FLAG_LADDER_BY_TAG: u8 = 0x01;
pub const WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL: u8 = 0x02;
pub const WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP: u8 = 0x04;

pub const HEARTBEAT_AUX0_SYNC_SEQ: u64 = 0x5359_4E43_5F53_4551;

// `UpdateMarkFunding`, `LiquidateAccount`, `MintRedeemSet`, and `AtomicSpread` flags
pub const MARK_AUX1_FLAG_DISTRIBUTE_YIELD: u64 = 0x0000_0000_0000_0001;
pub const MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT: u64 = 1u64 << 1;
pub const MARK_AUX1_FLAG_LINK_SUB_ACCOUNT: u64 = 1u64 << 2;
pub const MARK_AUX1_FLAG_SUB_TRANSFER: u64 = 1u64 << 3;
pub const MARK_AUX1_FLAG_SAVE_SNAPSHOT: u64 = 1u64 << 4;
pub const MARK_AUX1_FLAG_SWEEP_INSURANCE: u64 = 1u64 << 5;
pub const MARK_AUX1_FLAG_HARVEST_FLOAT_YIELD: u64 = 1u64 << 6;
pub const MARK_AUX1_FLAG_HARVEST_SPOT_REPO: u64 = 1u64 << 7;
pub const MARK_AUX1_FLAG_HARVEST_USD_REPO: u64 = 1u64 << 8;
pub const MARK_AUX1_FLAG_BIND_BUILDER: u64 = 1u64 << 9;
pub const MARK_AUX1_FLAG_CONFIG_MMP: u64 = 1u64 << 10;
pub const MARK_AUX1_FLAG_CONFIG_PAYOUT: u64 = 1u64 << 11;
pub const MARK_AUX1_FLAG_BASE_YIELD: u64 = 1u64 << 12;
pub const MARK_AUX1_FLAG_CONFIG_AUTO_REPO: u64 = 1u64 << 13;
pub const MARK_AUX1_FLAG_FUND_MARKET_VAULT: u64 = 1u64 << 14;
pub const MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES: u64 = 1u64 << 15;
pub const MARK_AUX1_FLAG_DEFAULT_INCENTIVES: u64 = 1u64 << 16;
pub const MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT: u64 = 1u64 << 17;

pub const INCENTIVE_PILLAR_SUPERCHARGE: u8 = 0x01;
pub const INCENTIVE_PILLAR_AUTO_YIELD_DRIP: u8 = 0x02;
pub const INCENTIVE_PILLAR_AUTO_REPO: u8 = 0x04;
pub const INCENTIVE_PILLAR_NOTIONAL_BBO: u8 = 0x08;
pub const INCENTIVE_PILLAR_TWO_SIDED_BONUS: u8 = 0x10;
pub const INCENTIVE_PILLAR_CLAIM_COLLATERAL: u8 = 0x20;
pub const INCENTIVE_PILLAR_ITCH_PRIVACY: u8 = 0x40;
pub const INCENTIVE_PILLAR_MACRO_AND_BASIS: u8 = 0x80;
pub const INCENTIVE_PILLARS_ALL_ON: u8 = 0xFF;

pub const PAYOUT_FLAG_AUTO_REPAY_BORROW: u8 = 0x01;
pub const PAYOUT_FLAG_COMPOUND_BONDING_CURVE: u8 = 0x02;
pub const PAYOUT_FLAG_AUTO_COMPOUND_QUOTES: u8 = 0x04;

pub const LIQ_AUX1_FLAG_SET_KNOCKOUT: u64 = 0x0000_0000_0000_0001;
pub const LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE: u64 = 1u64 << 1;
pub const LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT: u64 = 1u64 << 2;
pub const LIQ_AUX1_FLAG_AUTO_CROSS_ARB: u64 = 1u64 << 3;
pub const LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP: u64 = 1u64 << 4;
pub const LIQ_AUX1_FLAG_NO_OFFLOAD: u64 = 1u64 << 62;

pub const MINT_AUX1_FLAG_FLASH_ARB: u64 = 0x0000_0000_0000_0001;
pub const MINT_AUX1_FLAG_FLASH_MARKET: u64 = 1u64 << 1;

pub const SPREAD_AUX1_FLAG_LEG2_ASK: u64 = 1u64 << 40;
pub const SPREAD_AUX1_FLAG_LEG1_MARKET: u64 = 1u64 << 41;
pub const SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY: u64 = 1u64 << 42;
pub const SPREAD_AUX1_FLAG_LEG2_MARKET: u64 = 1u64 << 43;
pub const SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY: u64 = 1u64 << 44;
pub const SPREAD_AUX1_FLAG_MARGIN_SPOT: u64 = 1u64 << 45;
pub const SPREAD_AUX1_FLAG_MULTI_LEG_BASKET: u64 = 1u64 << 46;
pub const SPREAD_AUX1_FLAG_BASKET_4_LEGS: u64 = 1u64 << 47;
pub const SPREAD_AUX1_LEG4_MKT_SHIFT: u32 = 48;
pub const SPREAD_AUX1_FLAG_LEG3_ASK: u64 = 1u64 << 56;
pub const SPREAD_AUX1_FLAG_LEG3_MARKET: u64 = 1u64 << 57;
pub const SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY: u64 = 1u64 << 58;
pub const SPREAD_AUX1_FLAG_LEG4_ASK: u64 = 1u64 << 59;
pub const SPREAD_AUX1_FLAG_LEG4_MARKET: u64 = 1u64 << 60;
pub const SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY: u64 = 1u64 << 61;
pub const SPREAD_AUX1_FLAG_BASKET_2_LEGS: u64 = 1u64 << 62;
pub const SPREAD_AUX1_FLAG_BASKET_EXT_MKT16: u64 = 1u64 << 63;
pub const SPREAD_AUX1_LEG3_MKT_HI8_SHIFT: u32 = 24;
pub const SPREAD_AUX1_LEG4_MKT_HI8_SHIFT: u32 = 32;

pub const MAX_WIRE_BASKET_LEG24_QTY_LOTS: u64 = 0x00FF_FFFF;
pub const MIN_WIRE_BASKET_LEG34_PRICE_TICKS: i64 = -2_147_483_648;
pub const MAX_WIRE_BASKET_LEG34_PRICE_TICKS: i64 = 2_147_483_647;

pub const ARENA_LEDGER_TIP_DOMAIN: &[u8; 21] = b"ARENA_LEDGER_TIP_V2_1";
pub const ARENA_SOVEREIGN_LEDGER_GENESIS_DOMAIN: &[u8; 35] = b"ARENA_SOVEREIGN_LEDGER_GENESIS_V2_0";

// Cross-socket HFT priority auction bounds (`bytes[52..=53]`)
pub const MAX_PRIORITY_FEE_PPM: u16 = 50_000;
pub const MAX_EXPRESS_SURPLUS_BID_BPS: u16 = 5_000;
pub const MAX_LIQ_BOUNTY_REBATE_BID_BPS: u16 = 10_000;

// `ArenaITCH` v1 L3 market-data constants
pub const ARENA_ITCH_MAGIC: u16 = 0x4149;
pub const ARENA_ITCH_VERSION: u8 = 0x01;
pub const ARENA_ITCH_BYTES: usize = 64;
pub const ARENA_ITCH_MAC_KEY0: u64 = 0x4152_454E_4149_5443;
pub const ARENA_ITCH_MAC_KEY1: u64 = 0x485F_5631_5F4D_4143;
pub const ARENA_ITCH_REQ_MAGIC: u32 = 0x4149_5251;
pub const ARENA_ITCH_REQ_BYTES: usize = 16;
pub const ITCH_REQ_FLAG_REPLAY_FROM_SEQ: u16 = 0x0001;
pub const ITCH_REQ_FLAG_FULL_SNAPSHOT: u16 = 1u16 << 1;

// =============================================================================
// Internal Big-Endian & SipHash-2-4 Macros (`const fn` Rust 1.75 Compatible)
// =============================================================================

macro_rules! put_be16 {
    ($buf:expr, $off:expr, $val:expr) => {{
        let v: u16 = $val;
        let b = v.to_be_bytes();
        let o: usize = $off;
        $buf[o] = b[0];
        $buf[o + 1] = b[1];
    }};
}

macro_rules! put_be32 {
    ($buf:expr, $off:expr, $val:expr) => {{
        let v: u32 = $val;
        let b = v.to_be_bytes();
        let o: usize = $off;
        $buf[o] = b[0];
        $buf[o + 1] = b[1];
        $buf[o + 2] = b[2];
        $buf[o + 3] = b[3];
    }};
}

macro_rules! put_be64 {
    ($buf:expr, $off:expr, $val:expr) => {{
        let v: u64 = $val;
        let b = v.to_be_bytes();
        let o: usize = $off;
        $buf[o] = b[0];
        $buf[o + 1] = b[1];
        $buf[o + 2] = b[2];
        $buf[o + 3] = b[3];
        $buf[o + 4] = b[4];
        $buf[o + 5] = b[5];
        $buf[o + 6] = b[6];
        $buf[o + 7] = b[7];
    }};
}

macro_rules! sip_round {
    ($v0:ident, $v1:ident, $v2:ident, $v3:ident) => {{
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13) ^ $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16) ^ $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21) ^ $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17) ^ $v2;
        $v2 = $v2.rotate_left(32);
    }};
}

// =============================================================================
// Public Big-Endian Read / Write Helpers
// =============================================================================

/// Reads a big-endian `u16` from `buf[offset..offset + 2]`.
///
/// # Panics
///
/// Panics if `offset + 2 > buf.len()` (or if `offset + 1` overflows `usize`).
/// Use [`try_read_be16`] for fallible, non-panicking slice decoding.
#[inline]
pub const fn read_be16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Reads a big-endian `u32` from `buf[offset..offset + 4]`.
///
/// # Panics
///
/// Panics if `offset + 4 > buf.len()` (or if `offset + 3` overflows `usize`).
/// Use [`try_read_be32`] for fallible, non-panicking slice decoding.
#[inline]
pub const fn read_be32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Reads a big-endian `u64` from `buf[offset..offset + 8]`.
///
/// # Panics
///
/// Panics if `offset + 8 > buf.len()` (or if `offset + 7` overflows `usize`).
/// Use [`try_read_be64`] for fallible, non-panicking slice decoding.
#[inline]
pub const fn read_be64(buf: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Reads a big-endian `u16` from `buf[offset..offset + 2]`, returning `None` if out of bounds.
#[inline]
pub const fn try_read_be16(buf: &[u8], offset: usize) -> Option<u16> {
    if offset > buf.len() || buf.len() - offset < 2 {
        return None;
    }
    Some(read_be16(buf, offset))
}

/// Reads a big-endian `u32` from `buf[offset..offset + 4]`, returning `None` if out of bounds.
#[inline]
pub const fn try_read_be32(buf: &[u8], offset: usize) -> Option<u32> {
    if offset > buf.len() || buf.len() - offset < 4 {
        return None;
    }
    Some(read_be32(buf, offset))
}

/// Reads a big-endian `u64` from `buf[offset..offset + 8]`, returning `None` if out of bounds.
#[inline]
pub const fn try_read_be64(buf: &[u8], offset: usize) -> Option<u64> {
    if offset > buf.len() || buf.len() - offset < 8 {
        return None;
    }
    Some(read_be64(buf, offset))
}

/// Writes a big-endian `u16` into `buf[offset..offset + 2]`.
///
/// # Panics
///
/// Panics if `offset + 2 > buf.len()` (or if `offset + 1` overflows `usize`).
/// Use [`try_write_be16`] for fallible, non-panicking slice encoding.
#[inline]
pub fn write_be16(buf: &mut [u8], offset: usize, val: u16) {
    put_be16!(buf, offset, val);
}

/// Writes a big-endian `u32` into `buf[offset..offset + 4]`.
///
/// # Panics
///
/// Panics if `offset + 4 > buf.len()` (or if `offset + 3` overflows `usize`).
/// Use [`try_write_be32`] for fallible, non-panicking slice encoding.
#[inline]
pub fn write_be32(buf: &mut [u8], offset: usize, val: u32) {
    put_be32!(buf, offset, val);
}

/// Writes a big-endian `u64` into `buf[offset..offset + 8]`.
///
/// # Panics
///
/// Panics if `offset + 8 > buf.len()` (or if `offset + 7` overflows `usize`).
/// Use [`try_write_be64`] for fallible, non-panicking slice encoding.
#[inline]
pub fn write_be64(buf: &mut [u8], offset: usize, val: u64) {
    put_be64!(buf, offset, val);
}

/// Writes a big-endian `u16` into `buf[offset..offset + 2]`, returning `false` if out of bounds.
#[inline]
#[must_use]
pub fn try_write_be16(buf: &mut [u8], offset: usize, val: u16) -> bool {
    if offset > buf.len() || buf.len() - offset < 2 {
        return false;
    }
    put_be16!(buf, offset, val);
    true
}

/// Writes a big-endian `u32` into `buf[offset..offset + 4]`, returning `false` if out of bounds.
#[inline]
#[must_use]
pub fn try_write_be32(buf: &mut [u8], offset: usize, val: u32) -> bool {
    if offset > buf.len() || buf.len() - offset < 4 {
        return false;
    }
    put_be32!(buf, offset, val);
    true
}

/// Writes a big-endian `u64` into `buf[offset..offset + 8]`, returning `false` if out of bounds.
#[inline]
#[must_use]
pub fn try_write_be64(buf: &mut [u8], offset: usize, val: u64) -> bool {
    if offset > buf.len() || buf.len() - offset < 8 {
        return false;
    }
    put_be64!(buf, offset, val);
    true
}

// =============================================================================
// Protocol Error & Enumerations
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WireError {
    InvalidVersion,
    InvalidTrailer,
    InvalidMac,
    InvalidOp,
    InvalidOrderSide,
    InvalidFields,
    InvalidStatusCode,
    InvalidOrderStatus,
    InvalidItchMagic,
    InvalidItchVersion,
    InvalidItchChecksum,
    InvalidItchEventType,
    InvalidItchReqMagic,
    UnencryptedSessionKeyWrap,
    ZeroSessionKeyWrapSalt,
}

impl WireError {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidVersion => "invalid ArenaWire protocol version (expected 0x01)",
            Self::InvalidTrailer => "invalid ArenaWire trailer magic (expected 0xA1E0)",
            Self::InvalidMac => "ArenaWire SipHash-2-4 MAC verification failed",
            Self::InvalidOp => "unexpected or invalid ArenaWire operation code",
            Self::InvalidOrderSide => "invalid order side discriminant (expected 0=Bid or 1=Ask)",
            Self::InvalidFields => "ArenaWire frame fields out of canonical bounds",
            Self::InvalidStatusCode => "invalid ArenaWireResponse status code discriminant",
            Self::InvalidOrderStatus => "invalid ArenaWireResponse order status discriminant",
            Self::InvalidItchMagic => "invalid ArenaITCH magic (expected 0x4149)",
            Self::InvalidItchVersion => "invalid ArenaITCH protocol version (expected 0x01)",
            Self::InvalidItchChecksum => "ArenaITCH SipHash-2-4 checksum verification failed",
            Self::InvalidItchEventType => "unknown ArenaITCH event type discriminant",
            Self::InvalidItchReqMagic => {
                "invalid ArenaITCH subscribe request magic (expected 0x41495251)"
            }
            Self::UnencryptedSessionKeyWrap => "unencrypted session key rotation frame rejected",
            Self::ZeroSessionKeyWrapSalt => "encrypted session key rotation salt must be non-zero",
        }
    }
}

impl core::fmt::Display for WireError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum BaseOp {
    #[default]
    NewOrder = 0x0,
    Cancel = 0x1,
    ModifyInPlace = 0x2,
    CancelAllAccount = 0x3,
    DepositCollateral = 0x4,
    WithdrawCollateral = 0x5,
    QueryBookBbo = 0x6,
    QueryAccount = 0x7,
    UpdateMarkFunding = 0x8,
    LiquidateAccount = 0x9,
    RegisterSessionKey = 0xA,
    SetCancelOnDisconnect = 0xB,
    TwoSidedQuoteReplace = 0xC,
    AtomicSpread = 0xD,
    MintRedeemSet = 0xE,
    Heartbeat = 0xF,
}

impl BaseOp {
    #[inline]
    pub const fn from_nibble(nib: u8) -> Self {
        match nib & 0x0F {
            0x0 => Self::NewOrder,
            0x1 => Self::Cancel,
            0x2 => Self::ModifyInPlace,
            0x3 => Self::CancelAllAccount,
            0x4 => Self::DepositCollateral,
            0x5 => Self::WithdrawCollateral,
            0x6 => Self::QueryBookBbo,
            0x7 => Self::QueryAccount,
            0x8 => Self::UpdateMarkFunding,
            0x9 => Self::LiquidateAccount,
            0xA => Self::RegisterSessionKey,
            0xB => Self::SetCancelOnDisconnect,
            0xC => Self::TwoSidedQuoteReplace,
            0xD => Self::AtomicSpread,
            0xE => Self::MintRedeemSet,
            _ => Self::Heartbeat,
        }
    }

    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 0x0F {
            Some(Self::from_nibble(val))
        } else {
            None
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum OrderSide {
    #[default]
    Bid = 0b00,
    Ask = 0b01,
}

impl OrderSide {
    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Bid),
            1 => Some(Self::Ask),
            _ => None,
        }
    }

    #[inline]
    pub const fn from_bit(bit: u8) -> Self {
        if (bit & 0x01) == 0 {
            Self::Bid
        } else {
            Self::Ask
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum TimeInForce {
    #[default]
    GTC = 0b00,
    IOC = 0b01,
    FOK = 0b10,
    PostOnly = 0b11,
}

impl TimeInForce {
    #[inline]
    pub const fn from_bits2(bits: u8) -> Self {
        match bits & 0x03 {
            0b00 => Self::GTC,
            0b01 => Self::IOC,
            0b10 => Self::FOK,
            _ => Self::PostOnly,
        }
    }

    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 0b11 {
            Some(Self::from_bits2(val))
        } else {
            None
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum StpMode {
    #[default]
    CancelResting = 0b00,
    CancelIncoming = 0b01,
    CancelBoth = 0b10,
    None = 0b11,
}

impl StpMode {
    #[inline]
    pub const fn from_bits2(bits: u8) -> Self {
        match bits & 0x03 {
            0b00 => Self::CancelResting,
            0b01 => Self::CancelIncoming,
            0b10 => Self::CancelBoth,
            _ => Self::None,
        }
    }

    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 0b11 {
            Some(Self::from_bits2(val))
        } else {
            None
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum WireStatusCode {
    #[default]
    Ok = 0x00,
    RejectInvalidMac = 0x01,
    RejectReplayOrStale = 0x02,
    RejectSessionCap = 0x03,
    RejectInvalidOp = 0x04,
    RejectInvalidMarket = 0x05,
    RejectInvalidParams = 0x06,
    RejectInsufficient = 0x07,
    RejectOrderNotFound = 0x08,
    RejectUnauthorized = 0x09,
    RejectPostOnlyCross = 0x0A,
    RejectFokUnfillable = 0x0B,
    RejectNotLiquidatable = 0x0C,
    RejectWalIoError = 0x0D,
    RejectUnbonded = 0x0E,
    RejectRiskLimit = 0x0F,
}

impl WireStatusCode {
    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::RejectInvalidMac),
            0x02 => Some(Self::RejectReplayOrStale),
            0x03 => Some(Self::RejectSessionCap),
            0x04 => Some(Self::RejectInvalidOp),
            0x05 => Some(Self::RejectInvalidMarket),
            0x06 => Some(Self::RejectInvalidParams),
            0x07 => Some(Self::RejectInsufficient),
            0x08 => Some(Self::RejectOrderNotFound),
            0x09 => Some(Self::RejectUnauthorized),
            0x0A => Some(Self::RejectPostOnlyCross),
            0x0B => Some(Self::RejectFokUnfillable),
            0x0C => Some(Self::RejectNotLiquidatable),
            0x0D => Some(Self::RejectWalIoError),
            0x0E => Some(Self::RejectUnbonded),
            0x0F => Some(Self::RejectRiskLimit),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum WireOrderStatus {
    #[default]
    None = 0x00,
    Resting = 0x01,
    PartiallyFilled = 0x02,
    Filled = 0x03,
    Canceled = 0x04,
    Modified = 0x05,
    Rejected = 0x06,
}

impl WireOrderStatus {
    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Resting),
            0x02 => Some(Self::PartiallyFilled),
            0x03 => Some(Self::Filled),
            0x04 => Some(Self::Canceled),
            0x05 => Some(Self::Modified),
            0x06 => Some(Self::Rejected),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// =============================================================================
// `ArenaFlags` and `ArenaHeader`
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaFlags {
    pub tif: TimeInForce,
    pub stp: StpMode,
}

impl Default for ArenaFlags {
    #[inline]
    fn default() -> Self {
        Self::new(TimeInForce::GTC, StpMode::CancelResting)
    }
}

impl ArenaFlags {
    #[inline]
    pub const fn new(tif: TimeInForce, stp: StpMode) -> Self {
        Self { tif, stp }
    }

    #[inline]
    pub const fn pack4(self) -> u8 {
        (((self.stp as u8) & 0x03) << 2) | ((self.tif as u8) & 0x03)
    }

    #[inline]
    pub const fn unpack4(nib: u8) -> Self {
        Self {
            tif: TimeInForce::from_bits2(nib & 0x03),
            stp: StpMode::from_bits2((nib >> 2) & 0x03),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaHeader {
    pub op: BaseOp,
    pub flags: ArenaFlags,
    pub market_id: u16,
    pub account_id: u32,
    pub side: OrderSide,
    pub seq_lo: u16,
    pub price_ticks: i64,
    pub qty_lots: u64,
}

impl Default for ArenaHeader {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl ArenaHeader {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            op: BaseOp::NewOrder,
            flags: ArenaFlags::new(TimeInForce::GTC, StpMode::CancelResting),
            market_id: 0,
            account_id: 0,
            side: OrderSide::Bid,
            seq_lo: 0,
            price_ticks: 0,
            qty_lots: 0,
        }
    }

    /// Packs the 152-bit header into `(m0, m1, hi24)`.
    #[inline]
    pub const fn pack_words(&self) -> (u64, u64, u32) {
        let op_fl = (((self.op as u8 & 0x0F) as u64) << 4) | ((self.flags.pack4() & 0x0F) as u64);
        let mkt = self.market_id as u64;
        let acct = (self.account_id & 0x00FF_FFFF) as u64;
        let sd_seq = (((self.side as u8 & 0x03) as u64) << 14) | ((self.seq_lo & 0x3FFF) as u64);
        let m0 = (op_fl << 56) | (mkt << 40) | (acct << 16) | sd_seq;

        let p48 = (self.price_ticks as u64) & 0x0000_FFFF_FFFF_FFFF;
        let q40 = self.qty_lots & 0x0000_00FF_FFFF_FFFF;
        let m1 = (p48 << 16) | (q40 >> 24);
        let hi24 = (q40 & 0x00FF_FFFF) as u32;
        (m0, m1, hi24)
    }
}

// =============================================================================
// Validation & Aux-Bitfield Packing Helpers (`NewOrder`, `TwoSidedQuoteReplace`, `AtomicSpread`)
// =============================================================================

#[inline]
const fn clamp_i16(val: i16, min_val: i16, max_val: i16) -> i16 {
    if val < min_val {
        min_val
    } else if val > max_val {
        max_val
    } else {
        val
    }
}

#[inline]
const fn min_i16(a: i16, b: i16) -> i16 {
    if a < b {
        a
    } else {
        b
    }
}

#[inline]
const fn min_u16(a: u16, b: u16) -> u16 {
    if a < b {
        a
    } else {
        b
    }
}

#[inline]
pub const fn is_valid_wire_price_ticks_48(px: i64) -> bool {
    px >= MIN_WIRE_PRICE_TICKS_48 && px <= MAX_WIRE_PRICE_TICKS_48
}

#[inline]
pub const fn is_canonical_ext_qty_hi16(ask_qty_hi16: u16) -> bool {
    ask_qty_hi16 <= 0x7FFF
}

#[inline]
pub const fn is_valid_wire_fields(hdr: &ArenaHeader, ext_qty_hi16: u16) -> bool {
    hdr.account_id <= MAX_WIRE_ACCOUNT_ID
        && (hdr.side as u8) <= 1
        && is_valid_wire_price_ticks_48(hdr.price_ticks)
        && hdr.qty_lots <= MAX_WIRE_HEADER_QTY_LOTS
        && is_canonical_ext_qty_hi16(ext_qty_hi16)
}

#[inline]
pub const fn pack_jit_elastic_mult_nibble(jit_elastic_mult: u8) -> u8 {
    if jit_elastic_mult <= 1 {
        0
    } else if jit_elastic_mult <= 10 {
        jit_elastic_mult
    } else if jit_elastic_mult <= 17 {
        11
    } else if jit_elastic_mult <= 22 {
        12
    } else if jit_elastic_mult <= 30 {
        13
    } else if jit_elastic_mult <= 42 {
        14
    } else {
        15
    }
}

#[inline]
pub const fn unpack_jit_elastic_mult_nibble(raw: u8) -> u8 {
    match raw & 0x0F {
        0 | 1 => 0,
        11 => 15,
        12 => 20,
        13 => 25,
        14 => 35,
        15 => 50,
        n => n,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrderAux1Params {
    pub reduce_only: bool,
    pub is_market: bool,
    pub cancel_on_disconnect: bool,
    pub post_only_slide: bool,
    pub min_qty_lots: u64,
    pub primary_peg: bool,
    pub midpoint_peg: bool,
    pub margin_spot: bool,
    pub display_qty_lots: u64,
    pub dark_midpoint: bool,
    pub auto_skew_ticks: i16,
    pub peg_offset_ticks: i16,
    pub oco_linked: bool,
    pub max_lifetime_wal_seqs: u16,
    pub jit_elastic_mult: u8,
    pub mark_peg: bool,
    pub auto_flip_ticks: i16,
    pub trailing_peg: bool,
}

impl Default for OrderAux1Params {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl OrderAux1Params {
    #[inline]
    pub const fn new() -> Self {
        Self {
            reduce_only: false,
            is_market: false,
            cancel_on_disconnect: false,
            post_only_slide: false,
            min_qty_lots: 0,
            primary_peg: false,
            midpoint_peg: false,
            margin_spot: false,
            display_qty_lots: 0,
            dark_midpoint: false,
            auto_skew_ticks: 0,
            peg_offset_ticks: 0,
            oco_linked: false,
            max_lifetime_wal_seqs: 0,
            jit_elastic_mult: 0,
            mark_peg: false,
            auto_flip_ticks: 0,
            trailing_peg: false,
        }
    }

    #[inline]
    pub const fn pack(&self) -> u64 {
        pack_order_aux1(
            self.reduce_only,
            self.is_market,
            self.cancel_on_disconnect,
            self.post_only_slide,
            self.min_qty_lots,
            self.primary_peg,
            self.midpoint_peg,
            self.margin_spot,
            self.display_qty_lots,
            self.dark_midpoint,
            self.auto_skew_ticks,
            self.peg_offset_ticks,
            self.oco_linked,
            self.max_lifetime_wal_seqs,
            self.jit_elastic_mult,
            self.mark_peg,
            self.auto_flip_ticks,
            self.trailing_peg,
        )
    }
}

pub const fn pack_order_aux1(
    reduce_only: bool,
    is_market: bool,
    cancel_on_disconnect: bool,
    post_only_slide: bool,
    min_qty_lots: u64,
    primary_peg: bool,
    midpoint_peg: bool,
    margin_spot: bool,
    display_qty_lots: u64,
    dark_midpoint: bool,
    auto_skew_ticks: i16,
    peg_offset_ticks: i16,
    oco_linked: bool,
    max_lifetime_wal_seqs: u16,
    jit_elastic_mult: u8,
    mark_peg: bool,
    auto_flip_ticks: i16,
    trailing_peg: bool,
) -> u64 {
    let eff_trailing = trailing_peg && !dark_midpoint;
    let eff_primary = primary_peg || ((mark_peg || eff_trailing) && !dark_midpoint);
    let eff_midpoint = midpoint_peg || dark_midpoint || ((mark_peg || eff_trailing) && !dark_midpoint);
    let use_iceberg = (display_qty_lots > 0) || dark_midpoint || eff_trailing;
    let hi_qty = if dark_midpoint || eff_trailing {
        0
    } else if use_iceberg {
        display_qty_lots
    } else {
        min_qty_lots
    };

    let skew_or_peg = if (eff_primary || eff_midpoint) && !dark_midpoint {
        let clamped_off = clamp_i16(peg_offset_ticks, -500, 500);
        ((clamped_off as u16) as u64) & ORDER_AUX_PEG_OFFSET_MASK
    } else if auto_flip_ticks > 0 {
        ORDER_AUX_AUTO_FLIP_BIT | ((min_i16(auto_flip_ticks, 500) as u64) & 0x01FF)
    } else if auto_skew_ticks > 0 {
        (min_i16(auto_skew_ticks, 500) as u64) & 0x01FF
    } else {
        0
    };

    let has_gts = max_lifetime_wal_seqs > 0;
    let qty_mask = if has_gts {
        ORDER_AUX_MIN_QTY_GTS_MASK
    } else {
        ORDER_AUX_MIN_QTY_MASK
    };
    let clamped_hi_qty = if hi_qty > qty_mask { qty_mask } else { hi_qty };
    let gts_bits = if has_gts {
        ORDER_AUX_FLAG_GTS_EXPIRY
            | (((max_lifetime_wal_seqs as u64) & ORDER_AUX_GTS_MASK) << ORDER_AUX_GTS_SHIFT)
    } else {
        0
    };
    let jit_bits = if jit_elastic_mult > 1 {
        ((pack_jit_elastic_mult_nibble(jit_elastic_mult) as u64) & ORDER_AUX_JIT_MULT_MASK)
            << ORDER_AUX_JIT_MULT_SHIFT
    } else {
        0
    };

    (if reduce_only { ORDER_AUX_FLAG_REDUCE_ONLY } else { 0 })
        | (if is_market { ORDER_AUX_FLAG_MARKET } else { 0 })
        | (if cancel_on_disconnect {
            ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT
        } else {
            0
        })
        | (if post_only_slide {
            ORDER_AUX_FLAG_POST_ONLY_SLIDE
        } else {
            0
        })
        | (if eff_primary { ORDER_AUX_FLAG_PRIMARY_PEG } else { 0 })
        | (if eff_midpoint {
            ORDER_AUX_FLAG_MIDPOINT_PEG
        } else {
            0
        })
        | (if margin_spot { ORDER_AUX_FLAG_MARGIN_SPOT } else { 0 })
        | (if use_iceberg { ORDER_AUX_FLAG_ICEBERG } else { 0 })
        | (if oco_linked { ORDER_AUX_FLAG_OCO_LINKED } else { 0 })
        | (skew_or_peg << ORDER_AUX_AUTO_SKEW_SHIFT)
        | jit_bits
        | ((clamped_hi_qty & qty_mask) << ORDER_AUX_MIN_QTY_SHIFT)
        | gts_bits
}

#[inline]
pub const fn unpack_order_min_qty_lots(aux_param1: u64) -> u64 {
    if (aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0 {
        return 0;
    }
    let mask = if (aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0 {
        ORDER_AUX_MIN_QTY_GTS_MASK
    } else {
        ORDER_AUX_MIN_QTY_MASK
    };
    (aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask
}

#[inline]
pub const fn unpack_order_display_qty_lots(aux_param1: u64) -> u64 {
    if (aux_param1 & ORDER_AUX_FLAG_ICEBERG) == 0 {
        return 0;
    }
    let mask = if (aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0 {
        ORDER_AUX_MIN_QTY_GTS_MASK
    } else {
        ORDER_AUX_MIN_QTY_MASK
    };
    (aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask
}

#[inline]
pub const fn unpack_order_dark_midpoint(aux_param1: u64) -> bool {
    let mask = if (aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0 {
        ORDER_AUX_MIN_QTY_GTS_MASK
    } else {
        ORDER_AUX_MIN_QTY_MASK
    };
    ((aux_param1 & ORDER_AUX_FLAG_MIDPOINT_PEG) != 0)
        && ((aux_param1 & ORDER_AUX_FLAG_PRIMARY_PEG) == 0)
        && ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0)
        && (((aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0)
}

#[inline]
pub const fn unpack_order_trailing_peg(aux_param1: u64) -> bool {
    let mask = if (aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0 {
        ORDER_AUX_MIN_QTY_GTS_MASK
    } else {
        ORDER_AUX_MIN_QTY_MASK
    };
    ((aux_param1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO)
        && ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0)
        && (((aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0)
}

#[inline]
pub const fn unpack_order_mark_peg(aux_param1: u64) -> bool {
    ((aux_param1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO)
        && !unpack_order_trailing_peg(aux_param1)
        && !unpack_order_dark_midpoint(aux_param1)
}

#[inline]
pub const fn unpack_order_primary_peg(aux_param1: u64) -> bool {
    ((aux_param1 & ORDER_AUX_FLAG_PRIMARY_PEG) != 0)
        && !unpack_order_mark_peg(aux_param1)
        && !unpack_order_trailing_peg(aux_param1)
}

#[inline]
pub const fn unpack_order_midpoint_peg(aux_param1: u64) -> bool {
    ((aux_param1 & ORDER_AUX_FLAG_MIDPOINT_PEG) != 0)
        && !unpack_order_mark_peg(aux_param1)
        && !unpack_order_trailing_peg(aux_param1)
        && !unpack_order_dark_midpoint(aux_param1)
}

#[inline]
pub const fn unpack_order_auto_skew_ticks(aux_param1: u64) -> i16 {
    if (aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) != 0 {
        return 0;
    }
    let raw = ((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK) as u16;
    if (raw & (ORDER_AUX_AUTO_FLIP_BIT as u16)) != 0 {
        return 0;
    }
    min_u16(raw & 0x01FF, 500) as i16
}

#[inline]
pub const fn unpack_order_auto_flip_ticks(aux_param1: u64) -> i16 {
    if (aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) != 0 {
        return 0;
    }
    let raw = ((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK) as u16;
    if (raw & (ORDER_AUX_AUTO_FLIP_BIT as u16)) == 0 {
        return 0;
    }
    min_u16(raw & 0x01FF, 500) as i16
}

#[inline]
pub const fn unpack_order_peg_offset_ticks(aux_param1: u64) -> i16 {
    if (aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) == 0
        || unpack_order_dark_midpoint(aux_param1)
    {
        return 0;
    }
    let raw10 = ((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_PEG_OFFSET_MASK) as u16;
    let s10 = if (raw10 & 0x0200) != 0 {
        (raw10 | 0xFC00) as i16
    } else {
        raw10 as i16
    };
    clamp_i16(s10, -500, 500)
}

#[inline]
pub const fn unpack_order_oco_linked(aux_param1: u64) -> bool {
    (aux_param1 & ORDER_AUX_FLAG_OCO_LINKED) != 0
}

#[inline]
pub const fn unpack_order_max_lifetime_wal_seqs(aux_param1: u64) -> u16 {
    if (aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) == 0 {
        return 0;
    }
    ((aux_param1 >> ORDER_AUX_GTS_SHIFT) & ORDER_AUX_GTS_MASK) as u16
}

#[inline]
pub const fn unpack_order_jit_elastic_mult(aux_param1: u64) -> u8 {
    let raw = ((aux_param1 >> ORDER_AUX_JIT_MULT_SHIFT) & ORDER_AUX_JIT_MULT_MASK) as u8;
    unpack_jit_elastic_mult_nibble(raw)
}

#[inline]
pub const fn pack_quote_ask_qty_hi16(ask_qty_lots: u64) -> u16 {
    ((ask_qty_lots >> QUOTE_AUX_HI16_SHIFT) & 0x7FFF) as u16
}

#[inline]
pub const fn unpack_quote_ask_qty_parts(aux_param1: u64, ask_qty_hi16: u16) -> u64 {
    ((aux_param1 & QUOTE_AUX_QTY_MASK)
        | (((ask_qty_hi16 as u64) & 0x7FFF) << QUOTE_AUX_HI16_SHIFT))
        & QUOTE_AUX_QTY_50_MASK
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QuoteAux1Params {
    pub ask_qty_lots: u64,
    pub cancel_on_disconnect: bool,
    pub post_only_slide: bool,
    pub margin_spot: bool,
    pub auto_skew_ticks: i16,
    pub oco_linked: bool,
    pub max_lifetime_wal_seqs: u16,
    pub jit_elastic_mult: u8,
    pub auto_flip_ticks: i16,
    pub quote_peg_mode: u8,
    pub peg_offset_ticks: i16,
}

impl Default for QuoteAux1Params {
    #[inline]
    fn default() -> Self {
        Self::new(0)
    }
}

impl QuoteAux1Params {
    #[inline]
    pub const fn new(ask_qty_lots: u64) -> Self {
        Self {
            ask_qty_lots,
            cancel_on_disconnect: false,
            post_only_slide: false,
            margin_spot: false,
            auto_skew_ticks: 0,
            oco_linked: false,
            max_lifetime_wal_seqs: 0,
            jit_elastic_mult: 0,
            auto_flip_ticks: 0,
            quote_peg_mode: 0,
            peg_offset_ticks: 0,
        }
    }

    #[inline]
    pub const fn pack(&self) -> (u64, u16) {
        pack_quote_aux1(
            self.ask_qty_lots,
            self.cancel_on_disconnect,
            self.post_only_slide,
            self.margin_spot,
            self.auto_skew_ticks,
            self.oco_linked,
            self.max_lifetime_wal_seqs,
            self.jit_elastic_mult,
            self.auto_flip_ticks,
            self.quote_peg_mode,
            self.peg_offset_ticks,
        )
    }
}

/// Packs `TwoSidedQuoteReplace` `aux_param1` and returns `(aux_param1, ask_qty_hi16)` where
/// `ask_qty_hi16` holds bits `[49:35]` of the 50-bit `ask_qty_lots` for `frame.bytes[41..=42]`.
pub const fn pack_quote_aux1(
    ask_qty_lots: u64,
    cancel_on_disconnect: bool,
    post_only_slide: bool,
    margin_spot: bool,
    auto_skew_ticks: i16,
    oco_linked: bool,
    max_lifetime_wal_seqs: u16,
    jit_elastic_mult: u8,
    auto_flip_ticks: i16,
    quote_peg_mode: u8,
    peg_offset_ticks: i16,
) -> (u64, u16) {
    let ask_qty_hi16 = pack_quote_ask_qty_hi16(ask_qty_lots);
    let eff_peg = if quote_peg_mode <= 4 {
        quote_peg_mode
    } else {
        0
    };
    let skew10 = if eff_peg != 0 {
        let clamped_off = clamp_i16(peg_offset_ticks, -500, 500);
        ((clamped_off as u16) as u64) & QUOTE_AUX_AUTO_SKEW_MASK
    } else if auto_flip_ticks > 0 {
        ORDER_AUX_AUTO_FLIP_BIT | ((min_i16(auto_flip_ticks, 500) as u64) & 0x01FF)
    } else if auto_skew_ticks > 0 {
        (min_i16(auto_skew_ticks, 500) as u64) & 0x01FF
    } else {
        0
    };
    let gts_cap: u16 = if eff_peg != 0 { 255 } else { 1023 };
    let gts_val = min_u16(max_lifetime_wal_seqs, gts_cap) as u64;
    let gts_lo = (gts_val & 0x0F) << QUOTE_AUX_GTS_LO_SHIFT;
    let gts_hi_mask: u64 = if eff_peg != 0 { 0x0F } else { 0x3F };
    let gts_hi = ((gts_val >> 4) & gts_hi_mask) << QUOTE_AUX_GTS_HI_SHIFT;
    let jit4 = if jit_elastic_mult > 1 {
        ((pack_jit_elastic_mult_nibble(jit_elastic_mult) as u64) & QUOTE_AUX_JIT_MULT_MASK)
            << QUOTE_AUX_JIT_MULT_SHIFT
    } else {
        0
    };
    let peg_bits = if eff_peg != 0 {
        QUOTE_AUX_FLAG_PEG_ACTIVE
            | ((((eff_peg - 1) as u64) & QUOTE_AUX_PEG_MODE_MASK) << QUOTE_AUX_PEG_MODE_SHIFT)
    } else {
        0
    };
    let aux1 = (ask_qty_lots & QUOTE_AUX_QTY_MASK)
        | peg_bits
        | jit4
        | (if cancel_on_disconnect {
            QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT
        } else {
            0
        })
        | (if post_only_slide {
            QUOTE_AUX_FLAG_POST_ONLY_SLIDE
        } else {
            0
        })
        | (if margin_spot {
            QUOTE_AUX_FLAG_MARGIN_SPOT
        } else {
            0
        })
        | (if oco_linked {
            QUOTE_AUX_FLAG_OCO_LINKED
        } else {
            0
        })
        | gts_lo
        | ((skew10 & QUOTE_AUX_AUTO_SKEW_MASK) << QUOTE_AUX_AUTO_SKEW_SHIFT)
        | gts_hi;
    (aux1, ask_qty_hi16)
}

#[inline]
pub const fn unpack_quote_peg_mode(aux_param1: u64) -> u8 {
    if (aux_param1 & QUOTE_AUX_FLAG_PEG_ACTIVE) == 0 {
        return 0;
    }
    let raw2 = ((aux_param1 >> QUOTE_AUX_PEG_MODE_SHIFT) & QUOTE_AUX_PEG_MODE_MASK) as u8;
    raw2 + 1
}

#[inline]
pub const fn unpack_quote_peg_offset_ticks(aux_param1: u64) -> i16 {
    if unpack_quote_peg_mode(aux_param1) == 0 {
        return 0;
    }
    let raw10 = ((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK) as u16;
    let s10 = if (raw10 & 0x0200) != 0 {
        (raw10 | 0xFC00) as i16
    } else {
        raw10 as i16
    };
    clamp_i16(s10, -500, 500)
}

#[inline]
pub const fn unpack_quote_auto_skew_ticks(aux_param1: u64) -> i16 {
    if unpack_quote_peg_mode(aux_param1) != 0 {
        return 0;
    }
    let raw = ((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK) as u16;
    if (raw & (ORDER_AUX_AUTO_FLIP_BIT as u16)) != 0 {
        return 0;
    }
    min_u16(raw & 0x01FF, 500) as i16
}

#[inline]
pub const fn unpack_quote_auto_flip_ticks(aux_param1: u64) -> i16 {
    if unpack_quote_peg_mode(aux_param1) != 0 {
        return 0;
    }
    let raw = ((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK) as u16;
    if (raw & (ORDER_AUX_AUTO_FLIP_BIT as u16)) == 0 {
        return 0;
    }
    min_u16(raw & 0x01FF, 500) as i16
}

#[inline]
pub const fn unpack_quote_oco_linked(aux_param1: u64) -> bool {
    (aux_param1 & QUOTE_AUX_FLAG_OCO_LINKED) != 0
}

#[inline]
pub const fn unpack_quote_max_lifetime_wal_seqs(aux_param1: u64) -> u16 {
    let lo4 = ((aux_param1 >> QUOTE_AUX_GTS_LO_SHIFT) & 0x0F) as u16;
    let hi_mask: u64 = if (aux_param1 & QUOTE_AUX_FLAG_PEG_ACTIVE) != 0 {
        0x0F
    } else {
        0x3F
    };
    let hi = ((aux_param1 >> QUOTE_AUX_GTS_HI_SHIFT) & hi_mask) as u16;
    (hi << 4) | lo4
}

#[inline]
pub const fn unpack_quote_jit_elastic_mult(aux_param1: u64) -> u8 {
    let raw = ((aux_param1 >> QUOTE_AUX_JIT_MULT_SHIFT) & QUOTE_AUX_JIT_MULT_MASK) as u8;
    unpack_jit_elastic_mult_nibble(raw)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnpackedAtomicSpreadAux {
    pub leg2_market_id: u16,
    pub leg2_side: OrderSide,
    pub leg2_price_ticks: i64,
    pub leg2_qty_lots: u64,
    pub leg1_is_market: bool,
    pub leg1_reduce_only: bool,
    pub leg2_is_market: bool,
    pub leg2_reduce_only: bool,
    pub margin_spot: bool,
}

/// Packs 2-leg `AtomicSpread` auxiliary words, returning `(aux_param0, aux_param1, leg2_qty_hi16)`.
pub const fn pack_atomic_spread_aux(
    leg2_market_id: u16,
    leg2_side: OrderSide,
    leg2_price_ticks: i64,
    leg2_qty_lots: u64,
    leg1_is_market: bool,
    leg1_reduce_only: bool,
    leg2_is_market: bool,
    leg2_reduce_only: bool,
    margin_spot: bool,
) -> (u64, u64, u16) {
    let leg2_qty_hi16 = pack_quote_ask_qty_hi16(leg2_qty_lots);
    let p48 = (leg2_price_ticks as u64) & 0x0000_FFFF_FFFF_FFFF;
    let aux0 = ((leg2_market_id as u64) << 48) | p48;
    let aux1 = (leg2_qty_lots & QUOTE_AUX_QTY_MASK)
        | (if (leg2_side as u8) == (OrderSide::Ask as u8) {
            SPREAD_AUX1_FLAG_LEG2_ASK
        } else {
            0
        })
        | (if leg1_is_market {
            SPREAD_AUX1_FLAG_LEG1_MARKET
        } else {
            0
        })
        | (if leg1_reduce_only {
            SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY
        } else {
            0
        })
        | (if leg2_is_market {
            SPREAD_AUX1_FLAG_LEG2_MARKET
        } else {
            0
        })
        | (if leg2_reduce_only {
            SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY
        } else {
            0
        })
        | (if margin_spot {
            SPREAD_AUX1_FLAG_MARGIN_SPOT
        } else {
            0
        });
    (aux0, aux1, leg2_qty_hi16)
}

pub const fn unpack_atomic_spread_aux(
    aux_param0: u64,
    aux_param1: u64,
    leg2_qty_hi16: u16,
) -> UnpackedAtomicSpreadAux {
    let leg2_market_id = ((aux_param0 >> 48) & 0xFFFF) as u16;
    let p48 = aux_param0 & 0x0000_FFFF_FFFF_FFFF;
    let leg2_price_ticks = if (p48 & (1u64 << 47)) != 0 {
        (p48 | 0xFFFF_0000_0000_0000) as i64
    } else {
        p48 as i64
    };
    let is_3or4_leg_basket = ((aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0)
        && ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) == 0);
    let leg2_qty_lots = if is_3or4_leg_basket && ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16) != 0) {
        aux_param1 & 0x00FF_FFFF
    } else if is_3or4_leg_basket {
        unpack_quote_ask_qty_parts(aux_param1, 0)
    } else {
        unpack_quote_ask_qty_parts(aux_param1, leg2_qty_hi16)
    };
    UnpackedAtomicSpreadAux {
        leg2_market_id,
        leg2_side: if (aux_param1 & SPREAD_AUX1_FLAG_LEG2_ASK) != 0 {
            OrderSide::Ask
        } else {
            OrderSide::Bid
        },
        leg2_price_ticks,
        leg2_qty_lots,
        leg1_is_market: (aux_param1 & SPREAD_AUX1_FLAG_LEG1_MARKET) != 0,
        leg1_reduce_only: (aux_param1 & SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY) != 0,
        leg2_is_market: (aux_param1 & SPREAD_AUX1_FLAG_LEG2_MARKET) != 0,
        leg2_reduce_only: (aux_param1 & SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY) != 0,
        margin_spot: (aux_param1 & SPREAD_AUX1_FLAG_MARGIN_SPOT) != 0,
    }
}

// =============================================================================
// Dual SipHash-2-4 MACs (`PreSipHash40` + `TailSipHash48`)
// =============================================================================

/// Computes the 40-bit SipHash-2-4 header MAC stored in `bytes[19..=23]`.
pub const fn calc_pre_siphash40(
    hdr: &ArenaHeader,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> u64 {
    let (m0, m1, hi24) = hdr.pack_words();
    let m2 = ((hi24 as u64) << 40) | (seq_hi50 & 0x0000_00FF_FFFF_FFFF);
    let seq_top10 = (seq_hi50 >> 40) & 0x03FF;

    let mut v0 = key_lo64 ^ 0x736f_6d65_7073_6575 ^ seq_top10;
    let mut v1 = key_hi64 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key_lo64 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key_hi64 ^ 0x7465_6462_7974_6573 ^ m0;

    // Word m0 (already XORed into v3)
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^= m0;

    // Word m1
    v3 ^= m1;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^= m1;

    // Word m2
    v3 ^= m2;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^= m2;

    // Finalization (4 rounds)
    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    let digest = v0 ^ v1 ^ v2 ^ v3;
    (digest ^ (digest >> 24)) & 0x0000_00FF_FFFF_FFFF
}

/// Computes the 48-bit SipHash-2-4 payload MAC over `frame_bytes[0..56]` + `seq_hi50` domain,
/// stored in `bytes[56..=61]`.
pub const fn calc_tail_siphash48(
    frame_bytes: &[u8; ARENA_WIRE_BYTES],
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> u64 {
    let eff_hi50 = seq_hi50 & 0x0003_FFFF_FFFF_FFFF;
    let words: [u64; 9] = [
        read_be64(frame_bytes, 0),
        read_be64(frame_bytes, 8),
        read_be64(frame_bytes, 16),
        read_be64(frame_bytes, 24),
        read_be64(frame_bytes, 32),
        read_be64(frame_bytes, 40),
        read_be64(frame_bytes, 48),
        eff_hi50 | (0x2A54u64 << 50),
        (64u64 << 56) | 0x0000_4152_454E_4154,
    ];

    let mut v0 = key_lo64 ^ 0x736f_6d65_7073_6575 ^ 0x5441_494C_5F56_3231;
    let mut v1 = key_hi64 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key_lo64 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key_hi64 ^ 0x7465_6462_7974_6573;

    let mut i: usize = 0;
    while i < 9 {
        let m = words[i];
        v3 ^= m;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^= m;
        i += 1;
    }

    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    let h = v0 ^ v1 ^ v2 ^ v3;
    (h ^ (h >> 16)) & 0x0000_FFFF_FFFF_FFFF
}

// =============================================================================
// 64-Byte Cacheline-Aligned Ingress Frame (`ArenaWireFrame`)
// =============================================================================

/// 64-byte cacheline-aligned big-endian ingress order-entry frame (`ArenaWire` v1).
///
/// ```text
/// [0..=7]   : Header m0 (big-endian u64)
/// [8..=15]  : Header m1 (big-endian u64)
/// [16..=18] : Header hi24 (qty_lots[23:0], big-endian 24-bit)
/// [19..=23] : PreSipHash40 header MAC (big-endian 40-bit)
/// [24]      : Protocol version byte (0x01)
/// [25..=32] : aux_param0 (big-endian u64)
/// [33..=40] : aux_param1 (big-endian u64)
/// [41..=55] : Extended op payload / flags (bytes[41..=42] hi16 qty, bytes[43..=50] tag, bytes[51] ext flags)
/// [56..=61] : TailSipHash48 payload MAC (big-endian 48-bit)
/// [62..=63] : Frame trailer magic (0xA1, 0xE0)
/// ```
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaWireFrame {
    pub bytes: [u8; ARENA_WIRE_BYTES],
}

const _: [(); ARENA_WIRE_BYTES] = [(); core::mem::size_of::<ArenaWireFrame>()];
const _: [(); ARENA_WIRE_BYTES] = [(); core::mem::align_of::<ArenaWireFrame>()];

impl Default for ArenaWireFrame {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl ArenaWireFrame {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0u8; ARENA_WIRE_BYTES],
        }
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; ARENA_WIRE_BYTES]) -> Self {
        Self { bytes }
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; ARENA_WIRE_BYTES] {
        &self.bytes
    }

    #[inline]
    pub const fn has_valid_envelope(&self) -> bool {
        self.bytes[24] == ARENA_WIRE_VERSION
            && self.bytes[62] == ARENA_WIRE_TRAILER[0]
            && self.bytes[63] == ARENA_WIRE_TRAILER[1]
    }

    #[inline]
    pub const fn get_pre_siphash40(&self) -> u64 {
        ((self.bytes[19] as u64) << 32)
            | ((self.bytes[20] as u64) << 24)
            | ((self.bytes[21] as u64) << 16)
            | ((self.bytes[22] as u64) << 8)
            | (self.bytes[23] as u64)
    }

    #[inline]
    pub const fn get_tail_siphash48(&self) -> u64 {
        ((self.bytes[56] as u64) << 40)
            | ((self.bytes[57] as u64) << 32)
            | ((self.bytes[58] as u64) << 24)
            | ((self.bytes[59] as u64) << 16)
            | ((self.bytes[60] as u64) << 8)
            | (self.bytes[61] as u64)
    }

    #[inline]
    pub fn set_tail_siphash48(&mut self, mac48: u64) {
        self.bytes[56] = ((mac48 >> 40) & 0xFF) as u8;
        self.bytes[57] = ((mac48 >> 32) & 0xFF) as u8;
        self.bytes[58] = ((mac48 >> 24) & 0xFF) as u8;
        self.bytes[59] = ((mac48 >> 16) & 0xFF) as u8;
        self.bytes[60] = ((mac48 >> 8) & 0xFF) as u8;
        self.bytes[61] = (mac48 & 0xFF) as u8;
    }

    #[inline]
    pub const fn with_tail_siphash48(mut self, mac48: u64) -> Self {
        self.bytes[56] = ((mac48 >> 40) & 0xFF) as u8;
        self.bytes[57] = ((mac48 >> 32) & 0xFF) as u8;
        self.bytes[58] = ((mac48 >> 24) & 0xFF) as u8;
        self.bytes[59] = ((mac48 >> 16) & 0xFF) as u8;
        self.bytes[60] = ((mac48 >> 8) & 0xFF) as u8;
        self.bytes[61] = (mac48 & 0xFF) as u8;
        self
    }
}

/// Packs an `ArenaWireFrame` with `ext_qty_hi16 == 0`.
#[inline]
pub const fn pack_wire_frame(
    hdr: &ArenaHeader,
    aux_param0: u64,
    aux_param1: u64,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    pack_wire_frame_ext(
        hdr,
        aux_param0,
        aux_param1,
        seq_hi50,
        key_lo64,
        key_hi64,
        0,
    )
}

/// Packs an `ArenaWireFrame` with optional 15-bit high extended quantity `ext_qty_hi16` at `bytes[41..=42]`.
pub const fn pack_wire_frame_ext(
    hdr: &ArenaHeader,
    aux_param0: u64,
    aux_param1: u64,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
    ext_qty_hi16: u16,
) -> ArenaWireFrame {
    let mut bytes = [0u8; ARENA_WIRE_BYTES];
    let (m0, m1, hi24) = hdr.pack_words();

    put_be64!(bytes, 0, m0);
    put_be64!(bytes, 8, m1);
    bytes[16] = ((hi24 >> 16) & 0xFF) as u8;
    bytes[17] = ((hi24 >> 8) & 0xFF) as u8;
    bytes[18] = (hi24 & 0xFF) as u8;

    let mac40 = calc_pre_siphash40(hdr, seq_hi50, key_lo64, key_hi64);
    bytes[19] = ((mac40 >> 32) & 0xFF) as u8;
    bytes[20] = ((mac40 >> 24) & 0xFF) as u8;
    bytes[21] = ((mac40 >> 16) & 0xFF) as u8;
    bytes[22] = ((mac40 >> 8) & 0xFF) as u8;
    bytes[23] = (mac40 & 0xFF) as u8;

    bytes[24] = ARENA_WIRE_VERSION;
    put_be64!(bytes, 25, aux_param0);
    put_be64!(bytes, 33, aux_param1);
    if ext_qty_hi16 != 0 {
        put_be16!(bytes, 41, ext_qty_hi16);
    }

    let tail_mac48 = calc_tail_siphash48(&bytes, seq_hi50, key_lo64, key_hi64);
    bytes[56] = ((tail_mac48 >> 40) & 0xFF) as u8;
    bytes[57] = ((tail_mac48 >> 32) & 0xFF) as u8;
    bytes[58] = ((tail_mac48 >> 24) & 0xFF) as u8;
    bytes[59] = ((tail_mac48 >> 16) & 0xFF) as u8;
    bytes[60] = ((tail_mac48 >> 8) & 0xFF) as u8;
    bytes[61] = (tail_mac48 & 0xFF) as u8;
    bytes[62] = ARENA_WIRE_TRAILER[0];
    bytes[63] = ARENA_WIRE_TRAILER[1];

    ArenaWireFrame { bytes }
}

/// Validates field bounds before packing an `ArenaWireFrame`.
pub const fn try_pack_wire_frame(
    hdr: &ArenaHeader,
    aux_param0: u64,
    aux_param1: u64,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
    ext_qty_hi16: u16,
) -> Result<ArenaWireFrame, WireError> {
    if !is_valid_wire_fields(hdr, ext_qty_hi16) {
        return Err(WireError::InvalidFields);
    }
    Ok(pack_wire_frame_ext(
        hdr,
        aux_param0,
        aux_param1,
        seq_hi50,
        key_lo64,
        key_hi64,
        ext_qty_hi16,
    ))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnpackedWireFrame {
    pub header: ArenaHeader,
    pub rx_mac40: u64,
    pub aux_param0: u64,
    pub aux_param1: u64,
    pub ext_qty_hi16: u16,
    pub tail_mac48: u64,
}

impl UnpackedWireFrame {
    #[inline]
    pub const fn verify_macs(
        &self,
        frame: &ArenaWireFrame,
        seq_hi50: u64,
        key_lo64: u64,
        key_hi64: u64,
    ) -> bool {
        let exp_pre = calc_pre_siphash40(&self.header, seq_hi50, key_lo64, key_hi64);
        let exp_tail = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
        ((exp_pre ^ self.rx_mac40) | (exp_tail ^ self.tail_mac48)) == 0
    }
}

/// Unpacks an `ArenaWireFrame`, verifying the protocol version (`bytes[24] == 0x01`)
/// and frame trailer magic (`bytes[62..=63] == [0xA1, 0xE0]`).
pub const fn unpack_wire_frame(frame: &ArenaWireFrame) -> Result<UnpackedWireFrame, WireError> {
    if frame.bytes[24] != ARENA_WIRE_VERSION {
        return Err(WireError::InvalidVersion);
    }
    if frame.bytes[62] != ARENA_WIRE_TRAILER[0] || frame.bytes[63] != ARENA_WIRE_TRAILER[1] {
        return Err(WireError::InvalidTrailer);
    }

    let m0 = read_be64(&frame.bytes, 0);
    let m1 = read_be64(&frame.bytes, 8);
    let hi24 = ((frame.bytes[16] as u64) << 16)
        | ((frame.bytes[17] as u64) << 8)
        | (frame.bytes[18] as u64);

    let op_fl = ((m0 >> 56) & 0xFF) as u8;
    let op = BaseOp::from_nibble((op_fl >> 4) & 0x0F);
    let flags = ArenaFlags::unpack4(op_fl & 0x0F);
    let market_id = ((m0 >> 40) & 0xFFFF) as u16;
    let account_id = ((m0 >> 16) & 0x00FF_FFFF) as u32;
    let sd_s = (m0 & 0xFFFF) as u16;
    let side = match OrderSide::from_u8(((sd_s >> 14) & 0x03) as u8) {
        Some(s) => s,
        None => return Err(WireError::InvalidOrderSide),
    };
    let seq_lo = sd_s & 0x3FFF;

    let p48 = (m1 >> 16) & 0x0000_FFFF_FFFF_FFFF;
    let price_ticks = if (p48 & (1u64 << 47)) != 0 {
        (p48 | 0xFFFF_0000_0000_0000) as i64
    } else {
        p48 as i64
    };
    let qty_lots = (((m1 & 0xFFFF) << 24) | hi24) & 0x0000_00FF_FFFF_FFFF;

    let header = ArenaHeader {
        op,
        flags,
        market_id,
        account_id,
        side,
        seq_lo,
        price_ticks,
        qty_lots,
    };

    Ok(UnpackedWireFrame {
        header,
        rx_mac40: frame.get_pre_siphash40(),
        aux_param0: read_be64(&frame.bytes, 25),
        aux_param1: read_be64(&frame.bytes, 33),
        ext_qty_hi16: read_be16(&frame.bytes, 41),
        tail_mac48: frame.get_tail_siphash48(),
    })
}

/// Unpacks an `ArenaWireFrame` and verifies both `PreSipHash40` and `TailSipHash48` MACs.
pub const fn unpack_and_verify_wire_frame(
    frame: &ArenaWireFrame,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> Result<UnpackedWireFrame, WireError> {
    let unpacked = match unpack_wire_frame(frame) {
        Ok(u) => u,
        Err(e) => return Err(e),
    };
    if !unpacked.verify_macs(frame, seq_hi50, key_lo64, key_hi64) {
        return Err(WireError::InvalidMac);
    }
    Ok(unpacked)
}

// =============================================================================
// Extended `ArenaWireFrame` Trailer / Tag Modifiers & Structured Operations
// =============================================================================

#[inline]
pub const fn unpack_quote_ask_qty(frame: &ArenaWireFrame, aux_param1: u64) -> u64 {
    unpack_quote_ask_qty_parts(aux_param1, read_be16(&frame.bytes, 41))
}

pub const fn pack_quote_ext_tag_and_ladder(
    mut frame: ArenaWireFrame,
    client_tag: u64,
    ladder_by_tag: bool,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    if client_tag == 0
        && !ladder_by_tag
        && read_be64(&frame.bytes, 43) == 0
        && (frame.bytes[51] & WIRE_EXT51_FLAG_LADDER_BY_TAG) == 0
    {
        return frame;
    }
    put_be64!(frame.bytes, 43, client_tag);
    frame.bytes[51] &= !WIRE_EXT51_FLAG_LADDER_BY_TAG;
    if ladder_by_tag {
        frame.bytes[51] |= WIRE_EXT51_FLAG_LADDER_BY_TAG;
    }
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

#[inline]
pub fn set_quote_ext_tag_and_ladder(
    frame: &mut ArenaWireFrame,
    client_tag: u64,
    ladder_by_tag: bool,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) {
    *frame = pack_quote_ext_tag_and_ladder(
        *frame,
        client_tag,
        ladder_by_tag,
        seq_hi50,
        key_lo64,
        key_hi64,
    );
}

#[inline]
pub const fn unpack_quote_client_tag(frame: &ArenaWireFrame) -> u64 {
    read_be64(&frame.bytes, 43)
}

#[inline]
pub const fn unpack_quote_ladder_by_tag(frame: &ArenaWireFrame) -> bool {
    (frame.bytes[51] & WIRE_EXT51_FLAG_LADDER_BY_TAG) != 0
}

pub const fn pack_order_ext_stp_decrement_cancel(
    mut frame: ArenaWireFrame,
    stp_decrement_and_cancel: bool,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    if !stp_decrement_and_cancel && (frame.bytes[51] & WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL) == 0 {
        return frame;
    }
    frame.bytes[51] &= !WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL;
    if stp_decrement_and_cancel {
        frame.bytes[51] |= WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL;
    }
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

#[inline]
pub const fn unpack_order_stp_decrement_cancel(frame: &ArenaWireFrame) -> bool {
    (frame.bytes[51] & WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL) != 0
}

pub const fn pack_order_ext_priority_fee_ppm(
    mut frame: ArenaWireFrame,
    priority_fee_ppm: u16,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    if priority_fee_ppm == 0 && read_be16(&frame.bytes, 52) == 0 {
        return frame;
    }
    let clamped = min_u16(priority_fee_ppm, MAX_PRIORITY_FEE_PPM);
    put_be16!(frame.bytes, 52, clamped);
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

#[inline]
pub const fn unpack_order_priority_fee_ppm(frame: &ArenaWireFrame) -> u16 {
    read_be16(&frame.bytes, 52)
}

pub const fn pack_wire_express_surplus_bid_bps(
    mut frame: ArenaWireFrame,
    express_surplus_bid_bps: u16,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    if express_surplus_bid_bps == 0 && read_be16(&frame.bytes, 52) == 0 {
        return frame;
    }
    let clamped = min_u16(express_surplus_bid_bps, MAX_EXPRESS_SURPLUS_BID_BPS);
    put_be16!(frame.bytes, 52, clamped);
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

pub const fn pack_wire_liq_bounty_rebate_bid_bps(
    mut frame: ArenaWireFrame,
    bounty_rebate_bid_bps: u16,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    if bounty_rebate_bid_bps == 0 && read_be16(&frame.bytes, 52) == 0 {
        return frame;
    }
    let clamped = min_u16(bounty_rebate_bid_bps, MAX_LIQ_BOUNTY_REBATE_BID_BPS);
    put_be16!(frame.bytes, 52, clamped);
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

#[inline]
pub const fn liq_mode_flags_valid(aux_param1: u64) -> bool {
    let mode_bits = aux_param1
        & (LIQ_AUX1_FLAG_SET_KNOCKOUT
            | LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE
            | LIQ_AUX1_FLAG_AUTO_CROSS_ARB
            | LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP);
    (mode_bits & mode_bits.wrapping_sub(1)) == 0
}

pub const fn unpack_wire_express_surplus_bid_bps(
    frame: &ArenaWireFrame,
    op: BaseOp,
    aux_param1: u64,
) -> u16 {
    match op {
        BaseOp::AtomicSpread => {
            if (aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0
                && (aux_param1 & SPREAD_AUX1_FLAG_BASKET_4_LEGS) != 0
            {
                return 0; // bytes[52..=54] encodes leg4 qty_lots on 4-leg baskets
            }
            read_be16(&frame.bytes, 52)
        }
        BaseOp::MintRedeemSet => {
            if (aux_param1 & MINT_AUX1_FLAG_FLASH_ARB) != 0 {
                read_be16(&frame.bytes, 52)
            } else {
                0
            }
        }
        BaseOp::LiquidateAccount => {
            if !liq_mode_flags_valid(aux_param1) {
                return 0;
            }
            if (aux_param1 & LIQ_AUX1_FLAG_AUTO_CROSS_ARB) != 0 {
                read_be16(&frame.bytes, 52)
            } else {
                0
            }
        }
        _ => 0,
    }
}

pub const fn unpack_wire_liq_bounty_rebate_bid_bps(
    frame: &ArenaWireFrame,
    op: BaseOp,
    aux_param0: u64,
    aux_param1: u64,
) -> u16 {
    if (op as u8) != (BaseOp::LiquidateAccount as u8) || !liq_mode_flags_valid(aux_param1) {
        return 0;
    }
    if (aux_param1
        & (LIQ_AUX1_FLAG_SET_KNOCKOUT
            | LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE
            | LIQ_AUX1_FLAG_AUTO_CROSS_ARB))
        != 0
    {
        return 0;
    }
    if (aux_param1 & LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP) == 0 && aux_param0 == 0 {
        return 0;
    }
    read_be16(&frame.bytes, 52)
}

pub const fn peek_wire_priority_score(
    frame: &ArenaWireFrame,
    allow_arb_surplus_bids: bool,
) -> u32 {
    if !frame.has_valid_envelope() {
        return 0;
    }
    let op = BaseOp::from_nibble((frame.bytes[0] >> 4) & 0x0F);
    let tif = TimeInForce::from_bits2(frame.bytes[0] & 0x03);
    let aux1 = read_be64(&frame.bytes, 33);
    if (op as u8) == (BaseOp::NewOrder as u8) {
        if (tif as u8) == (TimeInForce::PostOnly as u8)
            || (aux1
                & (ORDER_AUX_FLAG_POST_ONLY_SLIDE
                    | ORDER_AUX_FLAG_PRIMARY_PEG
                    | ORDER_AUX_FLAG_MIDPOINT_PEG))
                != 0
        {
            return 0;
        }
        let ppm = read_be16(&frame.bytes, 52);
        if ppm == 0 || ppm > MAX_PRIORITY_FEE_PPM {
            return 0;
        }
        return (ppm as u32) * 10;
    }
    if !allow_arb_surplus_bids {
        return 0;
    }
    if (op as u8) == (BaseOp::LiquidateAccount as u8) {
        if !liq_mode_flags_valid(aux1) {
            return 0;
        }
        if (aux1
            & (LIQ_AUX1_FLAG_SET_KNOCKOUT
                | LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE
                | LIQ_AUX1_FLAG_AUTO_CROSS_ARB))
            == 0
        {
            let aux0 = read_be64(&frame.bytes, 25);
            let hdr_acct = ((frame.bytes[3] as u32) << 16)
                | ((frame.bytes[4] as u32) << 8)
                | (frame.bytes[5] as u32);
            if aux0 > 0xFFFF_FFFF || (aux0 != 0 && (aux0 as u32) == hdr_acct) {
                return 0;
            }
            let bounty_bps = unpack_wire_liq_bounty_rebate_bid_bps(frame, op, aux0, aux1);
            if bounty_bps > 0 && bounty_bps <= MAX_LIQ_BOUNTY_REBATE_BID_BPS {
                return (bounty_bps as u32) * 50;
            }
        }
    }
    let bps = unpack_wire_express_surplus_bid_bps(frame, op, aux1);
    if bps == 0 || bps > MAX_EXPRESS_SURPLUS_BID_BPS {
        return 0;
    }
    bps as u32
}

/// Structured builder/decoder for `BaseOp::TwoSidedQuoteReplace` (`0xC`), supporting
/// 50-bit `ask_qty_lots` (`bytes[41..=42]`) and `client_tag` / `ladder_by_tag` (`bytes[43..=51]`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TwoSidedQuoteReplace {
    pub flags: ArenaFlags,
    pub market_id: u16,
    pub account_id: u32,
    pub seq_lo: u16,
    pub bid_price_ticks: i64,
    pub bid_qty_lots: u64,
    pub ask_price_ticks: i64,
    pub ask_qty_lots: u64,
    pub cancel_on_disconnect: bool,
    pub post_only_slide: bool,
    pub margin_spot: bool,
    pub auto_skew_ticks: i16,
    pub oco_linked: bool,
    pub max_lifetime_wal_seqs: u16,
    pub jit_elastic_mult: u8,
    pub auto_flip_ticks: i16,
    pub quote_peg_mode: u8,
    pub peg_offset_ticks: i16,
    pub client_tag: u64,
    pub ladder_by_tag: bool,
}

impl Default for TwoSidedQuoteReplace {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl TwoSidedQuoteReplace {
    #[inline]
    pub const fn new() -> Self {
        Self {
            flags: ArenaFlags::new(TimeInForce::PostOnly, StpMode::CancelResting),
            market_id: 0,
            account_id: 0,
            seq_lo: 0,
            bid_price_ticks: 0,
            bid_qty_lots: 0,
            ask_price_ticks: 0,
            ask_qty_lots: 0,
            cancel_on_disconnect: false,
            post_only_slide: false,
            margin_spot: false,
            auto_skew_ticks: 0,
            oco_linked: false,
            max_lifetime_wal_seqs: 0,
            jit_elastic_mult: 0,
            auto_flip_ticks: 0,
            quote_peg_mode: 0,
            peg_offset_ticks: 0,
            client_tag: 0,
            ladder_by_tag: false,
        }
    }

    pub const fn pack_frame(
        &self,
        seq_hi50: u64,
        key_lo64: u64,
        key_hi64: u64,
    ) -> ArenaWireFrame {
        let hdr = ArenaHeader {
            op: BaseOp::TwoSidedQuoteReplace,
            flags: self.flags,
            market_id: self.market_id,
            account_id: self.account_id,
            side: OrderSide::Bid,
            seq_lo: self.seq_lo,
            price_ticks: self.bid_price_ticks,
            qty_lots: self.bid_qty_lots,
        };
        let (aux1, ask_qty_hi16) = pack_quote_aux1(
            self.ask_qty_lots,
            self.cancel_on_disconnect,
            self.post_only_slide,
            self.margin_spot,
            self.auto_skew_ticks,
            self.oco_linked,
            self.max_lifetime_wal_seqs,
            self.jit_elastic_mult,
            self.auto_flip_ticks,
            self.quote_peg_mode,
            self.peg_offset_ticks,
        );
        let base = pack_wire_frame_ext(
            &hdr,
            self.ask_price_ticks as u64,
            aux1,
            seq_hi50,
            key_lo64,
            key_hi64,
            ask_qty_hi16,
        );
        pack_quote_ext_tag_and_ladder(
            base,
            self.client_tag,
            self.ladder_by_tag,
            seq_hi50,
            key_lo64,
            key_hi64,
        )
    }

    pub const fn unpack_frame(frame: &ArenaWireFrame) -> Result<Self, WireError> {
        let u = match unpack_wire_frame(frame) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (u.header.op as u8) != (BaseOp::TwoSidedQuoteReplace as u8) {
            return Err(WireError::InvalidOp);
        }
        let aux1 = u.aux_param1;
        Ok(Self {
            flags: u.header.flags,
            market_id: u.header.market_id,
            account_id: u.header.account_id,
            seq_lo: u.header.seq_lo,
            bid_price_ticks: u.header.price_ticks,
            bid_qty_lots: u.header.qty_lots,
            ask_price_ticks: u.aux_param0 as i64,
            ask_qty_lots: unpack_quote_ask_qty(frame, aux1),
            cancel_on_disconnect: (aux1 & QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT) != 0,
            post_only_slide: (aux1 & QUOTE_AUX_FLAG_POST_ONLY_SLIDE) != 0,
            margin_spot: (aux1 & QUOTE_AUX_FLAG_MARGIN_SPOT) != 0,
            auto_skew_ticks: unpack_quote_auto_skew_ticks(aux1),
            oco_linked: unpack_quote_oco_linked(aux1),
            max_lifetime_wal_seqs: unpack_quote_max_lifetime_wal_seqs(aux1),
            jit_elastic_mult: unpack_quote_jit_elastic_mult(aux1),
            auto_flip_ticks: unpack_quote_auto_flip_ticks(aux1),
            quote_peg_mode: unpack_quote_peg_mode(aux1),
            peg_offset_ticks: unpack_quote_peg_offset_ticks(aux1),
            client_tag: unpack_quote_client_tag(frame),
            ladder_by_tag: unpack_quote_ladder_by_tag(frame),
        })
    }
}

/// Structured builder/decoder for 2-leg `BaseOp::AtomicSpread` (`0xD`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AtomicSpread {
    pub stp: StpMode,
    pub account_id: u32,
    pub seq_lo: u16,
    pub leg1_market_id: u16,
    pub leg1_side: OrderSide,
    pub leg1_price_ticks: i64,
    pub leg1_qty_lots: u64,
    pub leg1_is_market: bool,
    pub leg1_reduce_only: bool,
    pub leg2_market_id: u16,
    pub leg2_side: OrderSide,
    pub leg2_price_ticks: i64,
    pub leg2_qty_lots: u64,
    pub leg2_is_market: bool,
    pub leg2_reduce_only: bool,
    pub margin_spot: bool,
}

impl Default for AtomicSpread {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicSpread {
    #[inline]
    pub const fn new() -> Self {
        Self {
            stp: StpMode::CancelResting,
            account_id: 0,
            seq_lo: 0,
            leg1_market_id: 0,
            leg1_side: OrderSide::Bid,
            leg1_price_ticks: 0,
            leg1_qty_lots: 0,
            leg1_is_market: false,
            leg1_reduce_only: false,
            leg2_market_id: 0,
            leg2_side: OrderSide::Ask,
            leg2_price_ticks: 0,
            leg2_qty_lots: 0,
            leg2_is_market: false,
            leg2_reduce_only: false,
            margin_spot: false,
        }
    }

    pub const fn pack_frame(
        &self,
        seq_hi50: u64,
        key_lo64: u64,
        key_hi64: u64,
    ) -> ArenaWireFrame {
        let hdr = ArenaHeader {
            op: BaseOp::AtomicSpread,
            flags: ArenaFlags::new(TimeInForce::IOC, self.stp),
            market_id: self.leg1_market_id,
            account_id: self.account_id,
            side: self.leg1_side,
            seq_lo: self.seq_lo,
            price_ticks: self.leg1_price_ticks,
            qty_lots: self.leg1_qty_lots,
        };
        let (aux0, aux1, leg2_hi16) = pack_atomic_spread_aux(
            self.leg2_market_id,
            self.leg2_side,
            self.leg2_price_ticks,
            self.leg2_qty_lots,
            self.leg1_is_market,
            self.leg1_reduce_only,
            self.leg2_is_market,
            self.leg2_reduce_only,
            self.margin_spot,
        );
        pack_wire_frame_ext(
            &hdr,
            aux0,
            aux1,
            seq_hi50,
            key_lo64,
            key_hi64,
            leg2_hi16,
        )
    }

    pub const fn unpack_frame(frame: &ArenaWireFrame) -> Result<Self, WireError> {
        let u = match unpack_wire_frame(frame) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if (u.header.op as u8) != (BaseOp::AtomicSpread as u8) {
            return Err(WireError::InvalidOp);
        }
        if (u.aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0 {
            return Err(WireError::InvalidFields);
        }
        let s = unpack_atomic_spread_aux(u.aux_param0, u.aux_param1, u.ext_qty_hi16);
        Ok(Self {
            stp: u.header.flags.stp,
            account_id: u.header.account_id,
            seq_lo: u.header.seq_lo,
            leg1_market_id: u.header.market_id,
            leg1_side: u.header.side,
            leg1_price_ticks: u.header.price_ticks,
            leg1_qty_lots: u.header.qty_lots,
            leg1_is_market: s.leg1_is_market,
            leg1_reduce_only: s.leg1_reduce_only,
            leg2_market_id: s.leg2_market_id,
            leg2_side: s.leg2_side,
            leg2_price_ticks: s.leg2_price_ticks,
            leg2_qty_lots: s.leg2_qty_lots,
            leg2_is_market: s.leg2_is_market,
            leg2_reduce_only: s.leg2_reduce_only,
            margin_spot: s.margin_spot,
        })
    }
}

/// Single leg descriptor for 2-, 3-, or 4-leg atomic `BaseOp::AtomicSpread` (`0xD`) wire baskets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WireBasketLeg {
    pub market_id: u16,
    pub side: OrderSide,
    pub price_ticks: i64,
    pub qty_lots: u64,
    pub is_market: bool,
    pub reduce_only: bool,
    pub margin_spot: bool,
}

impl Default for WireBasketLeg {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl WireBasketLeg {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            market_id: 0,
            side: OrderSide::Bid,
            price_ticks: 0,
            qty_lots: 0,
            is_market: false,
            reduce_only: false,
            margin_spot: false,
        }
    }

    #[inline]
    pub const fn new(
        market_id: u16,
        side: OrderSide,
        price_ticks: i64,
        qty_lots: u64,
    ) -> Self {
        Self {
            market_id,
            side,
            price_ticks,
            qty_lots,
            is_market: false,
            reduce_only: false,
            margin_spot: false,
        }
    }
}

/// Validates and packs a 2-, 3-, or 4-leg atomic FOK `BaseOp::AtomicSpread` (`0xD`) wire basket
/// into a single 64-byte `ArenaWireFrame` with `PreSipHash40` + `TailSipHash48` MACs.
pub const fn try_pack_wire_basket_frame(
    account_id: u32,
    legs: &[WireBasketLeg],
    stp: StpMode,
    margin_spot: bool,
    seq_lo: u16,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> Result<ArenaWireFrame, WireError> {
    let num_legs = legs.len();
    if account_id > MAX_WIRE_ACCOUNT_ID || num_legs < 2 || num_legs > 4 {
        return Err(WireError::InvalidFields);
    }
    let mut idx: usize = 0;
    while idx < num_legs {
        if (legs[idx].side as u8) > 1 {
            return Err(WireError::InvalidOrderSide);
        }
        idx += 1;
    }
    if !is_valid_wire_price_ticks_48(legs[0].price_ticks)
        || legs[0].qty_lots > MAX_WIRE_HEADER_QTY_LOTS
        || !is_valid_wire_price_ticks_48(legs[1].price_ticks)
    {
        return Err(WireError::InvalidFields);
    }
    if num_legs == 2 && legs[1].qty_lots > MAX_WIRE_EXT_QTY_LOTS {
        return Err(WireError::InvalidFields);
    }
    if num_legs >= 3 {
        let ext_m = (legs[2].market_id > 0xFF) || (num_legs >= 4 && legs[3].market_id > 0xFF);
        let leg2_cap = if ext_m {
            MAX_WIRE_BASKET_LEG24_QTY_LOTS
        } else {
            QUOTE_AUX_QTY_MASK
        };
        if legs[1].qty_lots > leg2_cap
            || legs[2].qty_lots > MAX_WIRE_BASKET_LEG24_QTY_LOTS
            || legs[2].price_ticks < MIN_WIRE_BASKET_LEG34_PRICE_TICKS
            || legs[2].price_ticks > MAX_WIRE_BASKET_LEG34_PRICE_TICKS
        {
            return Err(WireError::InvalidFields);
        }
        if num_legs >= 4
            && (legs[3].qty_lots > MAX_WIRE_BASKET_LEG24_QTY_LOTS
                || legs[3].price_ticks < MIN_WIRE_BASKET_LEG34_PRICE_TICKS
                || legs[3].price_ticks > MAX_WIRE_BASKET_LEG34_PRICE_TICKS)
        {
            return Err(WireError::InvalidFields);
        }
    }

    let hdr = ArenaHeader {
        op: BaseOp::AtomicSpread,
        flags: ArenaFlags::new(TimeInForce::FOK, stp),
        market_id: legs[0].market_id,
        account_id,
        side: legs[0].side,
        seq_lo,
        price_ticks: legs[0].price_ticks,
        qty_lots: legs[0].qty_lots,
    };

    let mut any_margin_spot = margin_spot;
    let mut j: usize = 0;
    while j < num_legs {
        if legs[j].margin_spot {
            any_margin_spot = true;
        }
        j += 1;
    }

    let (aux0, mut aux1, _) = pack_atomic_spread_aux(
        legs[1].market_id,
        legs[1].side,
        legs[1].price_ticks,
        legs[1].qty_lots,
        legs[0].is_market,
        legs[0].reduce_only,
        legs[1].is_market,
        legs[1].reduce_only,
        any_margin_spot,
    );
    aux1 |= SPREAD_AUX1_FLAG_MULTI_LEG_BASKET;
    if num_legs == 2 {
        aux1 |= SPREAD_AUX1_FLAG_BASKET_2_LEGS;
    } else if num_legs >= 4 {
        aux1 |= SPREAD_AUX1_FLAG_BASKET_4_LEGS;
    }
    if num_legs >= 3 {
        if (legs[2].side as u8) == (OrderSide::Ask as u8) {
            aux1 |= SPREAD_AUX1_FLAG_LEG3_ASK;
        }
        if legs[2].is_market {
            aux1 |= SPREAD_AUX1_FLAG_LEG3_MARKET;
        }
        if legs[2].reduce_only {
            aux1 |= SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY;
        }
    }
    if num_legs >= 4 {
        aux1 |= ((legs[3].market_id as u64) & 0xFF) << SPREAD_AUX1_LEG4_MKT_SHIFT;
        if (legs[3].side as u8) == (OrderSide::Ask as u8) {
            aux1 |= SPREAD_AUX1_FLAG_LEG4_ASK;
        }
        if legs[3].is_market {
            aux1 |= SPREAD_AUX1_FLAG_LEG4_MARKET;
        }
        if legs[3].reduce_only {
            aux1 |= SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY;
        }
    }
    if num_legs >= 3 && (legs[2].market_id > 0xFF || (num_legs >= 4 && legs[3].market_id > 0xFF)) {
        let leg3_hi = (((legs[2].market_id >> 8) & 0xFF) as u64) << SPREAD_AUX1_LEG3_MKT_HI8_SHIFT;
        let leg4_hi = if num_legs >= 4 {
            (((legs[3].market_id >> 8) & 0xFF) as u64) << SPREAD_AUX1_LEG4_MKT_HI8_SHIFT
        } else {
            0
        };
        aux1 = (aux1 & !0x0000_00FF_FF00_0000)
            | SPREAD_AUX1_FLAG_BASKET_EXT_MKT16
            | leg3_hi
            | leg4_hi;
    }

    let mut bytes = [0u8; ARENA_WIRE_BYTES];
    let (m0, m1, hi24) = hdr.pack_words();
    put_be64!(bytes, 0, m0);
    put_be64!(bytes, 8, m1);
    bytes[16] = ((hi24 >> 16) & 0xFF) as u8;
    bytes[17] = ((hi24 >> 8) & 0xFF) as u8;
    bytes[18] = (hi24 & 0xFF) as u8;

    let mac40 = calc_pre_siphash40(&hdr, seq_hi50, key_lo64, key_hi64);
    bytes[19] = ((mac40 >> 32) & 0xFF) as u8;
    bytes[20] = ((mac40 >> 24) & 0xFF) as u8;
    bytes[21] = ((mac40 >> 16) & 0xFF) as u8;
    bytes[22] = ((mac40 >> 8) & 0xFF) as u8;
    bytes[23] = (mac40 & 0xFF) as u8;

    bytes[24] = ARENA_WIRE_VERSION;
    put_be64!(bytes, 25, aux0);
    put_be64!(bytes, 33, aux1);

    if num_legs == 2 {
        put_be16!(bytes, 41, pack_quote_ask_qty_hi16(legs[1].qty_lots));
    } else {
        put_be32!(bytes, 41, legs[2].price_ticks as u32);
        let q3 = (legs[2].qty_lots & 0x00FF_FFFF) as u32;
        bytes[49] = ((q3 >> 16) & 0xFF) as u8;
        bytes[50] = ((q3 >> 8) & 0xFF) as u8;
        bytes[51] = (q3 & 0xFF) as u8;
        bytes[55] = (legs[2].market_id & 0xFF) as u8;
        if num_legs >= 4 {
            put_be32!(bytes, 45, legs[3].price_ticks as u32);
            let q4 = (legs[3].qty_lots & 0x00FF_FFFF) as u32;
            bytes[52] = ((q4 >> 16) & 0xFF) as u8;
            bytes[53] = ((q4 >> 8) & 0xFF) as u8;
            bytes[54] = (q4 & 0xFF) as u8;
        }
    }

    let tail_mac48 = calc_tail_siphash48(&bytes, seq_hi50, key_lo64, key_hi64);
    bytes[56] = ((tail_mac48 >> 40) & 0xFF) as u8;
    bytes[57] = ((tail_mac48 >> 32) & 0xFF) as u8;
    bytes[58] = ((tail_mac48 >> 24) & 0xFF) as u8;
    bytes[59] = ((tail_mac48 >> 16) & 0xFF) as u8;
    bytes[60] = ((tail_mac48 >> 8) & 0xFF) as u8;
    bytes[61] = (tail_mac48 & 0xFF) as u8;
    bytes[62] = ARENA_WIRE_TRAILER[0];
    bytes[63] = ARENA_WIRE_TRAILER[1];

    Ok(ArenaWireFrame { bytes })
}

/// Fixed-array C++ parity wrapper around [`try_pack_wire_basket_frame`]; returns
/// `ArenaWireFrame::zeroed()` if `num_legs` (`2..=4`) or any leg field is out of bounds.
pub const fn pack_wire_basket_frame(
    account_id: u32,
    num_legs: u8,
    legs: &[WireBasketLeg; 4],
    stp: StpMode,
    margin_spot: bool,
    seq_lo: u16,
    seq_hi50: u64,
    key_lo64: u64,
    key_hi64: u64,
) -> ArenaWireFrame {
    let res = match num_legs {
        2 => try_pack_wire_basket_frame(
            account_id,
            &[legs[0], legs[1]],
            stp,
            margin_spot,
            seq_lo,
            seq_hi50,
            key_lo64,
            key_hi64,
        ),
        3 => try_pack_wire_basket_frame(
            account_id,
            &[legs[0], legs[1], legs[2]],
            stp,
            margin_spot,
            seq_lo,
            seq_hi50,
            key_lo64,
            key_hi64,
        ),
        4 => try_pack_wire_basket_frame(
            account_id,
            legs,
            stp,
            margin_spot,
            seq_lo,
            seq_hi50,
            key_lo64,
            key_hi64,
        ),
        _ => Err(WireError::InvalidFields),
    };
    match res {
        Ok(frame) => frame,
        Err(_) => ArenaWireFrame::zeroed(),
    }
}

/// Unpacks `(num_legs, leg3, leg4)` from a `BaseOp::AtomicSpread` (`0xD`) wire basket frame,
/// supporting both 8-bit and 16-bit (`SPREAD_AUX1_FLAG_BASKET_EXT_MKT16`) leg market IDs.
pub const fn unpack_wire_basket_legs34(
    frame: &ArenaWireFrame,
    aux_param1: u64,
) -> (u8, WireBasketLeg, WireBasketLeg) {
    let mut leg3 = WireBasketLeg::zeroed();
    let mut leg4 = WireBasketLeg::zeroed();
    if (aux_param1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) != 0
        || (aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) == 0
    {
        return (2, leg3, leg4);
    }
    let num_legs: u8 = if (aux_param1 & SPREAD_AUX1_FLAG_BASKET_4_LEGS) != 0 {
        4
    } else {
        3
    };
    let margin_spot = (aux_param1 & SPREAD_AUX1_FLAG_MARGIN_SPOT) != 0;
    let ext_mkt16 = (aux_param1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16) != 0;
    let leg3_hi8: u16 = if ext_mkt16 {
        (((aux_param1 >> SPREAD_AUX1_LEG3_MKT_HI8_SHIFT) & 0xFF) as u16) << 8
    } else {
        0
    };
    leg3 = WireBasketLeg {
        market_id: (frame.bytes[55] as u16) | leg3_hi8,
        side: if (aux_param1 & SPREAD_AUX1_FLAG_LEG3_ASK) != 0 {
            OrderSide::Ask
        } else {
            OrderSide::Bid
        },
        price_ticks: (read_be32(&frame.bytes, 41) as i32) as i64,
        qty_lots: ((frame.bytes[49] as u64) << 16)
            | ((frame.bytes[50] as u64) << 8)
            | (frame.bytes[51] as u64),
        is_market: (aux_param1 & SPREAD_AUX1_FLAG_LEG3_MARKET) != 0,
        reduce_only: (aux_param1 & SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY) != 0,
        margin_spot,
    };

    if num_legs >= 4 {
        let leg4_hi8: u16 = if ext_mkt16 {
            (((aux_param1 >> SPREAD_AUX1_LEG4_MKT_HI8_SHIFT) & 0xFF) as u16) << 8
        } else {
            0
        };
        leg4 = WireBasketLeg {
            market_id: (((aux_param1 >> SPREAD_AUX1_LEG4_MKT_SHIFT) & 0xFF) as u16) | leg4_hi8,
            side: if (aux_param1 & SPREAD_AUX1_FLAG_LEG4_ASK) != 0 {
                OrderSide::Ask
            } else {
                OrderSide::Bid
            },
            price_ticks: (read_be32(&frame.bytes, 45) as i32) as i64,
            qty_lots: ((frame.bytes[52] as u64) << 16)
                | ((frame.bytes[53] as u64) << 8)
                | (frame.bytes[54] as u64),
            is_market: (aux_param1 & SPREAD_AUX1_FLAG_LEG4_MARKET) != 0,
            reduce_only: (aux_param1 & SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY) != 0,
            margin_spot,
        };
    }

    (num_legs, leg3, leg4)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnpackedWireBasket {
    pub header: ArenaHeader,
    pub num_legs: u8,
    pub legs: [WireBasketLeg; 4],
    pub margin_spot: bool,
}

/// Unpacks all `2..=4` legs from a `BaseOp::AtomicSpread` (`0xD`) `ArenaWireFrame`.
pub const fn unpack_wire_basket_frame(
    frame: &ArenaWireFrame,
) -> Result<UnpackedWireBasket, WireError> {
    let u = match unpack_wire_frame(frame) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if (u.header.op as u8) != (BaseOp::AtomicSpread as u8) {
        return Err(WireError::InvalidOp);
    }
    let aux1 = u.aux_param1;
    let margin_spot = (aux1 & SPREAD_AUX1_FLAG_MARGIN_SPOT) != 0;
    let b2_hi16 = if (aux1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) != 0
        || (aux1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) == 0
    {
        u.ext_qty_hi16
    } else {
        0
    };
    let s = unpack_atomic_spread_aux(u.aux_param0, aux1, b2_hi16);
    let leg1 = WireBasketLeg {
        market_id: u.header.market_id,
        side: u.header.side,
        price_ticks: u.header.price_ticks,
        qty_lots: u.header.qty_lots,
        is_market: s.leg1_is_market,
        reduce_only: s.leg1_reduce_only,
        margin_spot,
    };
    let leg2 = WireBasketLeg {
        market_id: s.leg2_market_id,
        side: s.leg2_side,
        price_ticks: s.leg2_price_ticks,
        qty_lots: s.leg2_qty_lots,
        is_market: s.leg2_is_market,
        reduce_only: s.leg2_reduce_only,
        margin_spot,
    };
    let (num_legs, leg3, leg4) = unpack_wire_basket_legs34(frame, aux1);
    Ok(UnpackedWireBasket {
        header: u.header,
        num_legs,
        legs: [leg1, leg2, leg3, leg4],
        margin_spot,
    })
}

// =============================================================================
// SipHash-2-4 Stream-Encrypted `RegisterSessionKey` (`0xA`)
// =============================================================================

pub const fn siphash24_pair64(key_lo64: u64, key_hi64: u64, w0: u64, w1: u64) -> u64 {
    let words: [u64; 3] = [w0, w1, 16u64 << 56];
    let mut v0 = key_lo64 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key_hi64 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key_lo64 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key_hi64 ^ 0x7465_6462_7974_6573;

    let mut i: usize = 0;
    while i < 3 {
        let m = words[i];
        v3 ^= m;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^= m;
        i += 1;
    }

    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^ v1 ^ v2 ^ v3
}

pub const fn siphash24_quad64(
    key_lo64: u64,
    key_hi64: u64,
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
) -> u64 {
    let words: [u64; 5] = [w0, w1, w2, w3, 32u64 << 56];
    let mut v0 = key_lo64 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key_hi64 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key_lo64 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key_hi64 ^ 0x7465_6462_7974_6573;

    let mut i: usize = 0;
    while i < 5 {
        let m = words[i];
        v3 ^= m;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^= m;
        i += 1;
    }

    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^ v1 ^ v2 ^ v3
}

pub const fn compute_session_key_wrap_pad(
    cur_key_lo64: u64,
    cur_key_hi64: u64,
    seq_hi50: u64,
    seq_lo: u16,
    account_id: u32,
    wrap_salt64: u64,
) -> (u64, u64) {
    let wrap_klo = siphash24_pair64(
        cur_key_lo64 ^ 0x5752_4150_5F4B_3031,
        cur_key_hi64 ^ 0x5752_4150_5F4B_3032,
        0x5752_4150_5F4B_4559,
        0x5345_5353_494F_4E31,
    );
    let wrap_khi = siphash24_pair64(
        cur_key_lo64 ^ 0x5752_4150_5F4B_3033,
        cur_key_hi64 ^ 0x5752_4150_5F4B_3034,
        0x5752_4150_5F4B_4559,
        0x5345_5353_494F_4E32,
    );
    let w0 = ((seq_hi50 & 0x0003_FFFF_FFFF_FFFF) << 14) | ((seq_lo & 0x3FFF) as u64);
    let pad_lo = siphash24_quad64(
        wrap_klo,
        wrap_khi,
        w0,
        wrap_salt64,
        (0x4B57_5230u64 << 32) | (account_id as u64),
        0x5041_445F_5632_0000,
    );
    let pad_hi = siphash24_quad64(
        wrap_klo,
        wrap_khi,
        w0,
        wrap_salt64,
        (0x4B57_5231u64 << 32) | (account_id as u64),
        0x5041_445F_5632_0001,
    );
    (pad_lo, pad_hi)
}

/// Packs a SipHash-2-4 stream-encrypted `BaseOp::RegisterSessionKey` (`0xA`) frame.
/// Returns `ArenaWireFrame::zeroed()` if `wrap_salt64 == 0` or `account_id > MAX_WIRE_ACCOUNT_ID`.
pub const fn pack_encrypted_register_session_key_frame(
    account_id: u32,
    seq_lo: u16,
    seq_hi50: u64,
    cur_key_lo64: u64,
    cur_key_hi64: u64,
    new_key_lo64: u64,
    new_key_hi64: u64,
    wrap_salt64: u64,
) -> ArenaWireFrame {
    if wrap_salt64 == 0 || account_id > MAX_WIRE_ACCOUNT_ID {
        return ArenaWireFrame::zeroed();
    }
    let eff_seq_lo = seq_lo & 0x3FFF;
    let hdr = ArenaHeader {
        op: BaseOp::RegisterSessionKey,
        flags: ArenaFlags::new(TimeInForce::GTC, StpMode::CancelResting),
        market_id: 0,
        account_id,
        side: OrderSide::Bid,
        seq_lo: eff_seq_lo,
        price_ticks: 0,
        qty_lots: 0,
    };
    let (pad_lo, pad_hi) = compute_session_key_wrap_pad(
        cur_key_lo64,
        cur_key_hi64,
        seq_hi50,
        eff_seq_lo,
        account_id,
        wrap_salt64,
    );
    let mut frame = pack_wire_frame(
        &hdr,
        new_key_lo64 ^ pad_lo,
        new_key_hi64 ^ pad_hi,
        seq_hi50,
        cur_key_lo64,
        cur_key_hi64,
    );
    put_be64!(frame.bytes, 41, wrap_salt64);
    frame.bytes[51] |= WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP;
    let tail_mac48 = calc_tail_siphash48(&frame.bytes, seq_hi50, cur_key_lo64, cur_key_hi64);
    frame.with_tail_siphash48(tail_mac48)
}

/// Unpacks and decrypts `(new_key_lo64, new_key_hi64, was_encrypted)` from a `RegisterSessionKey` frame.
pub const fn unpack_register_session_key_wire(
    frame: &ArenaWireFrame,
    hdr: &ArenaHeader,
    seq_hi50: u64,
    cur_key_lo64: u64,
    cur_key_hi64: u64,
    raw_aux0: u64,
    raw_aux1: u64,
    allow_legacy_plaintext: bool,
) -> Result<(u64, u64, bool), WireError> {
    let was_encrypted = (frame.bytes[51] & WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0;
    if !was_encrypted {
        if !allow_legacy_plaintext {
            return Err(WireError::UnencryptedSessionKeyWrap);
        }
        return Ok((raw_aux0, raw_aux1, false));
    }
    let wrap_salt64 = read_be64(&frame.bytes, 41);
    if wrap_salt64 == 0 {
        return Err(WireError::ZeroSessionKeyWrapSalt);
    }
    let (pad_lo, pad_hi) = compute_session_key_wrap_pad(
        cur_key_lo64,
        cur_key_hi64,
        seq_hi50,
        hdr.seq_lo,
        hdr.account_id,
        wrap_salt64,
    );
    Ok((raw_aux0 ^ pad_lo, raw_aux1 ^ pad_hi, true))
}

// =============================================================================
// 64-Byte Big-Endian Egress Execution / Query Response (`ArenaWireResponse`)
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaWireResponse {
    pub status_code: WireStatusCode,
    pub order_status: WireOrderStatus,
    pub wal_seq: u64,
    pub order_id: u64,
    pub filled_lots: u64,
    pub resting_lots: u64,
    pub avg_price_ticks: i64,
    pub best_bid_ticks: i64,
    pub best_ask_ticks: i64,
    pub fee_or_position: i64,
    pub bid_filled_lots: u64,
    pub ask_filled_lots: u64,
}

impl Default for ArenaWireResponse {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl ArenaWireResponse {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            status_code: WireStatusCode::Ok,
            order_status: WireOrderStatus::None,
            wal_seq: 0,
            order_id: 0,
            filled_lots: 0,
            resting_lots: 0,
            avg_price_ticks: 0,
            best_bid_ticks: 0,
            best_ask_ticks: 0,
            fee_or_position: 0,
            bid_filled_lots: 0,
            ask_filled_lots: 0,
        }
    }

    /// Packs the response into 8 big-endian 64-bit words (`64` bytes), encoding the `0x80`
    /// two-sided quote split-fill flag when `bid_filled_lots` or `ask_filled_lots` is non-zero.
    pub const fn pack_bytes(&self) -> [u8; ARENA_WIRE_BYTES] {
        let mut out = [0u8; ARENA_WIRE_BYTES];
        let has_quote_side_fills = (self.bid_filled_lots > 0 || self.ask_filled_lots > 0)
            && (self.bid_filled_lots <= 0xFFFF)
            && (self.wal_seq <= 0xFFFF_FFFF);
        let os_byte = ((self.order_status as u8) & 0x7F)
            | (if has_quote_side_fills { 0x80 } else { 0x00 });
        let w0_low48 = if has_quote_side_fills {
            ((self.bid_filled_lots & 0xFFFF) << 32) | (self.wal_seq & 0xFFFF_FFFF)
        } else {
            self.wal_seq & 0x0000_FFFF_FFFF_FFFF
        };
        let w0 = ((self.status_code as u64) << 56) | ((os_byte as u64) << 48) | w0_low48;

        put_be64!(out, 0, w0);
        put_be64!(out, 8, self.order_id);
        put_be64!(out, 16, self.filled_lots);
        put_be64!(out, 24, self.resting_lots);
        put_be64!(out, 32, self.avg_price_ticks as u64);
        put_be64!(out, 40, self.best_bid_ticks as u64);
        put_be64!(out, 48, self.best_ask_ticks as u64);
        put_be64!(out, 56, self.fee_or_position as u64);
        out
    }

    /// Unpacks a 64-byte big-endian response, decoding split quote fills when `os_raw & 0x80 != 0`.
    pub const fn unpack_bytes(raw: &[u8; ARENA_WIRE_BYTES]) -> Result<Self, WireError> {
        let w0 = read_be64(raw, 0);
        let status_raw = ((w0 >> 56) & 0xFF) as u8;
        let os_raw = ((w0 >> 48) & 0xFF) as u8;

        let status_code = match WireStatusCode::from_u8(status_raw) {
            Some(c) => c,
            None => return Err(WireError::InvalidStatusCode),
        };
        let order_status = match WireOrderStatus::from_u8(os_raw & 0x7F) {
            Some(s) => s,
            None => return Err(WireError::InvalidOrderStatus),
        };

        let order_id = read_be64(raw, 8);
        let filled_lots = read_be64(raw, 16);
        let resting_lots = read_be64(raw, 24);
        let avg_price_ticks = read_be64(raw, 32) as i64;
        let best_bid_ticks = read_be64(raw, 40) as i64;
        let best_ask_ticks = read_be64(raw, 48) as i64;
        let fee_or_position = read_be64(raw, 56) as i64;

        let (wal_seq, bid_filled_lots, ask_filled_lots) = if (os_raw & 0x80) != 0 {
            let wal = w0 & 0xFFFF_FFFF;
            let bid_f = (w0 >> 32) & 0xFFFF;
            let ask_f = if filled_lots >= bid_f {
                filled_lots - bid_f
            } else {
                0
            };
            (wal, bid_f, ask_f)
        } else {
            (w0 & 0x0000_FFFF_FFFF_FFFF, 0, 0)
        };

        Ok(Self {
            status_code,
            order_status,
            wal_seq,
            order_id,
            filled_lots,
            resting_lots,
            avg_price_ticks,
            best_bid_ticks,
            best_ask_ticks,
            fee_or_position,
            bid_filled_lots,
            ask_filled_lots,
        })
    }
}

// =============================================================================
// 64-Byte Cacheline-Aligned L3 Market-Data Feed (`ArenaItchFrame` / `ArenaItchMessage`)
// =============================================================================

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ItchEventType {
    OrderAdded = 0x01,
    OrderExecuted = 0x02,
    OrderModified = 0x03,
    OrderDeleted = 0x04,
    MarkAndFunding = 0x05,
    SnapshotBegin = 0x06,
    SnapshotOrder = 0x07,
    SnapshotEnd = 0x08,
    LedgerCheckpoint = 0x09,
    MarketDirectory = 0x0A,
    #[default]
    Heartbeat = 0x0F,
}

impl ItchEventType {
    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::OrderAdded),
            0x02 => Some(Self::OrderExecuted),
            0x03 => Some(Self::OrderModified),
            0x04 => Some(Self::OrderDeleted),
            0x05 => Some(Self::MarkAndFunding),
            0x06 => Some(Self::SnapshotBegin),
            0x07 => Some(Self::SnapshotOrder),
            0x08 => Some(Self::SnapshotEnd),
            0x09 => Some(Self::LedgerCheckpoint),
            0x0A => Some(Self::MarketDirectory),
            0x0F => Some(Self::Heartbeat),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ItchDeleteReason {
    #[default]
    UserCancel = 0,
    SelfTradePrevention = 1,
    CancelAllOrDisconnect = 2,
    Liquidation = 3,
}

impl ItchDeleteReason {
    #[inline]
    pub const fn from_bits2(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::UserCancel,
            1 => Self::SelfTradePrevention,
            2 => Self::CancelAllOrDisconnect,
            _ => Self::Liquidation,
        }
    }

    #[inline]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 3 {
            Some(Self::from_bits2(val))
        } else {
            None
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[inline]
pub const fn pack_itch_flags(reduce_only: bool, reason: ItchDeleteReason) -> u8 {
    (if reduce_only { 1 } else { 0 }) | (((reason as u8) & 0x03) << 2)
}

pub const fn anonymize_itch_account_id(
    account_id: u32,
    mut key_lo64: u64,
    mut key_hi64: u64,
    epoch_salt_nonce: u64,
) -> u64 {
    if account_id == 0 {
        return 0;
    }
    if epoch_salt_nonce != 0 {
        key_lo64 ^= epoch_salt_nonce.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        key_hi64 ^= epoch_salt_nonce.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    }
    if key_lo64 == 0 && key_hi64 == 0 {
        let mut z = (account_id as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        return (z ^ (z >> 31)) | (1u64 << 63);
    }
    let m = (4u64 << 56) | (account_id as u64);
    let mut v0 = key_lo64 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key_hi64 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key_lo64 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key_hi64 ^ 0x7465_6462_7974_6573 ^ m;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^= m;
    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    (v0 ^ v1 ^ v2 ^ v3) | (1u64 << 63)
}

#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaItchFrame {
    pub bytes: [u8; ARENA_ITCH_BYTES],
}

const _: [(); ARENA_ITCH_BYTES] = [(); core::mem::size_of::<ArenaItchFrame>()];
const _: [(); ARENA_ITCH_BYTES] = [(); core::mem::align_of::<ArenaItchFrame>()];

impl Default for ArenaItchFrame {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl ArenaItchFrame {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0u8; ARENA_ITCH_BYTES],
        }
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; ARENA_ITCH_BYTES]) -> Self {
        Self { bytes }
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; ARENA_ITCH_BYTES] {
        &self.bytes
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItchMarketDirectory {
    pub market_kind: u8,
    pub sub_kind: u8,
    pub base_asset_id: u8,
    pub inst_flags: u8,
    pub ref_market_1: u16,
    pub ref_market_2: u16,
    pub imr_bps: u16,
    pub symbol16: [u8; 16],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaItchMessage {
    pub event_type: ItchEventType,
    pub market_id: u16,
    pub side: OrderSide,
    pub flags: u8,
    pub itch_seq: u64,
    pub wal_seq: u64,
    pub order_id: u64,
    pub price_ticks: i64,
    pub qty_lots: u64,
    pub aux_u64: u64,
}

impl Default for ArenaItchMessage {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl ArenaItchMessage {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            event_type: ItchEventType::Heartbeat,
            market_id: 0,
            side: OrderSide::Bid,
            flags: 0,
            itch_seq: 0,
            wal_seq: 0,
            order_id: 0,
            price_ticks: 0,
            qty_lots: 0,
            aux_u64: 0,
        }
    }

    /// Computes the 64-bit SipHash-2-4 integrity checksum over `raw[0..56]`
    /// with domain keys `0x4152_454E_4149_5443` / `0x485F_5631_5F4D_4143`.
    pub const fn compute_checksum64(raw: &[u8; ARENA_ITCH_BYTES]) -> u64 {
        let k0 = ARENA_ITCH_MAC_KEY0;
        let k1 = ARENA_ITCH_MAC_KEY1;
        let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
        let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
        let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
        let mut v3 = k1 ^ 0x7465_6462_7974_6573;

        let mut off: usize = 0;
        while off < 56 {
            let m = read_be64(raw, off);
            v3 ^= m;
            sip_round!(v0, v1, v2, v3);
            sip_round!(v0, v1, v2, v3);
            v0 ^= m;
            off += 8;
        }

        let len_b = 56u64 << 56;
        v3 ^= len_b;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^= len_b;

        v2 ^= 0xFF;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^ v1 ^ v2 ^ v3
    }

    pub const fn pack_frame(&self) -> ArenaItchFrame {
        let mut bytes = [0u8; ARENA_ITCH_BYTES];
        put_be16!(bytes, 0, ARENA_ITCH_MAGIC);
        bytes[2] = ARENA_ITCH_VERSION;
        bytes[3] = self.event_type as u8;
        put_be16!(bytes, 4, self.market_id);
        bytes[6] = (self.side as u8) & 0x01;
        bytes[7] = self.flags;
        put_be64!(bytes, 8, self.itch_seq);
        put_be64!(bytes, 16, self.wal_seq);
        put_be64!(bytes, 24, self.order_id);
        put_be64!(bytes, 32, self.price_ticks as u64);
        put_be64!(bytes, 40, self.qty_lots);
        put_be64!(bytes, 48, self.aux_u64);
        let chk = Self::compute_checksum64(&bytes);
        put_be64!(bytes, 56, chk);
        ArenaItchFrame { bytes }
    }

    pub const fn unpack_and_verify(frame: &ArenaItchFrame) -> Result<Self, WireError> {
        if read_be16(&frame.bytes, 0) != ARENA_ITCH_MAGIC {
            return Err(WireError::InvalidItchMagic);
        }
        if frame.bytes[2] != ARENA_ITCH_VERSION {
            return Err(WireError::InvalidItchVersion);
        }
        let expected_chk = Self::compute_checksum64(&frame.bytes);
        let actual_chk = read_be64(&frame.bytes, 56);
        if (expected_chk ^ actual_chk) != 0 {
            return Err(WireError::InvalidItchChecksum);
        }
        let event_type = match ItchEventType::from_u8(frame.bytes[3]) {
            Some(ev) => ev,
            None => return Err(WireError::InvalidItchEventType),
        };
        Ok(Self {
            event_type,
            market_id: read_be16(&frame.bytes, 4),
            side: OrderSide::from_bit(frame.bytes[6] & 0x01),
            flags: frame.bytes[7],
            itch_seq: read_be64(&frame.bytes, 8),
            wal_seq: read_be64(&frame.bytes, 16),
            order_id: read_be64(&frame.bytes, 24),
            price_ticks: read_be64(&frame.bytes, 32) as i64,
            qty_lots: read_be64(&frame.bytes, 40),
            aux_u64: read_be64(&frame.bytes, 48),
        })
    }

    pub const fn make_ledger_checkpoint(wal_seq: u64, hash32: &[u8; 32]) -> Self {
        Self {
            event_type: ItchEventType::LedgerCheckpoint,
            market_id: 0,
            side: OrderSide::Bid,
            flags: 0,
            itch_seq: 0,
            wal_seq,
            order_id: read_be64(hash32, 0),
            price_ticks: read_be64(hash32, 8) as i64,
            qty_lots: read_be64(hash32, 16),
            aux_u64: read_be64(hash32, 24),
        }
    }

    pub const fn extract_ledger_checkpoint_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        put_be64!(out, 0, self.order_id);
        put_be64!(out, 8, self.price_ticks as u64);
        put_be64!(out, 16, self.qty_lots);
        put_be64!(out, 24, self.aux_u64);
        out
    }

    pub const fn make_market_directory(
        market_id: u16,
        wal_seq: u64,
        market_kind: u8,
        sub_kind: u8,
        base_asset_id: u8,
        inst_flags: u8,
        ref_market_1: u16,
        ref_market_2: u16,
        imr_bps: u16,
        mark_price_ticks: i64,
        symbol16: &[u8; 16],
    ) -> Self {
        let clamped_mark = if mark_price_ticks < 0 {
            0
        } else {
            mark_price_ticks
        };
        Self {
            event_type: ItchEventType::MarketDirectory,
            market_id,
            side: OrderSide::Bid,
            flags: (market_kind & 0x07) | ((sub_kind & 0x1F) << 3),
            itch_seq: 0,
            wal_seq,
            order_id: read_be64(symbol16, 0),
            price_ticks: clamped_mark,
            qty_lots: read_be64(symbol16, 8),
            aux_u64: ((base_asset_id as u64) << 56)
                | ((inst_flags as u64) << 48)
                | ((ref_market_1 as u64) << 32)
                | ((ref_market_2 as u64) << 16)
                | (imr_bps as u64),
        }
    }

    pub const fn unpack_market_directory(&self) -> ItchMarketDirectory {
        let mut symbol16 = [0u8; 16];
        put_be64!(symbol16, 0, self.order_id);
        put_be64!(symbol16, 8, self.qty_lots);
        ItchMarketDirectory {
            market_kind: self.flags & 0x07,
            sub_kind: (self.flags >> 3) & 0x1F,
            base_asset_id: ((self.aux_u64 >> 56) & 0xFF) as u8,
            inst_flags: ((self.aux_u64 >> 48) & 0xFF) as u8,
            ref_market_1: ((self.aux_u64 >> 32) & 0xFFFF) as u16,
            ref_market_2: ((self.aux_u64 >> 16) & 0xFFFF) as u16,
            imr_bps: (self.aux_u64 & 0xFFFF) as u16,
            symbol16,
        }
    }
}

// =============================================================================
// 16-Byte Client Subscription / Sequence Gap-Replay Request (`ArenaItchSubscribeReq`)
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArenaItchSubscribeReq {
    pub market_id: u16,
    pub req_flags: u16,
    pub from_itch_seq: u64,
}

impl Default for ArenaItchSubscribeReq {
    #[inline]
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl ArenaItchSubscribeReq {
    #[inline]
    pub const fn new(market_id: u16, req_flags: u16, from_itch_seq: u64) -> Self {
        Self {
            market_id,
            req_flags,
            from_itch_seq,
        }
    }

    pub const fn pack_bytes(&self) -> [u8; ARENA_ITCH_REQ_BYTES] {
        let mut out = [0u8; ARENA_ITCH_REQ_BYTES];
        put_be32!(out, 0, ARENA_ITCH_REQ_MAGIC);
        put_be16!(out, 4, self.market_id);
        put_be16!(out, 6, self.req_flags);
        put_be64!(out, 8, self.from_itch_seq);
        out
    }

    pub const fn unpack_bytes(raw: &[u8; ARENA_ITCH_REQ_BYTES]) -> Result<Self, WireError> {
        if read_be32(raw, 0) != ARENA_ITCH_REQ_MAGIC {
            return Err(WireError::InvalidItchReqMagic);
        }
        Ok(Self {
            market_id: read_be16(raw, 4),
            req_flags: read_be16(raw, 6),
            from_itch_seq: read_be64(raw, 8),
        })
    }
}

// =============================================================================
// `#![no_std]` `const fn` Ethereum Keccak-256 & Sovereign Ledger Tip (`ARENA_LEDGER_TIP_V2_1`)
// =============================================================================

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const fn keccak_f1600(mut st: [u64; 25]) -> [u64; 25] {
    let mut round: usize = 0;
    while round < 24 {
        let mut bc = [0u64; 5];
        let mut i: usize = 0;
        while i < 5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            i += 1;
        }
        i = 0;
        while i < 5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            let mut j: usize = 0;
            while j < 25 {
                st[j + i] ^= t;
                j += 5;
            }
            i += 1;
        }

        let mut t = st[1];
        i = 0;
        while i < 24 {
            let j = KECCAK_PI[i];
            let tmp = st[j];
            st[j] = t.rotate_left(KECCAK_ROT[i]);
            t = tmp;
            i += 1;
        }

        let mut j: usize = 0;
        while j < 25 {
            i = 0;
            while i < 5 {
                bc[i] = st[j + i];
                i += 1;
            }
            i = 0;
            while i < 5 {
                st[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                i += 1;
            }
            j += 5;
        }

        st[0] ^= KECCAK_RC[round];
        round += 1;
    }
    st
}

/// Computes the 32-byte Ethereum `Keccak-256` digest (`0x01` domain separator, 136-byte rate)
/// in `#![no_std]` `const fn` Rust (`1.75+`).
pub const fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut st = [0u64; 25];
    let n = data.len();
    let mut off: usize = 0;

    while n - off >= 136 {
        let mut lane_idx: usize = 0;
        while lane_idx < 17 {
            let b = off + lane_idx * 8;
            let lane = u64::from_le_bytes([
                data[b],
                data[b + 1],
                data[b + 2],
                data[b + 3],
                data[b + 4],
                data[b + 5],
                data[b + 6],
                data[b + 7],
            ]);
            st[lane_idx] ^= lane;
            lane_idx += 1;
        }
        st = keccak_f1600(st);
        off += 136;
    }

    let mut tail = [0u8; 136];
    let rem = n - off;
    let mut k: usize = 0;
    while k < rem {
        tail[k] = data[off + k];
        k += 1;
    }
    tail[rem] ^= 0x01;
    tail[135] ^= 0x80;

    let mut lane_idx: usize = 0;
    while lane_idx < 17 {
        let b = lane_idx * 8;
        let lane = u64::from_le_bytes([
            tail[b],
            tail[b + 1],
            tail[b + 2],
            tail[b + 3],
            tail[b + 4],
            tail[b + 5],
            tail[b + 6],
            tail[b + 7],
        ]);
        st[lane_idx] ^= lane;
        lane_idx += 1;
    }
    st = keccak_f1600(st);

    let mut out = [0u8; 32];
    let mut w: usize = 0;
    while w < 4 {
        let lb = st[w].to_le_bytes();
        let mut bi: usize = 0;
        while bi < 8 {
            out[w * 8 + bi] = lb[bi];
            bi += 1;
        }
        w += 1;
    }
    out
}

/// Returns the canonical 32-byte genesis hash `Keccak256("ARENA_SOVEREIGN_LEDGER_GENESIS_V2_0")`.
#[inline]
pub const fn sovereign_ledger_genesis_hash() -> [u8; 32] {
    keccak256(ARENA_SOVEREIGN_LEDGER_GENESIS_DOMAIN)
}

/// Computes the 32-byte `ARENA_LEDGER_TIP_V2_1` `Keccak-256` commitment digest signed by the
/// operator at `GET /ledger/tip`:
/// `Keccak256("ARENA_LEDGER_TIP_V2_1" || be64(chain_id) || clearinghouse_20B || be64(wal_seq) || ledger_chain_hash_32B || state_root_32B)`.
pub const fn compute_ledger_tip_digest(
    wal_seq: u64,
    ledger_chain_hash: &[u8; 32],
    state_root: &[u8; 32],
    chain_id: u64,
    clearinghouse_address: Option<&[u8; 20]>,
) -> [u8; 32] {
    let mut payload = [0u8; 121];
    let mut i: usize = 0;
    while i < 21 {
        payload[i] = ARENA_LEDGER_TIP_DOMAIN[i];
        i += 1;
    }
    put_be64!(payload, 21, chain_id);
    match clearinghouse_address {
        Some(addr) => {
            let mut a: usize = 0;
            while a < 20 {
                payload[29 + a] = addr[a];
                a += 1;
            }
        }
        None => {}
    }
    put_be64!(payload, 49, wal_seq);
    let mut h: usize = 0;
    while h < 32 {
        payload[57 + h] = ledger_chain_hash[h];
        payload[89 + h] = state_root[h];
        h += 1;
    }
    keccak256(&payload)
}

// =============================================================================
// Golden Hex Vector & Round-Trip Verification Tests (`#[cfg(test)]`)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex byte"),
        }
    }

    const fn decode_hex_64(hex: &[u8; 128]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut i: usize = 0;
        while i < 64 {
            out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn decode_hex_16(hex: &[u8; 32]) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut i: usize = 0;
        while i < 16 {
            out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn golden_vector_1_new_order_post_only_slide() {
        let expected = decode_hex_64(
            b"0300010003e900010000004c4b400000002710cd2a7b07c801000000000000002a00000000000000080000000000000000000000000000003c32e487790ea1e0",
        );

        let aux_params = OrderAux1Params {
            post_only_slide: true,
            ..OrderAux1Params::new()
        };
        let aux1 = aux_params.pack();
        assert_eq!(aux1, 0x08);

        let hdr = ArenaHeader {
            op: BaseOp::NewOrder,
            flags: ArenaFlags::new(TimeInForce::PostOnly, StpMode::CancelResting),
            market_id: 1,
            account_id: 1001,
            side: OrderSide::Bid,
            seq_lo: 1,
            price_ticks: 5_000_000,
            qty_lots: 10_000,
        };
        let frame = pack_wire_frame(
            &hdr,
            42,
            aux1,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(frame.bytes, expected);
        assert_eq!(frame.get_pre_siphash40(), 0xcd2a_7b07_c8);
        assert_eq!(frame.get_tail_siphash48(), 0x3c32_e487_790e);

        let unpacked = unpack_and_verify_wire_frame(
            &frame,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        )
        .unwrap();
        assert_eq!(unpacked.header, hdr);
        assert_eq!(unpacked.aux_param0, 42);
        assert_eq!(unpacked.aux_param1, 0x08);

        let mut tampered = frame;
        tampered.bytes[24] = 0x02;
        assert_eq!(unpack_wire_frame(&tampered), Err(WireError::InvalidVersion));

        let mut bad_trailer = frame;
        bad_trailer.bytes[63] = 0xE1;
        assert_eq!(
            unpack_wire_frame(&bad_trailer),
            Err(WireError::InvalidTrailer)
        );
    }

    #[test]
    fn golden_vector_2_two_sided_quote_replace_50bit_ask_qty() {
        let expected = decode_hex_64(
            b"c300010003e900020000004c494c00000061a874e3c4b2200100000000004c4d3400000203a43b740000010000000000000309010000000054b57ec1f07ea1e0",
        );

        let key_lo: u64 = 0x1122_3344_5566_7788;
        let key_hi: u64 = 0x99AA_BBCC_DDEE_FF00;

        let quote = TwoSidedQuoteReplace {
            flags: ArenaFlags::new(TimeInForce::PostOnly, StpMode::CancelResting),
            market_id: 1,
            account_id: 1001,
            seq_lo: 2,
            bid_price_ticks: 4_999_500,
            bid_qty_lots: 25_000,
            ask_price_ticks: 5_000_500,
            ask_qty_lots: 50_000_000_000,
            post_only_slide: true,
            client_tag: 777,
            ladder_by_tag: true,
            ..TwoSidedQuoteReplace::new()
        };

        let frame = quote.pack_frame(1, key_lo, key_hi);
        assert_eq!(frame.bytes, expected);
        assert_eq!(read_be16(&frame.bytes, 41), 1);
        assert_eq!(unpack_quote_client_tag(&frame), 777);
        assert!(unpack_quote_ladder_by_tag(&frame));

        let verified = unpack_and_verify_wire_frame(&frame, 1, key_lo, key_hi).unwrap();
        assert_eq!(
            unpack_quote_ask_qty(&frame, verified.aux_param1),
            50_000_000_000
        );

        let decoded_quote = TwoSidedQuoteReplace::unpack_frame(&frame).unwrap();
        assert_eq!(decoded_quote, quote);
    }

    #[test]
    fn golden_vector_3_encrypted_register_session_key() {
        let expected = decode_hex_64(
            b"a0000000002a00070000000000000000000000d37ee0228b010ed42c497af0562e80af8757fe9894eb1122334455667788000004000000008562844d968ca1e0",
        );

        let cur_lo: u64 = 0x1122_3344_5566_7788;
        let cur_hi: u64 = 0x99AA_BBCC_DDEE_FF00;
        let new_lo: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let new_hi: u64 = 0x0123_4567_89AB_CDEF;
        let salt: u64 = 0x1122_3344_5566_7788;

        let frame = pack_encrypted_register_session_key_frame(
            42, 7, 77, cur_lo, cur_hi, new_lo, new_hi, salt,
        );
        assert_eq!(frame.bytes, expected);

        let unpacked = unpack_and_verify_wire_frame(&frame, 77, cur_lo, cur_hi).unwrap();
        assert_eq!(unpacked.header.op, BaseOp::RegisterSessionKey);
        assert_eq!(unpacked.header.account_id, 42);
        assert_eq!(unpacked.header.seq_lo, 7);

        let (dec_lo, dec_hi, was_enc) = unpack_register_session_key_wire(
            &frame,
            &unpacked.header,
            77,
            cur_lo,
            cur_hi,
            unpacked.aux_param0,
            unpacked.aux_param1,
            false,
        )
        .unwrap();
        assert!(was_enc);
        assert_eq!(dec_lo, new_lo);
        assert_eq!(dec_hi, new_hi);
    }

    #[test]
    fn golden_vector_4_arena_wire_response_standard_and_split_fill() {
        let expected_standard = decode_hex_64(
            b"000300000000006500000000000023290000000000002710000000000000000000000000004c4b4000000000004c4adc00000000004c4ba4fffffffffff85ee0",
        );
        let resp_standard = ArenaWireResponse {
            status_code: WireStatusCode::Ok,
            order_status: WireOrderStatus::Filled,
            wal_seq: 101,
            order_id: 9001,
            filled_lots: 10_000,
            resting_lots: 0,
            avg_price_ticks: 5_000_000,
            best_bid_ticks: 4_999_900,
            best_ask_ticks: 5_000_100,
            fee_or_position: -500_000,
            bid_filled_lots: 0,
            ask_filled_lots: 0,
        };
        let raw_standard = resp_standard.pack_bytes();
        assert_eq!(raw_standard, expected_standard);
        let decoded_standard = ArenaWireResponse::unpack_bytes(&raw_standard).unwrap();
        assert_eq!(decoded_standard, resp_standard);

        let expected_split = decode_hex_64(
            b"008200c800000066000000000000232a00000000000001f400000000000005dc000000000000232b00000000004c494c00000000004c4d34ffffffffffff9e58",
        );
        let resp_split = ArenaWireResponse {
            status_code: WireStatusCode::Ok,
            order_status: WireOrderStatus::PartiallyFilled,
            wal_seq: 102,
            order_id: 9002,
            filled_lots: 500,
            resting_lots: 1_500,
            avg_price_ticks: 9003,
            best_bid_ticks: 4_999_500,
            best_ask_ticks: 5_000_500,
            fee_or_position: -25_000,
            bid_filled_lots: 200,
            ask_filled_lots: 300,
        };
        let raw_split = resp_split.pack_bytes();
        assert_eq!(raw_split, expected_split);
        assert_eq!(raw_split[1] & 0x80, 0x80);
        let decoded_split = ArenaWireResponse::unpack_bytes(&raw_split).unwrap();
        assert_eq!(decoded_split, resp_split);
    }

    #[test]
    fn golden_vector_5_itch_frame_and_subscribe_req() {
        let expected_itch = decode_hex_64(
            b"414901010001000000000000000000650000000000000037000000000000232900000000004c4b40000000000000271000000000000003e97fa38baed2f4ba89",
        );
        let msg = ArenaItchMessage {
            event_type: ItchEventType::OrderAdded,
            market_id: 1,
            side: OrderSide::Bid,
            flags: 0,
            itch_seq: 101,
            wal_seq: 55,
            order_id: 9001,
            price_ticks: 5_000_000,
            qty_lots: 10_000,
            aux_u64: 1001,
        };
        let itch_frame = msg.pack_frame();
        assert_eq!(itch_frame.bytes, expected_itch);
        assert_eq!(
            ArenaItchMessage::compute_checksum64(&itch_frame.bytes),
            0x7fa3_8bae_d2f4_ba89
        );

        let decoded_msg = ArenaItchMessage::unpack_and_verify(&itch_frame).unwrap();
        assert_eq!(decoded_msg, msg);

        let mut bad_itch = itch_frame;
        bad_itch.bytes[47] ^= 0x01;
        assert_eq!(
            ArenaItchMessage::unpack_and_verify(&bad_itch),
            Err(WireError::InvalidItchChecksum)
        );

        let expected_req = decode_hex_16(b"41495251000100030000000000000065");
        let sub_req = ArenaItchSubscribeReq::new(
            1,
            ITCH_REQ_FLAG_REPLAY_FROM_SEQ | ITCH_REQ_FLAG_FULL_SNAPSHOT,
            101,
        );
        let raw_req = sub_req.pack_bytes();
        assert_eq!(raw_req, expected_req);
        let decoded_req = ArenaItchSubscribeReq::unpack_bytes(&raw_req).unwrap();
        assert_eq!(decoded_req, sub_req);
    }

    #[test]
    fn atomic_spread_50bit_leg2_round_trip() {
        let spread = AtomicSpread {
            stp: StpMode::CancelIncoming,
            account_id: 1001,
            seq_lo: 19,
            leg1_market_id: 1,
            leg1_side: OrderSide::Bid,
            leg1_price_ticks: -125_000,
            leg1_qty_lots: 50_000,
            leg1_is_market: false,
            leg1_reduce_only: true,
            leg2_market_id: 2,
            leg2_side: OrderSide::Ask,
            leg2_price_ticks: -250_000,
            leg2_qty_lots: 75_000_000_000,
            leg2_is_market: true,
            leg2_reduce_only: false,
            margin_spot: true,
        };
        let frame = spread.pack_frame(9, DEFAULT_DEV_KEY_LO64, DEFAULT_DEV_KEY_HI64);
        let verified =
            unpack_and_verify_wire_frame(&frame, 9, DEFAULT_DEV_KEY_LO64, DEFAULT_DEV_KEY_HI64)
                .unwrap();
        assert_eq!(verified.header.op, BaseOp::AtomicSpread);
        assert_eq!(verified.header.flags.tif, TimeInForce::IOC);

        let decoded = AtomicSpread::unpack_frame(&frame).unwrap();
        assert_eq!(decoded, spread);
    }

    const fn decode_hex_32(hex: &[u8; 64]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i: usize = 0;
        while i < 32 {
            out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn decode_hex_20(hex: &[u8; 40]) -> [u8; 20] {
        let mut out = [0u8; 20];
        let mut i: usize = 0;
        while i < 20 {
            out[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn golden_vector_6_keccak256_and_ledger_tip_digest_v2_1() {
        const EMPTY_DIGEST: [u8; 32] = keccak256(b"");
        const ABC_DIGEST: [u8; 32] = keccak256(b"abc");
        const GENESIS: [u8; 32] = sovereign_ledger_genesis_hash();
        const STATE_ROOT: [u8; 32] = keccak256(b"ARENA_TEST_STATE_ROOT_V494");

        assert_eq!(
            EMPTY_DIGEST,
            decode_hex_32(b"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            ABC_DIGEST,
            decode_hex_32(b"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
        assert_eq!(
            GENESIS,
            decode_hex_32(b"1c444338adbe21e084325e469dbc56c4580d094b380d8e8ce1b2dd6bd6625249")
        );
        assert_eq!(
            STATE_ROOT,
            decode_hex_32(b"588bacd8c6b8188d673057e712c097a6634ce129528861358e9bc6a54500c702")
        );

        let mut long_msg = [0u8; 200];
        let mut idx: usize = 0;
        while idx < 200 {
            long_msg[idx] = ((idx * 37 + 13) & 0xFF) as u8;
            idx += 1;
        }
        assert_eq!(
            keccak256(&long_msg),
            decode_hex_32(b"3e36ba3d69c2262f69d3a6f25be64ec0e6924de9c201110180aa831f8a366de5")
        );

        const CLEARINGHOUSE_20: [u8; 20] =
            decode_hex_20(b"11223344556677889900aabbccddeeff00112233");
        const TIP_84532: [u8; 32] =
            compute_ledger_tip_digest(42_001, &GENESIS, &STATE_ROOT, 84_532, Some(&CLEARINGHOUSE_20));
        const TIP_ZERO: [u8; 32] =
            compute_ledger_tip_digest(42_001, &GENESIS, &STATE_ROOT, 0, None);

        assert_eq!(
            TIP_84532,
            decode_hex_32(b"92268bdcc50579e70aef02e7ea93def43c8da7965e07013af18b1f2218a8ebac")
        );
        assert_eq!(
            TIP_ZERO,
            decode_hex_32(b"a658366496aac8c43b384aebaf22898a71a1c4bf11a5df34b40b19058726be1d")
        );
    }

    #[test]
    fn golden_vector_7_wire_basket_3leg_and_4leg_ext_mkt16() {
        let expected_3leg = decode_hex_64(
            b"d600010003e900070000004c4b4000000027103d87facb310100020000000493e002007100000249f0fffffb1e000000000061a800000011b81e7aab4934a1e0",
        );
        let legs3 = [
            WireBasketLeg {
                market_id: 1,
                side: OrderSide::Bid,
                price_ticks: 5_000_000,
                qty_lots: 10_000,
                is_market: false,
                reduce_only: false,
                margin_spot: true,
            },
            WireBasketLeg {
                market_id: 2,
                side: OrderSide::Ask,
                price_ticks: 300_000,
                qty_lots: 150_000,
                is_market: false,
                reduce_only: true,
                margin_spot: false,
            },
            WireBasketLeg {
                market_id: 17,
                side: OrderSide::Bid,
                price_ticks: -1_250,
                qty_lots: 25_000,
                is_market: true,
                reduce_only: false,
                margin_spot: false,
            },
        ];
        let f3 = try_pack_wire_basket_frame(
            1001,
            &legs3,
            StpMode::CancelIncoming,
            false,
            7,
            3,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        )
        .unwrap();
        assert_eq!(f3.bytes, expected_3leg);

        let f3_arr = pack_wire_basket_frame(
            1001,
            3,
            &[legs3[0], legs3[1], legs3[2], WireBasketLeg::zeroed()],
            StpMode::CancelIncoming,
            false,
            7,
            3,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(f3_arr, f3);

        let v3 =
            unpack_and_verify_wire_frame(&f3, 3, DEFAULT_DEV_KEY_LO64, DEFAULT_DEV_KEY_HI64)
                .unwrap();
        let (n3, u_leg3, _u_leg4) = unpack_wire_basket_legs34(&f3, v3.aux_param1);
        assert_eq!(n3, 3);
        assert_eq!(u_leg3.market_id, 17);
        assert_eq!(u_leg3.side, OrderSide::Bid);
        assert_eq!(u_leg3.price_ticks, -1_250);
        assert_eq!(u_leg3.qty_lots, 25_000);
        assert!(u_leg3.is_market);
        assert!(!u_leg3.reduce_only);
        assert!(u_leg3.margin_spot);

        let full3 = unpack_wire_basket_frame(&f3).unwrap();
        assert_eq!(full3.num_legs, 3);
        assert!(full3.margin_spot);
        assert_eq!(full3.legs[1].qty_lots, 150_000);
        assert_eq!(full3.legs[2].price_ticks, -1_250);

        let expected_4leg = decode_hex_64(
            b"d200010003e900080000004c4b40000000271089e6e8aa6b0100020000000493e0b503e9020107a120ffff3cb0000b71b001e24009fbf12cbc4735670036a1e0",
        );
        let legs4 = [
            WireBasketLeg::new(1, OrderSide::Bid, 5_000_000, 10_000),
            WireBasketLeg {
                market_id: 2,
                side: OrderSide::Ask,
                price_ticks: 300_000,
                qty_lots: 500_000,
                is_market: true,
                reduce_only: false,
                margin_spot: false,
            },
            WireBasketLeg {
                market_id: 300,
                side: OrderSide::Ask,
                price_ticks: -50_000,
                qty_lots: 123_456,
                is_market: false,
                reduce_only: true,
                margin_spot: false,
            },
            WireBasketLeg {
                market_id: 515,
                side: OrderSide::Bid,
                price_ticks: 750_000,
                qty_lots: 654_321,
                is_market: true,
                reduce_only: true,
                margin_spot: true,
            },
        ];
        let f4 = try_pack_wire_basket_frame(
            1001,
            &legs4,
            StpMode::CancelResting,
            false,
            8,
            3,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        )
        .unwrap();
        assert_eq!(f4.bytes, expected_4leg);

        let v4 =
            unpack_and_verify_wire_frame(&f4, 3, DEFAULT_DEV_KEY_LO64, DEFAULT_DEV_KEY_HI64)
                .unwrap();
        let (n4, d_leg3, d_leg4) = unpack_wire_basket_legs34(&f4, v4.aux_param1);
        assert_eq!(n4, 4);
        assert_eq!(d_leg3.market_id, 300);
        assert_eq!(d_leg3.side, OrderSide::Ask);
        assert_eq!(d_leg3.price_ticks, -50_000);
        assert_eq!(d_leg3.qty_lots, 123_456);
        assert!(!d_leg3.is_market);
        assert!(d_leg3.reduce_only);
        assert_eq!(d_leg4.market_id, 515);
        assert_eq!(d_leg4.side, OrderSide::Bid);
        assert_eq!(d_leg4.price_ticks, 750_000);
        assert_eq!(d_leg4.qty_lots, 654_321);
        assert!(d_leg4.is_market);
        assert!(d_leg4.reduce_only);
        assert!(d_leg4.margin_spot);

        let full4 = unpack_wire_basket_frame(&f4).unwrap();
        assert_eq!(full4.num_legs, 4);
        assert_eq!(full4.legs[1].qty_lots, 500_000);
        assert_eq!(full4.legs[2].market_id, 300);
        assert_eq!(full4.legs[3].market_id, 515);

        // Out-of-range leg count or leg3 qty must fail closed
        assert_eq!(
            try_pack_wire_basket_frame(
                1001,
                &[legs4[0]],
                StpMode::CancelResting,
                false,
                1,
                1,
                DEFAULT_DEV_KEY_LO64,
                DEFAULT_DEV_KEY_HI64,
            ),
            Err(WireError::InvalidFields)
        );
        // Multi-leg basket frames must be rejected by 2-leg AtomicSpread::unpack_frame
        assert_eq!(
            AtomicSpread::unpack_frame(&f3),
            Err(WireError::InvalidFields)
        );
    }

    #[test]
    fn priority_auction_fallible_be_and_ext_clear_round_trip() {
        let mut scratch = [0u8; 8];
        assert!(try_write_be16(&mut scratch, 0, 0x1234));
        assert!(!try_write_be16(&mut scratch, 7, 0x1234));
        assert_eq!(try_read_be16(&scratch, 0), Some(0x1234));
        assert_eq!(try_read_be16(&scratch, 7), None);

        assert!(try_write_be32(&mut scratch, 2, 0x89AB_CDEF));
        assert!(!try_write_be32(&mut scratch, 5, 0x89AB_CDEF));
        assert_eq!(try_read_be32(&scratch, 2), Some(0x89AB_CDEF));
        assert_eq!(try_read_be32(&scratch, 5), None);

        assert!(try_write_be64(&mut scratch, 0, 0x0123_4567_89AB_CDEF));
        assert!(!try_write_be64(&mut scratch, 1, 0x0123_4567_89AB_CDEF));
        assert_eq!(try_read_be64(&scratch, 0), Some(0x0123_4567_89AB_CDEF));
        assert_eq!(try_read_be64(&scratch, 1), None);

        struct FixedFmtBuf {
            buf: [u8; 128],
            len: usize,
        }
        impl core::fmt::Write for FixedFmtBuf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let b = s.as_bytes();
                if self.len + b.len() > self.buf.len() {
                    return Err(core::fmt::Error);
                }
                self.buf[self.len..self.len + b.len()].copy_from_slice(b);
                self.len += b.len();
                Ok(())
            }
        }
        let mut fmt_out = FixedFmtBuf {
            buf: [0u8; 128],
            len: 0,
        };
        core::fmt::Write::write_fmt(&mut fmt_out, format_args!("{}", WireError::InvalidMac))
            .unwrap();
        assert_eq!(
            &fmt_out.buf[..fmt_out.len],
            WireError::InvalidMac.as_str().as_bytes()
        );

        let hdr = ArenaHeader {
            op: BaseOp::NewOrder,
            flags: ArenaFlags::new(TimeInForce::IOC, StpMode::CancelResting),
            market_id: 1,
            account_id: 1001,
            side: OrderSide::Bid,
            seq_lo: 5,
            price_ticks: 5_000_000,
            qty_lots: 10_000,
        };
        let base = pack_wire_frame(
            &hdr,
            99,
            0,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        let with_ext = pack_quote_ext_tag_and_ladder(
            pack_order_ext_stp_decrement_cancel(
                pack_order_ext_priority_fee_ppm(
                    base,
                    1_250,
                    1,
                    DEFAULT_DEV_KEY_LO64,
                    DEFAULT_DEV_KEY_HI64,
                ),
                true,
                1,
                DEFAULT_DEV_KEY_LO64,
                DEFAULT_DEV_KEY_HI64,
            ),
            42,
            true,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(peek_wire_priority_score(&with_ext, true), 12_500);
        let cleared = pack_quote_ext_tag_and_ladder(
            pack_order_ext_stp_decrement_cancel(
                pack_order_ext_priority_fee_ppm(
                    with_ext,
                    0,
                    1,
                    DEFAULT_DEV_KEY_LO64,
                    DEFAULT_DEV_KEY_HI64,
                ),
                false,
                1,
                DEFAULT_DEV_KEY_LO64,
                DEFAULT_DEV_KEY_HI64,
            ),
            0,
            false,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(cleared, base);
        assert_eq!(peek_wire_priority_score(&cleared, true), 0);

        assert!(liq_mode_flags_valid(0));
        assert!(liq_mode_flags_valid(LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP));
        assert!(!liq_mode_flags_valid(
            LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP | LIQ_AUX1_FLAG_AUTO_CROSS_ARB
        ));

        let liq_hdr = ArenaHeader {
            op: BaseOp::LiquidateAccount,
            flags: ArenaFlags::new(TimeInForce::IOC, StpMode::CancelResting),
            market_id: 4,
            account_id: 101,
            side: OrderSide::Bid,
            seq_lo: 6,
            price_ticks: 0,
            qty_lots: 1_000,
        };
        let liq_frame = pack_wire_liq_bounty_rebate_bid_bps(
            pack_wire_frame(
                &liq_hdr,
                202,
                LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP,
                1,
                DEFAULT_DEV_KEY_LO64,
                DEFAULT_DEV_KEY_HI64,
            ),
            2_500,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(
            unpack_wire_liq_bounty_rebate_bid_bps(
                &liq_frame,
                BaseOp::LiquidateAccount,
                202,
                LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP
            ),
            2_500
        );
        assert_eq!(peek_wire_priority_score(&liq_frame, true), 125_000);
        assert_eq!(peek_wire_priority_score(&liq_frame, false), 0);

        let spread_frame = pack_wire_express_surplus_bid_bps(
            AtomicSpread {
                account_id: 101,
                seq_lo: 7,
                leg1_market_id: 1,
                leg1_side: OrderSide::Bid,
                leg1_price_ticks: 5_000_000,
                leg1_qty_lots: 1_000,
                leg2_market_id: 4,
                leg2_side: OrderSide::Ask,
                leg2_price_ticks: 5_001_000,
                leg2_qty_lots: 1_000,
                ..AtomicSpread::new()
            }
            .pack_frame(1, DEFAULT_DEV_KEY_LO64, DEFAULT_DEV_KEY_HI64),
            1_500,
            1,
            DEFAULT_DEV_KEY_LO64,
            DEFAULT_DEV_KEY_HI64,
        );
        assert_eq!(peek_wire_priority_score(&spread_frame, true), 1_500);
    }
}
