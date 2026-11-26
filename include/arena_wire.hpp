// =============================================================================
// HEADER: include/arena_wire.hpp
// PROJECT: Arena Exchange v4.9
// PURPOSE:
//   1. 64-byte (512-bit) cacheline-aligned binary order-entry wire protocol
//      (`ArenaWireFrame` and `ArenaWireResponse`) for ultra-low-latency TCP &
//      UDP HFT trading, authenticated by dual SipHash MACs (`PreSipHash40`
//      header MAC + `TailSipHash48` payload MAC), including `Cancel-On-Disconnect`
//      (`SetCancelOnDisconnect`) and atomic two-sided market-maker quoting
//      (`TwoSidedQuoteReplace`).
//   2. 64-byte (512-bit) cacheline-aligned binary tick-by-tick L3 incremental
//      market-data protocol (`ArenaItchFrame` and 16-byte `ArenaItchSubscribeReq`)
//      with SipHash-2-4 integrity checksums, monotonic sequence numbers, full L3
//      book snapshot framing, and sequence gap-recovery replay.
// =============================================================================
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace arena::wire {

inline constexpr std::size_t ARENA_WIRE_BITS  = 512;
inline constexpr std::size_t ARENA_WIRE_BYTES = 64;

enum class BaseOp : uint8_t {
    NewOrder              = 0x0, // Submit limit or market order (GTC, IOC, FOK, PostOnly)
    Cancel                = 0x1, // Cancel resting order by order_id (in aux_param0)
    ModifyInPlace         = 0x2, // Modify resting order price/qty (order_id in aux_param0)
    CancelAllAccount      = 0x3, // Cancel resting orders for account (market_id=0 -> all; aux0=client_tag_filter, aux1=market_bitmask)
    DepositCollateral     = 0x4, // Credit USD micro-units (aux_param0=0) or base asset lots (aux_param0=asset_id)
    WithdrawCollateral    = 0x5, // Debit free USD micro-units or base asset lots
    QueryBookBbo          = 0x6, // Query best bid/ask prices & depths for market_id
    QueryAccount          = 0x7, // Query account free USD, equity, margin & perp position
    UpdateMarkFunding     = 0x8, // Update perp mark price (price_ticks) & funding delta (signed aux_param0)
    LiquidateAccount      = 0x9, // Liquidate underwater perp account (target in aux_param0) OR set Exact-Tick Knock-Out Barrier (aux0=0 / LIQ_AUX1_FLAG_SET_KNOCKOUT, price_ticks)
    RegisterSessionKey    = 0xA, // Rotate account's 128-bit SipHash session key (lo in aux0, hi in aux1)
    SetCancelOnDisconnect = 0xB, // Arm/disarm TCP session Cancel-On-Disconnect (enable in aux0, timeout_ms in aux1)
    TwoSidedQuoteReplace  = 0xC, // Atomic Bid(price_ticks, qty_lots) + Ask(aux0, 50-bit ask_qty via aux1 + bytes[41..42]) quote refresh
    AtomicSpread          = 0xD, // Atomic 2-leg FOK spread: Leg1 in header + Leg2 in (aux_param0, aux_param1)
    MintRedeemSet         = 0xE, // Complete-Set Mint/Redeem (BoundedClaim) or Bonding-Curve Mint/Burn (Spot): Bid=Mint, Ask=Redeem
    Heartbeat             = 0xF  // Authenticated keepalive / anti-replay check
};

enum class OrderSide : uint8_t {
    Bid = 0b00,
    Ask = 0b01
};

enum class TimeInForce : uint8_t {
    GTC      = 0b00, // Good-Til-Canceled (rests remainder in L3 FIFO book)
    IOC      = 0b01, // Immediate-Or-Cancel (fills crossable, cancels remainder)
    FOK      = 0b10, // Fill-Or-Kill (fills 100% immediately or rejects without mutation)
    PostOnly = 0b11  // Maker-Only (rejects if order would cross opposite BBO)
};

enum class StpMode : uint8_t {
    CancelResting  = 0b00, // Cancel resting self-order and continue matching
    CancelIncoming = 0b01, // Cancel incoming remainder upon encountering self-order
    CancelBoth     = 0b10, // Cancel resting self-order AND stop incoming remainder
    None           = 0b11  // Self-trade prevention disabled (or pod-scoped client_tag crossing)
};

enum class WireStatusCode : uint8_t {
    Ok                   = 0x00,
    RejectInvalidMac     = 0x01,
    RejectReplayOrStale  = 0x02,
    RejectSessionCap     = 0x03,
    RejectInvalidOp      = 0x04,
    RejectInvalidMarket  = 0x05,
    RejectInvalidParams  = 0x06,
    RejectInsufficient   = 0x07, // Insufficient free balance, margin, or base asset
    RejectOrderNotFound  = 0x08,
    RejectUnauthorized   = 0x09, // Attempt to cancel/modify another account's order
    RejectPostOnlyCross  = 0x0A,
    RejectFokUnfillable  = 0x0B,
    RejectNotLiquidatable= 0x0C,
    RejectWalIoError     = 0x0D,
    RejectUnbonded       = 0x0E, // Account equity below `--min-wire-bond-usd` collateral bond
    RejectRiskLimit      = 0x0F  // Rolling Market Maker Protection (MMP) cooldown active
};

enum class WireOrderStatus : uint8_t {
    None            = 0x00,
    Resting         = 0x01,
    PartiallyFilled = 0x02, // Filled partially and resting (GTC) or remainder canceled (IOC)
    Filled          = 0x03,
    Canceled        = 0x04,
    Modified        = 0x05,
    Rejected        = 0x06
};

struct ArenaFlags {
    TimeInForce tif = TimeInForce::GTC;           // bits [1:0]
    StpMode     stp = StpMode::CancelResting;     // bits [3:2]

    constexpr uint8_t pack4() const noexcept {
        return static_cast<uint8_t>(
            ((static_cast<uint8_t>(stp) & 0x3U) << 2U) |
            (static_cast<uint8_t>(tif) & 0x3U)
        );
    }

    static constexpr ArenaFlags unpack4(uint8_t nib) noexcept {
        return ArenaFlags{
            .tif = static_cast<TimeInForce>(nib & 0x3U),
            .stp = static_cast<StpMode>((nib >> 2U) & 0x3U)
        };
    }
};

// Aux flags carried in `aux_param1` for `NewOrder` and `TwoSidedQuoteReplace`
//   For `BaseOp::NewOrder`:
//     bits [7:0]   : order attribute flags (reduce_only, is_market, cancel_on_disconnect, post_only_slide,
//                    primary_peg, midpoint_peg, margin_spot, iceberg; dark_midpoint = midpoint_peg | iceberg with display_qty_lots==0)
//     bits [17:8]  : 10-bit `auto_skew_ticks` (`1..500` when unpegged & bit 9 == 0), OR 10-bit `0x0200 | auto_flip_ticks` (`1..500` when unpegged & bit 9 == 1), OR 10-bit signed `peg_offset_ticks` (`-500..+500` when pegged)
//     bit  18      : `oco_linked` (v2.7 Native OCO group linked by `client_tag` / bracket knock-out)
//     bit  19      : `ORDER_AUX_FLAG_GTS_EXPIRY` (when 1, bits [63:48] hold 16-bit `max_lifetime_wal_seqs`)
//     bits [23:20] : 4-bit `jit_elastic_mult` (v3.0/v3.9 Elastic JIT Liquidity multiplier `2..50`, `0` = `1x` default)
//     bits [63:24] : 40-bit `min_qty_lots` / `display_qty_lots` (24-bit bits [47:24] when `ORDER_AUX_FLAG_GTS_EXPIRY != 0`)
inline constexpr uint64_t ORDER_AUX_FLAG_REDUCE_ONLY          = (1ULL << 0U);
inline constexpr uint64_t ORDER_AUX_FLAG_MARKET               = (1ULL << 1U);
inline constexpr uint64_t ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT = (1ULL << 2U);
inline constexpr uint64_t ORDER_AUX_FLAG_POST_ONLY_SLIDE      = (1ULL << 3U);
inline constexpr uint64_t ORDER_AUX_FLAG_PRIMARY_PEG          = (1ULL << 4U);
inline constexpr uint64_t ORDER_AUX_FLAG_MIDPOINT_PEG         = (1ULL << 5U);
inline constexpr uint64_t ORDER_AUX_FLAG_MARK_PEG_COMBO       = (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG);
inline constexpr uint64_t ORDER_AUX_FLAG_MARGIN_SPOT          = (1ULL << 6U);
inline constexpr uint64_t ORDER_AUX_FLAG_ICEBERG              = (1ULL << 7U);
inline constexpr uint64_t ORDER_AUX_FLAG_TRAILING_PEG         = (ORDER_AUX_FLAG_MARK_PEG_COMBO | ORDER_AUX_FLAG_ICEBERG);
inline constexpr uint32_t ORDER_AUX_AUTO_SKEW_SHIFT           = 8U;
inline constexpr uint64_t ORDER_AUX_AUTO_SKEW_MASK            = 0x03FFULL;
inline constexpr uint64_t ORDER_AUX_AUTO_FLIP_BIT             = 0x0200ULL;
inline constexpr uint64_t ORDER_AUX_PEG_OFFSET_MASK           = 0x03FFULL;
inline constexpr uint64_t ORDER_AUX_FLAG_OCO_LINKED           = (1ULL << 18U);
inline constexpr uint64_t ORDER_AUX_FLAG_GTS_EXPIRY           = (1ULL << 19U);
inline constexpr uint32_t ORDER_AUX_JIT_MULT_SHIFT            = 20U;
inline constexpr uint64_t ORDER_AUX_JIT_MULT_MASK             = 0x0FULL; // v3.0/v3.9 4-bit Elastic JIT multiplier (0..1=1x; 2..10=2x..10x; 11..15={15x,20x,25x,35x,50x})
inline constexpr uint32_t ORDER_AUX_MIN_QTY_SHIFT             = 24U;
inline constexpr uint64_t ORDER_AUX_MIN_QTY_MASK              = 0xFF'FFFF'FFFFULL; // 40-bit min_qty_lots / display_qty_lots
inline constexpr uint64_t ORDER_AUX_MIN_QTY_GTS_MASK          = 0x00'00FF'FFFFULL; // 24-bit when GTS expiry is active
inline constexpr uint32_t ORDER_AUX_GTS_SHIFT                 = 48U;
inline constexpr uint64_t ORDER_AUX_GTS_MASK                  = 0xFFFFULL;

inline constexpr uint8_t pack_jit_elastic_mult_nibble(uint8_t jit_elastic_mult) noexcept {
    if (jit_elastic_mult <= 1U)  return 0U;
    if (jit_elastic_mult <= 10U) return jit_elastic_mult;
    if (jit_elastic_mult <= 17U) return 11U;
    if (jit_elastic_mult <= 22U) return 12U;
    if (jit_elastic_mult <= 30U) return 13U;
    if (jit_elastic_mult <= 42U) return 14U;
    return 15U;
}

inline constexpr uint8_t unpack_jit_elastic_mult_nibble(uint8_t raw) noexcept {
    switch (raw & 0x0FU) {
        case 0U:
        case 1U:  return 0U;
        case 11U: return 15U;
        case 12U: return 20U;
        case 13U: return 25U;
        case 14U: return 35U;
        case 15U: return 50U;
        default:  return static_cast<uint8_t>(raw & 0x0FU);
    }
}

inline constexpr uint64_t pack_order_aux1(
    bool     reduce_only,
    bool     is_market,
    bool     cancel_on_disconnect  = false,
    bool     post_only_slide       = false,
    uint64_t min_qty_lots          = 0ULL,
    bool     primary_peg           = false,
    bool     midpoint_peg          = false,
    bool     margin_spot           = false,
    uint64_t display_qty_lots      = 0ULL,
    bool     dark_midpoint         = false,
    int16_t  auto_skew_ticks       = 0,
    int16_t  peg_offset_ticks      = 0,
    bool     oco_linked            = false,
    uint16_t max_lifetime_wal_seqs = 0U,
    uint8_t  jit_elastic_mult      = 0U,
    bool     mark_peg              = false,
    int16_t  auto_flip_ticks       = 0,
    bool     trailing_peg          = false
) noexcept {
    const bool     eff_trailing = trailing_peg && !dark_midpoint;
    const bool     eff_primary  = primary_peg || ((mark_peg || eff_trailing) && !dark_midpoint);
    const bool     eff_midpoint = midpoint_peg || dark_midpoint || ((mark_peg || eff_trailing) && !dark_midpoint);
    const bool     use_iceberg  = (display_qty_lots > 0ULL) || dark_midpoint || eff_trailing;
    const uint64_t hi_qty       = (dark_midpoint || eff_trailing) ? 0ULL : (use_iceberg ? display_qty_lots : min_qty_lots);
    uint64_t       skew_or_peg  = 0ULL;
    if ((eff_primary || eff_midpoint) && !dark_midpoint) {
        const int16_t clamped_off = std::clamp<int16_t>(peg_offset_ticks, -500, 500);
        skew_or_peg = static_cast<uint64_t>(static_cast<uint16_t>(clamped_off)) & ORDER_AUX_PEG_OFFSET_MASK;
    } else if (auto_flip_ticks > 0) {
        skew_or_peg = ORDER_AUX_AUTO_FLIP_BIT |
                      (static_cast<uint64_t>(std::min<int16_t>(auto_flip_ticks, 500)) & 0x01FFULL);
    } else if (auto_skew_ticks > 0) {
        skew_or_peg = static_cast<uint64_t>(std::min<int16_t>(auto_skew_ticks, 500)) & 0x01FFULL;
    }
    const bool     has_gts        = (max_lifetime_wal_seqs > 0U);
    const uint64_t qty_mask       = has_gts ? ORDER_AUX_MIN_QTY_GTS_MASK : ORDER_AUX_MIN_QTY_MASK;
    const uint64_t clamped_hi_qty = (hi_qty > qty_mask) ? qty_mask : hi_qty;
    const uint64_t gts_bits     = has_gts
                                ? (ORDER_AUX_FLAG_GTS_EXPIRY |
                                   ((static_cast<uint64_t>(max_lifetime_wal_seqs) & ORDER_AUX_GTS_MASK) << ORDER_AUX_GTS_SHIFT))
                                : 0ULL;
    const uint64_t jit_bits     = (jit_elastic_mult > 1U)
                                ? ((static_cast<uint64_t>(pack_jit_elastic_mult_nibble(jit_elastic_mult)) & ORDER_AUX_JIT_MULT_MASK) << ORDER_AUX_JIT_MULT_SHIFT)
                                : 0ULL;
    return (reduce_only          ? ORDER_AUX_FLAG_REDUCE_ONLY          : 0ULL) |
           (is_market            ? ORDER_AUX_FLAG_MARKET               : 0ULL) |
           (cancel_on_disconnect ? ORDER_AUX_FLAG_CANCEL_ON_DISCONNECT : 0ULL) |
           (post_only_slide      ? ORDER_AUX_FLAG_POST_ONLY_SLIDE      : 0ULL) |
           (eff_primary          ? ORDER_AUX_FLAG_PRIMARY_PEG          : 0ULL) |
           (eff_midpoint         ? ORDER_AUX_FLAG_MIDPOINT_PEG         : 0ULL) |
           (margin_spot          ? ORDER_AUX_FLAG_MARGIN_SPOT          : 0ULL) |
           (use_iceberg          ? ORDER_AUX_FLAG_ICEBERG              : 0ULL) |
           (oco_linked           ? ORDER_AUX_FLAG_OCO_LINKED           : 0ULL) |
           (skew_or_peg << ORDER_AUX_AUTO_SKEW_SHIFT) |
           jit_bits |
           ((clamped_hi_qty & qty_mask) << ORDER_AUX_MIN_QTY_SHIFT) |
           gts_bits;
}

inline constexpr uint64_t unpack_order_min_qty_lots(uint64_t aux_param1) noexcept {
    if ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0ULL) {
        return 0ULL;
    }
    const uint64_t mask = ((aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0ULL)
                        ? ORDER_AUX_MIN_QTY_GTS_MASK
                        : ORDER_AUX_MIN_QTY_MASK;
    return (aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask;
}

inline constexpr uint64_t unpack_order_display_qty_lots(uint64_t aux_param1) noexcept {
    if ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) == 0ULL) {
        return 0ULL;
    }
    const uint64_t mask = ((aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0ULL)
                        ? ORDER_AUX_MIN_QTY_GTS_MASK
                        : ORDER_AUX_MIN_QTY_MASK;
    return (aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask;
}

inline constexpr bool unpack_order_dark_midpoint(uint64_t aux_param1) noexcept {
    const uint64_t mask = ((aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0ULL)
                        ? ORDER_AUX_MIN_QTY_GTS_MASK
                        : ORDER_AUX_MIN_QTY_MASK;
    return ((aux_param1 & ORDER_AUX_FLAG_MIDPOINT_PEG) != 0ULL) &&
           ((aux_param1 & ORDER_AUX_FLAG_PRIMARY_PEG) == 0ULL) &&
           ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0ULL) &&
           (((aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0ULL);
}

inline constexpr bool unpack_order_trailing_peg(uint64_t aux_param1, uint64_t client_tag = 0ULL) noexcept {
    (void)client_tag;
    const uint64_t mask = ((aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) != 0ULL)
                        ? ORDER_AUX_MIN_QTY_GTS_MASK
                        : ORDER_AUX_MIN_QTY_MASK;
    return ((aux_param1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO) &&
           ((aux_param1 & ORDER_AUX_FLAG_ICEBERG) != 0ULL) &&
           (((aux_param1 >> ORDER_AUX_MIN_QTY_SHIFT) & mask) == 0ULL);
}

inline constexpr bool unpack_order_mark_peg(uint64_t aux_param1) noexcept {
    return ((aux_param1 & ORDER_AUX_FLAG_MARK_PEG_COMBO) == ORDER_AUX_FLAG_MARK_PEG_COMBO) &&
           !unpack_order_trailing_peg(aux_param1) &&
           !unpack_order_dark_midpoint(aux_param1);
}

inline constexpr bool unpack_order_primary_peg(uint64_t aux_param1) noexcept {
    return ((aux_param1 & ORDER_AUX_FLAG_PRIMARY_PEG) != 0ULL) &&
           !unpack_order_mark_peg(aux_param1) &&
           !unpack_order_trailing_peg(aux_param1);
}

inline constexpr bool unpack_order_midpoint_peg(uint64_t aux_param1) noexcept {
    return ((aux_param1 & ORDER_AUX_FLAG_MIDPOINT_PEG) != 0ULL) &&
           !unpack_order_mark_peg(aux_param1) &&
           !unpack_order_trailing_peg(aux_param1) &&
           !unpack_order_dark_midpoint(aux_param1);
}

inline constexpr int16_t unpack_order_auto_skew_ticks(uint64_t aux_param1, uint64_t client_tag = 0ULL) noexcept {
    (void)client_tag;
    if ((aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) != 0ULL) {
        return 0;
    }
    const uint16_t raw = static_cast<uint16_t>((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK);
    if ((raw & ORDER_AUX_AUTO_FLIP_BIT) != 0U) {
        return 0;
    }
    return static_cast<int16_t>(std::min<uint16_t>(raw & 0x01FFU, 500U));
}

inline constexpr int16_t unpack_order_auto_flip_ticks(uint64_t aux_param1, uint64_t client_tag = 0ULL) noexcept {
    (void)client_tag;
    if ((aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) != 0ULL) {
        return 0;
    }
    const uint16_t raw = static_cast<uint16_t>((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_AUTO_SKEW_MASK);
    if ((raw & ORDER_AUX_AUTO_FLIP_BIT) == 0U) {
        return 0;
    }
    return static_cast<int16_t>(std::min<uint16_t>(raw & 0x01FFU, 500U));
}

inline constexpr int16_t unpack_order_peg_offset_ticks(uint64_t aux_param1, uint64_t client_tag = 0ULL) noexcept {
    (void)client_tag;
    if ((aux_param1 & (ORDER_AUX_FLAG_PRIMARY_PEG | ORDER_AUX_FLAG_MIDPOINT_PEG)) == 0ULL ||
        unpack_order_dark_midpoint(aux_param1)) {
        return 0;
    }
    const uint16_t raw10 = static_cast<uint16_t>((aux_param1 >> ORDER_AUX_AUTO_SKEW_SHIFT) & ORDER_AUX_PEG_OFFSET_MASK);
    const int16_t  s10   = ((raw10 & 0x0200U) != 0U)
                         ? static_cast<int16_t>(raw10 | 0xFC00U)
                         : static_cast<int16_t>(raw10);
    return std::clamp<int16_t>(s10, -500, 500);
}

inline constexpr bool unpack_order_oco_linked(uint64_t aux_param1, uint64_t client_tag = 0ULL) noexcept {
    (void)client_tag;
    return (aux_param1 & ORDER_AUX_FLAG_OCO_LINKED) != 0ULL;
}

inline constexpr uint16_t unpack_order_max_lifetime_wal_seqs(uint64_t aux_param1) noexcept {
    if ((aux_param1 & ORDER_AUX_FLAG_GTS_EXPIRY) == 0ULL) {
        return 0U;
    }
    return static_cast<uint16_t>((aux_param1 >> ORDER_AUX_GTS_SHIFT) & ORDER_AUX_GTS_MASK);
}

inline constexpr uint8_t unpack_order_jit_elastic_mult(uint64_t aux_param1) noexcept {
    const uint8_t raw = static_cast<uint8_t>((aux_param1 >> ORDER_AUX_JIT_MULT_SHIFT) & ORDER_AUX_JIT_MULT_MASK);
    return unpack_jit_elastic_mult_nibble(raw);
}

inline constexpr uint64_t QUOTE_AUX_QTY_MASK                  = 0x07'FFFF'FFFFULL; // 35-bit low ask_qty_lots in aux_param1 (extended to 50-bit via frame.bytes[41..42])
inline constexpr uint32_t QUOTE_AUX_HI16_SHIFT                = 35U;               // bits [49:35] (15 high bits) carried in ArenaWireFrame::bytes[41..42]
inline constexpr uint64_t QUOTE_AUX_QTY_50_MASK               = 0x0003'FFFF'FFFF'FFFFULL; // 50-bit extended ask_qty_lots / leg2_qty_lots
inline constexpr uint64_t QUOTE_EXT_QTY_MAX                   = 0x0003'FFFF'FFFF'FFFFULL; // 50-bit ask_qty_lots / leg2_qty_lots (> 10^15 MAX_VALID_ORDER_LOTS)
inline constexpr uint64_t QUOTE_AUX_FLAG_PEG_ACTIVE           = (1ULL << 35U);     // bit 35: quote_peg_mode active (1..4)
inline constexpr uint32_t QUOTE_AUX_PEG_MODE_SHIFT            = 62U;               // bits [63:62]: 2-bit (quote_peg_mode - 1) when PEG_ACTIVE is set
inline constexpr uint64_t QUOTE_AUX_PEG_MODE_MASK             = 0x03ULL;
inline constexpr uint32_t QUOTE_AUX_JIT_MULT_SHIFT            = 36U;               // bits [39:36] 4-bit jit_elastic_mult (2..50)
inline constexpr uint64_t QUOTE_AUX_JIT_MULT_MASK             = 0x0FULL;
inline constexpr uint64_t QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT = (1ULL << 40U);
inline constexpr uint64_t QUOTE_AUX_FLAG_POST_ONLY_SLIDE      = (1ULL << 41U);
inline constexpr uint64_t QUOTE_AUX_FLAG_MARGIN_SPOT          = (1ULL << 42U);
inline constexpr uint64_t QUOTE_AUX_FLAG_OCO_LINKED           = (1ULL << 43U);
inline constexpr uint32_t QUOTE_AUX_GTS_LO_SHIFT              = 44U;
inline constexpr uint32_t QUOTE_AUX_AUTO_SKEW_SHIFT           = 48U;
inline constexpr uint64_t QUOTE_AUX_AUTO_SKEW_MASK            = 0x03FFULL;
inline constexpr uint32_t QUOTE_AUX_GTS_HI_SHIFT              = 58U;

inline constexpr bool is_canonical_ext_qty_hi16(uint16_t ask_qty_hi16) noexcept {
    return ask_qty_hi16 <= 0x7FFFU;
}

inline constexpr uint16_t pack_quote_ask_qty_hi16(uint64_t ask_qty_lots) noexcept {
    return static_cast<uint16_t>((ask_qty_lots >> QUOTE_AUX_HI16_SHIFT) & 0x7FFFULL);
}

inline constexpr uint64_t unpack_quote_ask_qty(uint64_t aux_param1, uint16_t ask_qty_hi16 = 0U) noexcept {
    return ((aux_param1 & QUOTE_AUX_QTY_MASK) |
            ((static_cast<uint64_t>(ask_qty_hi16) & 0x7FFFULL) << QUOTE_AUX_HI16_SHIFT)) &
           QUOTE_AUX_QTY_50_MASK;
}

inline constexpr uint64_t pack_quote_aux1(
    uint64_t ask_qty_lots,
    bool     cancel_on_disconnect  = false,
    bool     post_only_slide       = false,
    bool     margin_spot           = false,
    int16_t  auto_skew_ticks       = 0,
    bool     oco_linked            = false,
    uint16_t max_lifetime_wal_seqs = 0U,
    uint8_t  jit_elastic_mult      = 0U,
    int16_t  auto_flip_ticks       = 0,
    uint8_t  quote_peg_mode        = 0U,
    int16_t  peg_offset_ticks      = 0,
    uint16_t* ask_qty_hi16_out     = nullptr
) noexcept {
    if (ask_qty_hi16_out != nullptr) {
        *ask_qty_hi16_out = pack_quote_ask_qty_hi16(ask_qty_lots);
    }
    const uint8_t eff_peg = (quote_peg_mode <= 4U) ? quote_peg_mode : 0U;
    uint64_t skew10 = 0ULL;
    if (eff_peg != 0U) {
        const int16_t clamped_off = std::clamp<int16_t>(peg_offset_ticks, -500, 500);
        skew10 = static_cast<uint64_t>(static_cast<uint16_t>(clamped_off)) & QUOTE_AUX_AUTO_SKEW_MASK;
    } else if (auto_flip_ticks > 0) {
        skew10 = ORDER_AUX_AUTO_FLIP_BIT |
                 (static_cast<uint64_t>(std::min<int16_t>(auto_flip_ticks, 500)) & 0x01FFULL);
    } else if (auto_skew_ticks > 0) {
        skew10 = static_cast<uint64_t>(std::min<int16_t>(auto_skew_ticks, 500)) & 0x01FFULL;
    }
    const uint16_t gts_cap = (eff_peg != 0U) ? 255U : 1023U;
    const uint64_t gts_val = static_cast<uint64_t>(std::min<uint16_t>(max_lifetime_wal_seqs, gts_cap));
    const uint64_t gts_lo  = (gts_val & 0x0FULL) << QUOTE_AUX_GTS_LO_SHIFT;
    const uint64_t gts_hi_mask = (eff_peg != 0U) ? 0x0FULL : 0x3FULL;
    const uint64_t gts_hi  = ((gts_val >> 4U) & gts_hi_mask) << QUOTE_AUX_GTS_HI_SHIFT;
    const uint64_t jit4    = (jit_elastic_mult > 1U)
                           ? ((static_cast<uint64_t>(pack_jit_elastic_mult_nibble(jit_elastic_mult)) & QUOTE_AUX_JIT_MULT_MASK) << QUOTE_AUX_JIT_MULT_SHIFT)
                           : 0ULL;
    const uint64_t peg_bits = (eff_peg != 0U)
                            ? (QUOTE_AUX_FLAG_PEG_ACTIVE |
                               ((static_cast<uint64_t>(eff_peg - 1U) & QUOTE_AUX_PEG_MODE_MASK) << QUOTE_AUX_PEG_MODE_SHIFT))
                            : 0ULL;
    return (ask_qty_lots & QUOTE_AUX_QTY_MASK) |
           peg_bits |
           jit4 |
           (cancel_on_disconnect ? QUOTE_AUX_FLAG_CANCEL_ON_DISCONNECT : 0ULL) |
           (post_only_slide      ? QUOTE_AUX_FLAG_POST_ONLY_SLIDE      : 0ULL) |
           (margin_spot          ? QUOTE_AUX_FLAG_MARGIN_SPOT          : 0ULL) |
           (oco_linked           ? QUOTE_AUX_FLAG_OCO_LINKED           : 0ULL) |
           gts_lo |
           ((skew10 & QUOTE_AUX_AUTO_SKEW_MASK) << QUOTE_AUX_AUTO_SKEW_SHIFT) |
           gts_hi;
}

inline constexpr uint8_t unpack_quote_peg_mode(uint64_t aux_param1) noexcept {
    if ((aux_param1 & QUOTE_AUX_FLAG_PEG_ACTIVE) == 0ULL) {
        return 0U;
    }
    const uint8_t raw2 = static_cast<uint8_t>((aux_param1 >> QUOTE_AUX_PEG_MODE_SHIFT) & QUOTE_AUX_PEG_MODE_MASK);
    return static_cast<uint8_t>(raw2 + 1U);
}

inline constexpr int16_t unpack_quote_peg_offset_ticks(uint64_t aux_param1) noexcept {
    if (unpack_quote_peg_mode(aux_param1) == 0U) {
        return 0;
    }
    const uint16_t raw10 = static_cast<uint16_t>((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK);
    const int16_t  s10   = ((raw10 & 0x0200U) != 0U)
                         ? static_cast<int16_t>(raw10 | 0xFC00U)
                         : static_cast<int16_t>(raw10);
    return std::clamp<int16_t>(s10, -500, 500);
}

inline constexpr int16_t unpack_quote_auto_skew_ticks(uint64_t aux_param1) noexcept {
    if (unpack_quote_peg_mode(aux_param1) != 0U) {
        return 0;
    }
    const uint16_t raw = static_cast<uint16_t>((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK);
    if ((raw & ORDER_AUX_AUTO_FLIP_BIT) != 0U) {
        return 0;
    }
    return static_cast<int16_t>(std::min<uint16_t>(raw & 0x01FFU, 500U));
}

inline constexpr int16_t unpack_quote_auto_flip_ticks(uint64_t aux_param1) noexcept {
    if (unpack_quote_peg_mode(aux_param1) != 0U) {
        return 0;
    }
    const uint16_t raw = static_cast<uint16_t>((aux_param1 >> QUOTE_AUX_AUTO_SKEW_SHIFT) & QUOTE_AUX_AUTO_SKEW_MASK);
    if ((raw & ORDER_AUX_AUTO_FLIP_BIT) == 0U) {
        return 0;
    }
    return static_cast<int16_t>(std::min<uint16_t>(raw & 0x01FFU, 500U));
}

inline constexpr bool unpack_quote_oco_linked(uint64_t aux_param1) noexcept {
    return (aux_param1 & QUOTE_AUX_FLAG_OCO_LINKED) != 0ULL;
}

inline constexpr uint16_t unpack_quote_max_lifetime_wal_seqs(uint64_t aux_param1) noexcept {
    const uint16_t lo4 = static_cast<uint16_t>((aux_param1 >> QUOTE_AUX_GTS_LO_SHIFT) & 0x0FULL);
    const uint64_t hi_mask = ((aux_param1 & QUOTE_AUX_FLAG_PEG_ACTIVE) != 0ULL) ? 0x0FULL : 0x3FULL;
    const uint16_t hi  = static_cast<uint16_t>((aux_param1 >> QUOTE_AUX_GTS_HI_SHIFT) & hi_mask);
    return static_cast<uint16_t>((hi << 4U) | lo4);
}

inline constexpr uint8_t unpack_quote_jit_elastic_mult(uint64_t aux_param1) noexcept {
    const uint8_t raw = static_cast<uint8_t>((aux_param1 >> QUOTE_AUX_JIT_MULT_SHIFT) & QUOTE_AUX_JIT_MULT_MASK);
    return unpack_jit_elastic_mult_nibble(raw);
}

inline constexpr uint16_t pack_ext_qty_hi15(uint64_t qty_lots) noexcept {
    return pack_quote_ask_qty_hi16(qty_lots);
}

// Aux flag in `aux_param1` for `BaseOp::ModifyInPlace = 0x2` to preserve FIFO queue priority on size-up
inline constexpr uint64_t MODIFY_AUX_FLAG_KEEP_PRIORITY       = (1ULL << 0U);

// Aux flags in `aux_param0` (`client_tag_filter`) for `BaseOp::CancelAllAccount = 0x3` to cancel only Bids or only Asks
inline constexpr uint64_t CANCEL_ALL_FLAG_BID_ONLY            = (1ULL << 62U);
inline constexpr uint64_t CANCEL_ALL_FLAG_ASK_ONLY            = (1ULL << 63U);
inline constexpr uint64_t CANCEL_ALL_TAG_MASK                 = 0x3FFF'FFFF'FFFF'FFFFULL;

// Extended byte[51] flags in `ArenaWireFrame::bytes[51]` (authenticated by `TailSipHash48`):
//   bit 0 (`0x01`): `ladder_by_tag` on `BaseOp::TwoSidedQuoteReplace = 0xC` (`bytes[43..50]` = 64-bit `client_tag`)
//   bit 1 (`0x02`): `stp_decrement_and_cancel` (`DC`) on `BaseOp::NewOrder = 0x0`
//   bit 2 (`0x04`): SipHash-2-4 stream-encrypted `(new_key_lo64, new_key_hi64)` key wrap on `BaseOp::RegisterSessionKey = 0xB`
inline constexpr uint8_t  WIRE_EXT51_FLAG_LADDER_BY_TAG       = 0x01U;
inline constexpr uint8_t  WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL = 0x02U;
inline constexpr uint8_t  WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP   = 0x04U;

// `aux_param0` magic value on `BaseOp::Heartbeat = 0xF` to resynchronize the server's 14-bit `seq_lo` sliding window after a client reconnect
inline constexpr uint64_t HEARTBEAT_AUX0_SYNC_SEQ             = 0x5359'4E43'5F53'4551ULL; // "SYNC_SEQ"

// Aux flags in `aux_param1` for `BaseOp::UpdateMarkFunding = 0x8` to trigger Margin & BBO Maker Yield Drip,
// configure the v2.8 Protocol Treasury Account (`MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT`),
// execute v3.2 Prime-Brokerage Sub-Account Link (`MARK_AUX1_FLAG_LINK_SUB_ACCOUNT`) / 0-bps Internal Transfer (`MARK_AUX1_FLAG_SUB_TRANSFER`),
// trigger a v3.3 Deterministic Keccak-256 Binary State Snapshot (`MARK_AUX1_FLAG_SAVE_SNAPSHOT`),
// execute a v3.4 Risk-Calibrated Surplus Insurance Fund Sweep (`MARK_AUX1_FLAG_SWEEP_INSURANCE`),
// or bind a v4.4 Native Builder / Order-Flow Router (`MARK_AUX1_FLAG_BIND_BUILDER`)
inline constexpr uint64_t MARK_AUX1_FLAG_DISTRIBUTE_YIELD     = (1ULL << 0U);
inline constexpr uint64_t MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT = (1ULL << 1U);
inline constexpr uint64_t MARK_AUX1_FLAG_LINK_SUB_ACCOUNT     = (1ULL << 2U);
inline constexpr uint64_t MARK_AUX1_FLAG_SUB_TRANSFER         = (1ULL << 3U);
inline constexpr uint64_t MARK_AUX1_FLAG_SAVE_SNAPSHOT        = (1ULL << 4U);
inline constexpr uint64_t MARK_AUX1_FLAG_SWEEP_INSURANCE      = (1ULL << 5U);
inline constexpr uint64_t MARK_AUX1_FLAG_HARVEST_FLOAT_YIELD  = (1ULL << 6U);
inline constexpr uint64_t MARK_AUX1_FLAG_HARVEST_SPOT_REPO    = (1ULL << 7U);
inline constexpr uint64_t MARK_AUX1_FLAG_HARVEST_USD_REPO     = (1ULL << 8U);
inline constexpr uint64_t MARK_AUX1_FLAG_BIND_BUILDER         = (1ULL << 9U);
inline constexpr uint64_t MARK_AUX1_FLAG_CONFIG_MMP           = (1ULL << 10U);
inline constexpr uint64_t MARK_AUX1_FLAG_CONFIG_PAYOUT        = (1ULL << 11U);
inline constexpr uint64_t MARK_AUX1_FLAG_BASE_YIELD           = (1ULL << 12U);
inline constexpr uint64_t MARK_AUX1_FLAG_CONFIG_AUTO_REPO     = (1ULL << 13U);
inline constexpr uint64_t MARK_AUX1_FLAG_FUND_MARKET_VAULT    = (1ULL << 14U);
inline constexpr uint64_t MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES     = (1ULL << 15U);
inline constexpr uint64_t MARK_AUX1_FLAG_DEFAULT_INCENTIVES      = (1ULL << 16U);
inline constexpr uint64_t MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT  = (1ULL << 17U);

// v4.8 Default-On Trader Incentive Pillar Bitmask (`INCENTIVE_PILLAR_*`):
inline constexpr uint8_t INCENTIVE_PILLAR_SUPERCHARGE      = 0x01U;
inline constexpr uint8_t INCENTIVE_PILLAR_AUTO_YIELD_DRIP  = 0x02U;
inline constexpr uint8_t INCENTIVE_PILLAR_AUTO_REPO        = 0x04U;
inline constexpr uint8_t INCENTIVE_PILLAR_NOTIONAL_BBO     = 0x08U;
inline constexpr uint8_t INCENTIVE_PILLAR_TWO_SIDED_BONUS  = 0x10U;
inline constexpr uint8_t INCENTIVE_PILLAR_CLAIM_COLLATERAL = 0x20U;
inline constexpr uint8_t INCENTIVE_PILLAR_ITCH_PRIVACY     = 0x40U;
inline constexpr uint8_t INCENTIVE_PILLAR_MACRO_AND_BASIS  = 0x80U;
inline constexpr uint8_t INCENTIVE_PILLARS_ALL_ON          = 0xFFU;

// v4.6/v4.7 Yield & Rebate Payout Mode Bitmask (`PAYOUT_FLAG_*`):
inline constexpr uint8_t PAYOUT_FLAG_AUTO_REPAY_BORROW      = 0x01U;
inline constexpr uint8_t PAYOUT_FLAG_COMPOUND_BONDING_CURVE = 0x02U;
inline constexpr uint8_t PAYOUT_FLAG_AUTO_COMPOUND_QUOTES   = 0x04U;

// Aux flags in `aux_param1` for `BaseOp::LiquidateAccount = 0x9`:
//   - `LIQ_AUX1_FLAG_SET_KNOCKOUT` (`bit 0`): arm/disarm Exact-Tick Knock-Out Barrier (`price_ticks`) or Drawdown Stop (`market_id=0`)
//   - `LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE` (`bit 1`): v3.0 1-Frame Portfolio Delta-Neutralizer (`aux0=base_asset_id`, `market_id=preferred_hedge_market_id`, `price_ticks=max_slippage_bps`)
//   - `LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT` (`bit 2`): allow `margin_spot` shorting when `LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE` routes to a Spot market
//   - `LIQ_AUX1_FLAG_AUTO_CROSS_ARB` (`bit 3`): v3.2 Autonomous Cross-Market Basis & Triangular Auto-Arb Sweeper (`market_id=primary_market_id`, `qty_lots=max_lots`, `price_ticks=min_profit_micro`)
//   - `LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP` (`bit 4`): v3.3 Autonomous Zero-Capital Liquidation & Backstop Sweeper (`market_id=target_market_id` or `0` for all perps, `aux0=target_account_id`, `qty_lots=max_lots`, `price_ticks=min_bounty_micro`)
inline constexpr uint64_t LIQ_AUX1_FLAG_SET_KNOCKOUT          = (1ULL << 0U);
inline constexpr uint64_t LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE      = (1ULL << 1U);
inline constexpr uint64_t LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT     = (1ULL << 2U);
inline constexpr uint64_t LIQ_AUX1_FLAG_AUTO_CROSS_ARB        = (1ULL << 3U);
inline constexpr uint64_t LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP        = (1ULL << 4U);
inline constexpr uint64_t LIQ_AUX1_FLAG_NO_OFFLOAD            = (1ULL << 62U);

// Aux flags in `aux_param1` for `BaseOp::MintRedeemSet = 0xE` to execute Intra-Tick Atomic Flash Arbitrage
inline constexpr uint64_t MINT_AUX1_FLAG_FLASH_ARB            = (1ULL << 0U);
inline constexpr uint64_t MINT_AUX1_FLAG_FLASH_MARKET         = (1ULL << 1U);

// Aux packing for `BaseOp::AtomicSpread = 0xD`:
//   `aux_param0`: `(uint64_t(leg2_market_id) << 48) | (uint64_t(leg2_price_ticks) & 0xFFFF'FFFF'FFFFULL)`
//   `aux_param1`: `(leg2_qty_lots & 0xFF'FFFF'FFFFULL)` (extended to 50-bit via `bytes[41..42]`) | flags in bits [63:40]
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG2_ASK         = (1ULL << 40U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG1_MARKET      = (1ULL << 41U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY = (1ULL << 42U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG2_MARKET      = (1ULL << 43U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY = (1ULL << 44U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_MARGIN_SPOT      = (1ULL << 45U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_MULTI_LEG_BASKET = (1ULL << 46U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_BASKET_4_LEGS    = (1ULL << 47U);
inline constexpr uint32_t SPREAD_AUX1_LEG4_MKT_SHIFT        = 48U;
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG3_ASK         = (1ULL << 56U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG3_MARKET      = (1ULL << 57U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY = (1ULL << 58U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG4_ASK           = (1ULL << 59U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG4_MARKET        = (1ULL << 60U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY   = (1ULL << 61U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_BASKET_2_LEGS      = (1ULL << 62U);
inline constexpr uint64_t SPREAD_AUX1_FLAG_BASKET_EXT_MKT16   = (1ULL << 63U);
inline constexpr uint32_t SPREAD_AUX1_LEG3_MKT_HI8_SHIFT      = 24U;
inline constexpr uint32_t SPREAD_AUX1_LEG4_MKT_HI8_SHIFT      = 32U;

struct WireBasketLeg {
    uint16_t  market_id   = 0;
    OrderSide side        = OrderSide::Bid;
    int64_t   price_ticks = 0;
    uint64_t  qty_lots    = 0;
    bool      is_market   = false;
    bool      reduce_only = false;
    bool      margin_spot = false;
};

inline constexpr void pack_atomic_spread_aux(
    uint16_t  leg2_market_id,
    OrderSide leg2_side,
    int64_t   leg2_price_ticks,
    uint64_t  leg2_qty_lots,
    bool      leg1_is_market,
    bool      leg1_reduce_only,
    bool      leg2_is_market,
    bool      leg2_reduce_only,
    uint64_t& aux_param0_out,
    uint64_t& aux_param1_out,
    bool      margin_spot       = false,
    uint16_t* leg2_qty_hi16_out = nullptr
) noexcept {
    if (leg2_qty_hi16_out != nullptr) {
        *leg2_qty_hi16_out = pack_quote_ask_qty_hi16(leg2_qty_lots);
    }
    const uint64_t p48 = static_cast<uint64_t>(leg2_price_ticks) & 0xFFFF'FFFF'FFFFULL;
    aux_param0_out = (static_cast<uint64_t>(leg2_market_id) << 48U) | p48;
    aux_param1_out = (leg2_qty_lots & QUOTE_AUX_QTY_MASK) |
                     ((leg2_side == OrderSide::Ask) ? SPREAD_AUX1_FLAG_LEG2_ASK : 0ULL) |
                     (leg1_is_market   ? SPREAD_AUX1_FLAG_LEG1_MARKET      : 0ULL) |
                     (leg1_reduce_only ? SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY : 0ULL) |
                     (leg2_is_market   ? SPREAD_AUX1_FLAG_LEG2_MARKET      : 0ULL) |
                     (leg2_reduce_only ? SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY : 0ULL) |
                     (margin_spot      ? SPREAD_AUX1_FLAG_MARGIN_SPOT      : 0ULL);
}

inline constexpr void unpack_atomic_spread_aux(
    uint64_t   aux_param0,
    uint64_t   aux_param1,
    uint16_t&  leg2_market_id_out,
    OrderSide& leg2_side_out,
    int64_t&   leg2_price_ticks_out,
    uint64_t&  leg2_qty_lots_out,
    bool&      leg1_is_market_out,
    bool&      leg1_reduce_only_out,
    bool&      leg2_is_market_out,
    bool&      leg2_reduce_only_out,
    uint16_t   leg2_qty_hi16 = 0U
) noexcept {
    leg2_market_id_out = static_cast<uint16_t>((aux_param0 >> 48U) & 0xFFFFULL);
    const uint64_t p48 = aux_param0 & 0xFFFF'FFFF'FFFFULL;
    if ((p48 & (1ULL << 47U)) != 0ULL) {
        leg2_price_ticks_out = static_cast<int64_t>(p48 | 0xFFFF'0000'0000'0000ULL);
    } else {
        leg2_price_ticks_out = static_cast<int64_t>(p48);
    }
    const bool is_3or4_leg_basket =
        ((aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0ULL) &&
        ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) == 0ULL);
    leg2_qty_lots_out = (is_3or4_leg_basket && ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16) != 0ULL))
        ? (aux_param1 & 0xFFFFFFULL)
        : (is_3or4_leg_basket
            ? unpack_quote_ask_qty(aux_param1, 0U)
            : unpack_quote_ask_qty(aux_param1, leg2_qty_hi16));
    leg2_side_out        = ((aux_param1 & SPREAD_AUX1_FLAG_LEG2_ASK) != 0ULL) ? OrderSide::Ask : OrderSide::Bid;
    leg1_is_market_out   = ((aux_param1 & SPREAD_AUX1_FLAG_LEG1_MARKET) != 0ULL);
    leg1_reduce_only_out = ((aux_param1 & SPREAD_AUX1_FLAG_LEG1_REDUCE_ONLY) != 0ULL);
    leg2_is_market_out   = ((aux_param1 & SPREAD_AUX1_FLAG_LEG2_MARKET) != 0ULL);
    leg2_reduce_only_out = ((aux_param1 & SPREAD_AUX1_FLAG_LEG2_REDUCE_ONLY) != 0ULL);
}

struct ArenaHeader {
    BaseOp     op          = BaseOp::NewOrder; // 4 bits
    ArenaFlags flags       = {};               // 4 bits
    uint16_t   market_id   = 0;                // 16 bits
    uint32_t   account_id  = 0;                // 24 bits (0 .. 16,777,215)
    OrderSide  side        = OrderSide::Bid;   // 2 bits
    uint16_t   seq_lo      = 0;                // 14 bits (RFC-1982 modular anti-replay)
    int64_t    price_ticks = 0;                // 48 bits signed
    uint64_t   qty_lots    = 0;                // 40 bits unsigned

    // Pack into 152 bits = m0 [151:88], m1 [87:24], hi24 [23:0]
    constexpr void pack_words(uint64_t& m0, uint64_t& m1, uint32_t& hi24) const noexcept {
        const uint64_t op_fl  = (static_cast<uint64_t>(static_cast<uint8_t>(op) & 0xFU) << 4U) |
                                static_cast<uint64_t>(flags.pack4() & 0xFU);
        const uint64_t mkt    = static_cast<uint64_t>(market_id);
        const uint64_t acct   = static_cast<uint64_t>(account_id & 0xFFFFFFU);
        const uint64_t sd_seq = (static_cast<uint64_t>(static_cast<uint8_t>(side) & 0x3U) << 14U) |
                                static_cast<uint64_t>(seq_lo & 0x3FFFU);
        m0 = (op_fl << 56U) | (mkt << 40U) | (acct << 16U) | sd_seq;

        const uint64_t p48 = static_cast<uint64_t>(price_ticks) & 0xFFFF'FFFF'FFFFULL;
        const uint64_t q40 = qty_lots & 0xFF'FFFF'FFFFULL;
        m1   = (p48 << 16U) | (q40 >> 24U);
        hi24 = static_cast<uint32_t>(q40 & 0xFFFFFFULL);
    }
};

// -----------------------------------------------------------------------------
// Big-Endian Helpers & SipHash MACs (`PreSipHash40` + `TailSipHash48`)
// -----------------------------------------------------------------------------
inline constexpr void write_be16_wire(uint8_t* dst, uint16_t val) noexcept {
    dst[0] = static_cast<uint8_t>((val >> 8U) & 0xFFU);
    dst[1] = static_cast<uint8_t>(val & 0xFFU);
}

inline constexpr uint16_t read_be16_wire(const uint8_t* src) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(src[0]) << 8U) | src[1]);
}

inline constexpr void write_be32_wire(uint8_t* dst, uint32_t val) noexcept {
    dst[0] = static_cast<uint8_t>((val >> 24U) & 0xFFU);
    dst[1] = static_cast<uint8_t>((val >> 16U) & 0xFFU);
    dst[2] = static_cast<uint8_t>((val >> 8U) & 0xFFU);
    dst[3] = static_cast<uint8_t>(val & 0xFFU);
}

inline constexpr uint32_t read_be32_wire(const uint8_t* src) noexcept {
    return (static_cast<uint32_t>(src[0]) << 24U) |
           (static_cast<uint32_t>(src[1]) << 16U) |
           (static_cast<uint32_t>(src[2]) << 8U)  |
           static_cast<uint32_t>(src[3]);
}

inline constexpr void write_be64(uint8_t* dst, uint64_t val) noexcept {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<uint8_t>((val >> (56 - 8 * i)) & 0xFFULL);
    }
}

inline constexpr uint64_t read_be64(const uint8_t* src) noexcept {
    uint64_t val = 0ULL;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8U) | static_cast<uint64_t>(src[i]);
    }
    return val;
}

inline constexpr uint64_t rotl64(uint64_t x, unsigned int b) noexcept {
    return (x << b) | (x >> (64U - b));
}

inline constexpr void sip_round(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3) noexcept {
    v0 = v0 + v1; v1 = rotl64(v1, 13) ^ v0; v0 = rotl64(v0, 32);
    v2 = v2 + v3; v3 = rotl64(v3, 16) ^ v2;
    v0 = v0 + v3; v3 = rotl64(v3, 21) ^ v0;
    v2 = v2 + v1; v1 = rotl64(v1, 17) ^ v2; v2 = rotl64(v2, 32);
}

inline constexpr uint64_t calc_pre_siphash40(
    const ArenaHeader& hdr,
    uint64_t           seq_hi50,
    uint64_t           key_lo64,
    uint64_t           key_hi64
) noexcept {
    uint64_t m0 = 0ULL;
    uint64_t m1 = 0ULL;
    uint32_t hi24 = 0U;
    hdr.pack_words(m0, m1, hi24);

    const uint64_t m2       = (static_cast<uint64_t>(hi24) << 40U) | (seq_hi50 & 0xFF'FFFF'FFFFULL);
    const uint64_t seq_top10 = (seq_hi50 >> 40U) & 0x3FFULL;

    uint64_t v0 = key_lo64 ^ 0x736f6d6570736575ULL ^ seq_top10;
    uint64_t v1 = key_hi64 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key_lo64 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key_hi64 ^ 0x7465646279746573ULL ^ m0;

    // SipHash-2-4 across (m0, m1, m2) with 4 finalization rounds (`calc_pre_siphash40`)
    // Word m0 (already XORed into v3)
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= m0;

    // Word m1
    v3 ^= m1;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= m1;

    // Word m2 (absorb m2 = (hi24 << 40) | seq_hi50_lo40)
    v3 ^= m2;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= m2;

    // Finalization (4 rounds)
    v2 ^= 0xFFULL;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    const uint64_t digest = v0 ^ v1 ^ v2 ^ v3;
    return (digest ^ (digest >> 24U)) & 0xFF'FFFF'FFFFULL;
}

inline constexpr bool is_valid_wire_price_ticks_48_val(int64_t px) noexcept {
    constexpr int64_t kMinPx48 = -(1LL << 47U);
    constexpr int64_t kMaxPx48 = (1LL << 47U) - 1LL;
    return px >= kMinPx48 && px <= kMaxPx48;
}

inline constexpr bool is_valid_wire_fields(
    const ArenaHeader& hdr,
    uint16_t           ext_qty_hi16 = 0U
) noexcept {
    return hdr.account_id <= 0xFF'FFFFU &&
           static_cast<uint8_t>(hdr.side) <= 1U &&
           is_valid_wire_price_ticks_48_val(hdr.price_ticks) &&
           hdr.qty_lots <= 0xFF'FFFF'FFFFULL &&
           is_canonical_ext_qty_hi16(ext_qty_hi16);
}

inline constexpr uint64_t calc_tail_siphash48(
    const std::array<uint8_t, ARENA_WIRE_BYTES>& frame_bytes,
    uint64_t                                     seq_hi50,
    uint64_t                                     key_lo64,
    uint64_t                                     key_hi64
) noexcept {
    const uint64_t eff_hi50 = seq_hi50 & 0x0003'FFFF'FFFF'FFFFULL;
    const uint64_t w0 = read_be64(&frame_bytes[0]);
    const uint64_t w1 = read_be64(&frame_bytes[8]);
    const uint64_t w2 = read_be64(&frame_bytes[16]);
    const uint64_t w3 = read_be64(&frame_bytes[24]);
    const uint64_t w4 = read_be64(&frame_bytes[32]);
    const uint64_t w5 = read_be64(&frame_bytes[40]);
    const uint64_t w6 = read_be64(&frame_bytes[48]);
    const uint64_t w7 = eff_hi50 | (0x2A54ULL << 50U);
    const uint64_t w8 = (64ULL << 56U) | 0x4152454E4154ULL;

    uint64_t v0 = key_lo64 ^ 0x736f6d6570736575ULL ^ 0x5441494C5F563231ULL;
    uint64_t v1 = key_hi64 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key_lo64 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key_hi64 ^ 0x7465646279746573ULL;

    const std::array<uint64_t, 9> words{{w0, w1, w2, w3, w4, w5, w6, w7, w8}};
    for (const uint64_t m : words) {
        v3 ^= m;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }

    v2 ^= 0xFFULL;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);

    const uint64_t h = v0 ^ v1 ^ v2 ^ v3;
    return (h ^ (h >> 16U)) & 0xFFFF'FFFF'FFFFULL;
}

// -----------------------------------------------------------------------------
// 64-Byte Cacheline-Aligned Ingress Frame (`ArenaWireFrame`)
// Layout:
//   [0..7]   : Header `m0` (big-endian 64-bit)
//   [8..15]  : Header `m1` (big-endian 64-bit)
//   [16..18] : Header `hi24` (`qty_lots[23:0]`, big-endian 24-bit)
//   [19..23] : `PreSipHash40` header MAC (big-endian 40-bit)
//   [24]     : Protocol version byte (`0x01`)
//   [25..32] : `aux_param0` (big-endian 64-bit: `order_id`, `asset_id`, `ask_px`, `cod_enable`)
//   [33..40] : `aux_param1` (big-endian 64-bit: `order_flags`, `ask_qty_and_flags`, `cod_timeout_ms`)
//   [41..55] : Extended op payload / flags (`bytes[41..42]` hi16 qty, `bytes[43..50]` tag/rules, `bytes[51]` ext flags; authenticated by `TailSipHash48`)
//   [56..61] : `TailSipHash48` payload MAC (big-endian 48-bit)
//   [62..63] : Frame trailer magic (`0xA1`, `0xE0`)
// -----------------------------------------------------------------------------
struct alignas(64) ArenaWireFrame {
    std::array<uint8_t, ARENA_WIRE_BYTES> bytes{};

    constexpr uint64_t get_tail_siphash48() const noexcept {
        return (static_cast<uint64_t>(bytes[56]) << 40U) |
               (static_cast<uint64_t>(bytes[57]) << 32U) |
               (static_cast<uint64_t>(bytes[58]) << 24U) |
               (static_cast<uint64_t>(bytes[59]) << 16U) |
               (static_cast<uint64_t>(bytes[60]) << 8U) |
               static_cast<uint64_t>(bytes[61]);
    }

    constexpr void set_tail_siphash48(uint64_t mac48) noexcept {
        bytes[56] = static_cast<uint8_t>((mac48 >> 40U) & 0xFFULL);
        bytes[57] = static_cast<uint8_t>((mac48 >> 32U) & 0xFFULL);
        bytes[58] = static_cast<uint8_t>((mac48 >> 24U) & 0xFFULL);
        bytes[59] = static_cast<uint8_t>((mac48 >> 16U) & 0xFFULL);
        bytes[60] = static_cast<uint8_t>((mac48 >> 8U) & 0xFFULL);
        bytes[61] = static_cast<uint8_t>(mac48 & 0xFFULL);
    }

    static constexpr ArenaWireFrame make_auto_liquidate_sweep(
        uint32_t account_id,
        uint16_t market_id            = 0U,
        uint32_t target_account_id    = 0U,
        uint64_t max_qty_lots         = 0ULL,
        int64_t  min_bounty_micro     = 0LL,
        bool     auto_offload_to_book = true,
        uint16_t seq_lo               = 1U,
        uint64_t seq_hi50             = 1ULL,
        uint64_t key_lo64             = 0x0123'4567'89AB'CDEFULL,
        uint64_t key_hi64             = 0xCAFE'BABE'DEAD'BEEFULL,
        StpMode  stp                  = StpMode::CancelResting,
        bool     hedge_margin_spot    = false
    ) noexcept;
};

static_assert(sizeof(ArenaWireFrame) == 64, "ArenaWireFrame must be exactly 64 bytes");
static_assert(alignof(ArenaWireFrame) == 64, "ArenaWireFrame must be 64-byte aligned");

inline constexpr ArenaWireFrame pack_wire_frame(
    const ArenaHeader& hdr,
    uint64_t           aux_param0,
    uint64_t           aux_param1,
    uint64_t           seq_hi50,
    uint64_t           key_lo64,
    uint64_t           key_hi64,
    uint16_t           ext_qty_hi16 = 0U
) noexcept {
    ArenaWireFrame frame{};
    uint64_t m0 = 0ULL;
    uint64_t m1 = 0ULL;
    uint32_t hi24 = 0U;
    hdr.pack_words(m0, m1, hi24);

    write_be64(&frame.bytes[0], m0);
    write_be64(&frame.bytes[8], m1);
    frame.bytes[16] = static_cast<uint8_t>((hi24 >> 16U) & 0xFFU);
    frame.bytes[17] = static_cast<uint8_t>((hi24 >> 8U) & 0xFFU);
    frame.bytes[18] = static_cast<uint8_t>(hi24 & 0xFFU);

    const uint64_t mac40 = calc_pre_siphash40(hdr, seq_hi50, key_lo64, key_hi64);
    frame.bytes[19] = static_cast<uint8_t>((mac40 >> 32U) & 0xFFULL);
    frame.bytes[20] = static_cast<uint8_t>((mac40 >> 24U) & 0xFFULL);
    frame.bytes[21] = static_cast<uint8_t>((mac40 >> 16U) & 0xFFULL);
    frame.bytes[22] = static_cast<uint8_t>((mac40 >> 8U) & 0xFFULL);
    frame.bytes[23] = static_cast<uint8_t>(mac40 & 0xFFULL);

    frame.bytes[24] = 0x01U; // ArenaWire v1
    write_be64(&frame.bytes[25], aux_param0);
    write_be64(&frame.bytes[33], aux_param1);
    if (ext_qty_hi16 != 0U) {
        write_be16_wire(&frame.bytes[41], ext_qty_hi16);
    }

    const uint64_t tail_mac48 = calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.set_tail_siphash48(tail_mac48);
    frame.bytes[62] = 0xA1U;
    frame.bytes[63] = 0xE0U;
    return frame;
}

[[nodiscard]] inline constexpr bool try_pack_wire_frame(
    const ArenaHeader& hdr,
    uint64_t           aux_param0,
    uint64_t           aux_param1,
    uint64_t           seq_hi50,
    uint64_t           key_lo64,
    uint64_t           key_hi64,
    ArenaWireFrame&    frame_out,
    uint16_t           ext_qty_hi16 = 0U
) noexcept {
    if (!is_valid_wire_fields(hdr, ext_qty_hi16)) {
        frame_out = ArenaWireFrame{};
        return false;
    }
    frame_out = pack_wire_frame(
        hdr, aux_param0, aux_param1, seq_hi50, key_lo64, key_hi64, ext_qty_hi16
    );
    return true;
}

inline constexpr uint64_t unpack_quote_ask_qty(
    const ArenaWireFrame& frame,
    uint64_t              aux_param1
) noexcept {
    return unpack_quote_ask_qty(aux_param1, read_be16_wire(&frame.bytes[41]));
}

inline constexpr void pack_quote_ext_tag_and_ladder(
    ArenaWireFrame& frame,
    uint64_t        client_tag,
    bool            ladder_by_tag,
    uint64_t        seq_hi50,
    uint64_t        key_lo64,
    uint64_t        key_hi64
) noexcept {
    if (client_tag == 0ULL && !ladder_by_tag) {
        return;
    }
    write_be64(&frame.bytes[43], client_tag);
    if (ladder_by_tag) {
        frame.bytes[51] |= WIRE_EXT51_FLAG_LADDER_BY_TAG;
    }
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64));
}

inline constexpr uint64_t unpack_quote_client_tag(const ArenaWireFrame& frame) noexcept {
    return read_be64(&frame.bytes[43]);
}

inline constexpr bool unpack_quote_ladder_by_tag(const ArenaWireFrame& frame) noexcept {
    return (frame.bytes[51] & WIRE_EXT51_FLAG_LADDER_BY_TAG) != 0U;
}

inline constexpr void pack_order_ext_stp_decrement_cancel(
    ArenaWireFrame& frame,
    bool            stp_decrement_and_cancel,
    uint64_t        seq_hi50,
    uint64_t        key_lo64,
    uint64_t        key_hi64
) noexcept {
    if (!stp_decrement_and_cancel) {
        return;
    }
    frame.bytes[51] |= WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL;
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64));
}

inline constexpr bool unpack_order_stp_decrement_cancel(const ArenaWireFrame& frame) noexcept {
    return (frame.bytes[51] & WIRE_EXT51_FLAG_STP_DECREMENT_CANCEL) != 0U;
}

// -----------------------------------------------------------------------------
// v4.9 Cross-Socket HFT Priority Auction (`bytes[52..53]` big-endian `uint16_t`,
// authenticated by `TailSipHash48` via `w4`, 0x0000 on all legacy frames):
//   - `NewOrder`: `priority_fee_ppm` (`0..50,000` ppm = `0..500.00` bps of filled taker notional; `0` on `PostOnly`)
//   - `AtomicSpread` (<=3 legs), `FlashArbitrage` (`MintRedeemSet`), `AutoCrossArb` (`LiquidateAccount`):
//     `express_surplus_bid_bps` (`0..5,000` bps = `0..50.00%` of realized arb surplus)
//   - `LiquidateAccount` / `AutoLiquidateSweep`: `bounty_rebate_bid_bps` (`0..10,000` bps = `0..100.00%` of liquidator cash bounty)
// -----------------------------------------------------------------------------
inline constexpr uint16_t MAX_PRIORITY_FEE_PPM         = 50'000U;
inline constexpr uint16_t MAX_EXPRESS_SURPLUS_BID_BPS  = 5'000U;
inline constexpr uint16_t MAX_LIQ_BOUNTY_REBATE_BID_BPS = 10'000U;

inline constexpr void pack_order_ext_priority_fee_ppm(
    ArenaWireFrame& frame,
    uint16_t        priority_fee_ppm,
    uint64_t        seq_hi50,
    uint64_t        key_lo64,
    uint64_t        key_hi64
) noexcept {
    if (priority_fee_ppm == 0U) {
        return;
    }
    const uint16_t clamped = std::min<uint16_t>(priority_fee_ppm, MAX_PRIORITY_FEE_PPM);
    write_be16_wire(&frame.bytes[52], clamped);
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64));
}

inline constexpr uint16_t unpack_order_priority_fee_ppm(const ArenaWireFrame& frame) noexcept {
    return read_be16_wire(&frame.bytes[52]);
}

inline constexpr void pack_wire_express_surplus_bid_bps(
    ArenaWireFrame& frame,
    uint16_t        express_surplus_bid_bps,
    uint64_t        seq_hi50,
    uint64_t        key_lo64,
    uint64_t        key_hi64
) noexcept {
    if (express_surplus_bid_bps == 0U) {
        return;
    }
    const uint16_t clamped = std::min<uint16_t>(express_surplus_bid_bps, MAX_EXPRESS_SURPLUS_BID_BPS);
    write_be16_wire(&frame.bytes[52], clamped);
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64));
}

inline constexpr void pack_wire_liq_bounty_rebate_bid_bps(
    ArenaWireFrame& frame,
    uint16_t        bounty_rebate_bid_bps,
    uint64_t        seq_hi50,
    uint64_t        key_lo64,
    uint64_t        key_hi64
) noexcept {
    if (bounty_rebate_bid_bps == 0U) {
        return;
    }
    const uint16_t clamped = std::min<uint16_t>(bounty_rebate_bid_bps, MAX_LIQ_BOUNTY_REBATE_BID_BPS);
    write_be16_wire(&frame.bytes[52], clamped);
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64));
}

inline constexpr bool liq_mode_flags_valid(uint64_t aux_param1) noexcept {
    const uint64_t mode_bits = aux_param1 & (
        LIQ_AUX1_FLAG_SET_KNOCKOUT |
        LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE |
        LIQ_AUX1_FLAG_AUTO_CROSS_ARB |
        LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP
    );
    return (mode_bits & (mode_bits - 1ULL)) == 0ULL;
}

inline constexpr uint16_t unpack_wire_express_surplus_bid_bps(
    const ArenaWireFrame& frame,
    BaseOp                op,
    uint64_t              aux_param1
) noexcept {
    if (op == BaseOp::AtomicSpread) {
        if ((aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0ULL &&
            (aux_param1 & SPREAD_AUX1_FLAG_BASKET_4_LEGS) != 0ULL) {
            return 0U; // bytes[52..54] encodes leg4 qty_lots on 4-leg baskets
        }
        return read_be16_wire(&frame.bytes[52]);
    }
    if (op == BaseOp::MintRedeemSet) {
        return ((aux_param1 & MINT_AUX1_FLAG_FLASH_ARB) != 0ULL)
             ? read_be16_wire(&frame.bytes[52])
             : 0U;
    }
    if (op == BaseOp::LiquidateAccount) {
        if (!liq_mode_flags_valid(aux_param1)) {
            return 0U;
        }
        return ((aux_param1 & LIQ_AUX1_FLAG_AUTO_CROSS_ARB) != 0ULL)
             ? read_be16_wire(&frame.bytes[52])
             : 0U;
    }
    return 0U;
}

inline constexpr uint16_t unpack_wire_liq_bounty_rebate_bid_bps(
    const ArenaWireFrame& frame,
    BaseOp                op,
    uint64_t              aux_param0,
    uint64_t              aux_param1
) noexcept {
    if (op != BaseOp::LiquidateAccount || !liq_mode_flags_valid(aux_param1)) {
        return 0U;
    }
    if ((aux_param1 & (LIQ_AUX1_FLAG_SET_KNOCKOUT | LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE | LIQ_AUX1_FLAG_AUTO_CROSS_ARB)) != 0ULL) {
        return 0U;
    }
    if ((aux_param1 & LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP) == 0ULL && aux_param0 == 0ULL) {
        return 0U;
    }
    return read_be16_wire(&frame.bytes[52]);
}

inline constexpr uint32_t peek_wire_priority_score(
    const ArenaWireFrame& frame,
    bool                  allow_arb_surplus_bids = true
) noexcept {
    if (frame.bytes[24] != 0x01U || frame.bytes[62] != 0xA1U || frame.bytes[63] != 0xE0U) {
        return 0U;
    }
    const BaseOp      op   = static_cast<BaseOp>((frame.bytes[0] >> 4U) & 0x0FU);
    const TimeInForce tif  = static_cast<TimeInForce>(frame.bytes[0] & 0x03U);
    const uint64_t    aux1 = read_be64(&frame.bytes[33]);
    if (op == BaseOp::NewOrder) {
        if (tif == TimeInForce::PostOnly ||
            (aux1 & (ORDER_AUX_FLAG_POST_ONLY_SLIDE |
                     ORDER_AUX_FLAG_PRIMARY_PEG |
                     ORDER_AUX_FLAG_MIDPOINT_PEG)) != 0ULL) {
            return 0U;
        }
        const uint16_t ppm = read_be16_wire(&frame.bytes[52]);
        if (ppm == 0U || ppm > MAX_PRIORITY_FEE_PPM) {
            return 0U;
        }
        return static_cast<uint32_t>(ppm) * 10U;
    }
    if (!allow_arb_surplus_bids) {
        return 0U;
    }
    if (op == BaseOp::LiquidateAccount) {
        if (!liq_mode_flags_valid(aux1)) {
            return 0U;
        }
        if ((aux1 & (LIQ_AUX1_FLAG_SET_KNOCKOUT | LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE | LIQ_AUX1_FLAG_AUTO_CROSS_ARB)) == 0ULL) {
            const uint64_t aux0 = read_be64(&frame.bytes[25]);
            const uint32_t hdr_acct =
                (static_cast<uint32_t>(frame.bytes[3]) << 16U) |
                (static_cast<uint32_t>(frame.bytes[4]) << 8U)  |
                static_cast<uint32_t>(frame.bytes[5]);
            if (aux0 > 0xFFFF'FFFFULL || (aux0 != 0ULL && static_cast<uint32_t>(aux0) == hdr_acct)) {
                return 0U;
            }
            const uint16_t bounty_bps = unpack_wire_liq_bounty_rebate_bid_bps(frame, op, aux0, aux1);
            if (bounty_bps > 0U && bounty_bps <= MAX_LIQ_BOUNTY_REBATE_BID_BPS) {
                return static_cast<uint32_t>(bounty_bps) * 50U;
            }
        }
    }
    const uint16_t bps  = unpack_wire_express_surplus_bid_bps(frame, op, aux1);
    if (bps == 0U || bps > MAX_EXPRESS_SURPLUS_BID_BPS) {
        return 0U;
    }
    return static_cast<uint32_t>(bps);
}

inline constexpr uint64_t siphash24_pair64(
    uint64_t key_lo64,
    uint64_t key_hi64,
    uint64_t w0,
    uint64_t w1
) noexcept {
    const uint64_t w2 = 16ULL << 56U;
    uint64_t v0 = key_lo64 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key_hi64 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key_lo64 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key_hi64 ^ 0x7465646279746573ULL;
    const std::array<uint64_t, 3> words{{w0, w1, w2}};
    for (const uint64_t m : words) {
        v3 ^= m;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }
    v2 ^= 0xFFULL;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

inline constexpr uint64_t siphash24_quad64(
    uint64_t key_lo64,
    uint64_t key_hi64,
    uint64_t w0,
    uint64_t w1,
    uint64_t w2,
    uint64_t w3
) noexcept {
    const uint64_t w4 = 32ULL << 56U;
    uint64_t v0 = key_lo64 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key_hi64 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key_lo64 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key_hi64 ^ 0x7465646279746573ULL;
    const std::array<uint64_t, 5> words{{w0, w1, w2, w3, w4}};
    for (const uint64_t m : words) {
        v3 ^= m;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }
    v2 ^= 0xFFULL;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

inline constexpr void compute_session_key_wrap_pad(
    uint64_t  cur_key_lo64,
    uint64_t  cur_key_hi64,
    uint64_t  seq_hi50,
    uint16_t  seq_lo,
    uint32_t  account_id,
    uint64_t  wrap_salt64,
    uint64_t& pad_lo_out,
    uint64_t& pad_hi_out
) noexcept {
    const uint64_t wrap_klo = siphash24_pair64(
        cur_key_lo64 ^ 0x575241505F4B3031ULL,
        cur_key_hi64 ^ 0x575241505F4B3032ULL,
        0x575241505F4B4559ULL,
        0x53455353494F4E31ULL
    );
    const uint64_t wrap_khi = siphash24_pair64(
        cur_key_lo64 ^ 0x575241505F4B3033ULL,
        cur_key_hi64 ^ 0x575241505F4B3034ULL,
        0x575241505F4B4559ULL,
        0x53455353494F4E32ULL
    );
    const uint64_t w0 =
        ((seq_hi50 & 0x0003'FFFF'FFFF'FFFFULL) << 14U) |
        static_cast<uint64_t>(seq_lo & 0x3FFFU);
    pad_lo_out = siphash24_quad64(
        wrap_klo,
        wrap_khi,
        w0,
        wrap_salt64,
        (0x4B57'5230ULL << 32U) | static_cast<uint64_t>(account_id),
        0x5041445F56320000ULL
    );
    pad_hi_out = siphash24_quad64(
        wrap_klo,
        wrap_khi,
        w0,
        wrap_salt64,
        (0x4B57'5231ULL << 32U) | static_cast<uint64_t>(account_id),
        0x5041445F56320001ULL
    );
}

inline constexpr ArenaWireFrame pack_encrypted_register_session_key_frame(
    uint32_t account_id,
    uint16_t seq_lo,
    uint64_t seq_hi50,
    uint64_t cur_key_lo64,
    uint64_t cur_key_hi64,
    uint64_t new_key_lo64,
    uint64_t new_key_hi64,
    uint64_t wrap_salt64
) noexcept {
    if (wrap_salt64 == 0ULL || account_id > 0xFF'FFFFU) {
        return ArenaWireFrame{};
    }
    ArenaHeader hdr{};
    hdr.op          = BaseOp::RegisterSessionKey;
    hdr.flags       = ArenaFlags{TimeInForce::GTC, StpMode::CancelResting};
    hdr.market_id   = 0U;
    hdr.account_id  = account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = static_cast<uint16_t>(seq_lo & 0x3FFFU);
    hdr.price_ticks = 0LL;
    hdr.qty_lots    = 0ULL;
    uint64_t pad_lo = 0ULL;
    uint64_t pad_hi = 0ULL;
    compute_session_key_wrap_pad(
        cur_key_lo64,
        cur_key_hi64,
        seq_hi50,
        hdr.seq_lo,
        account_id,
        wrap_salt64,
        pad_lo,
        pad_hi
    );
    ArenaWireFrame frame = pack_wire_frame(
        hdr,
        new_key_lo64 ^ pad_lo,
        new_key_hi64 ^ pad_hi,
        seq_hi50,
        cur_key_lo64,
        cur_key_hi64
    );
    write_be64(&frame.bytes[41], wrap_salt64);
    frame.bytes[51] |= WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP;
    frame.set_tail_siphash48(calc_tail_siphash48(frame.bytes, seq_hi50, cur_key_lo64, cur_key_hi64));
    return frame;
}

inline constexpr bool unpack_register_session_key_wire(
    const ArenaWireFrame& frame,
    const ArenaHeader&    hdr,
    uint64_t              seq_hi50,
    uint64_t              cur_key_lo64,
    uint64_t              cur_key_hi64,
    uint64_t              raw_aux0,
    uint64_t              raw_aux1,
    uint64_t&             new_key_lo64_out,
    uint64_t&             new_key_hi64_out,
    bool&                 was_encrypted_out,
    bool                  allow_legacy_plaintext = false
) noexcept {
    was_encrypted_out = (frame.bytes[51] & WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0U;
    if (!was_encrypted_out) {
        if (!allow_legacy_plaintext) {
            new_key_lo64_out = 0ULL;
            new_key_hi64_out = 0ULL;
            return false;
        }
        new_key_lo64_out = raw_aux0;
        new_key_hi64_out = raw_aux1;
        return true;
    }
    const uint64_t wrap_salt64 = read_be64(&frame.bytes[41]);
    if (wrap_salt64 == 0ULL) {
        new_key_lo64_out = 0ULL;
        new_key_hi64_out = 0ULL;
        return false;
    }
    uint64_t pad_lo = 0ULL;
    uint64_t pad_hi = 0ULL;
    compute_session_key_wrap_pad(
        cur_key_lo64,
        cur_key_hi64,
        seq_hi50,
        hdr.seq_lo,
        hdr.account_id,
        wrap_salt64,
        pad_lo,
        pad_hi
    );
    new_key_lo64_out = raw_aux0 ^ pad_lo;
    new_key_hi64_out = raw_aux1 ^ pad_hi;
    return true;
}

inline constexpr uint64_t MAX_WIRE_HEADER_QTY_LOTS          = 0xFF'FFFF'FFFFULL;
inline constexpr uint64_t MAX_WIRE_EXT_QTY_LOTS             = QUOTE_AUX_QTY_50_MASK;
inline constexpr uint64_t MAX_WIRE_BASKET_LEG24_QTY_LOTS    = 0x00FF'FFFFULL;
inline constexpr int64_t  MIN_WIRE_BASKET_LEG34_PRICE_TICKS = -2'147'483'648LL;
inline constexpr int64_t  MAX_WIRE_BASKET_LEG34_PRICE_TICKS =  2'147'483'647LL;

inline constexpr uint64_t anonymize_itch_account_id(
    uint32_t account_id,
    uint64_t key_lo64         = 0ULL,
    uint64_t key_hi64         = 0ULL,
    uint64_t epoch_salt_nonce = 0ULL
) noexcept {
    if (account_id == 0U) {
        return 0ULL;
    }
    if (epoch_salt_nonce != 0ULL) {
        key_lo64 ^= (epoch_salt_nonce * 0x9E37'79B9'7F4A'7C15ULL);
        key_hi64 ^= (epoch_salt_nonce * 0xBF58'476D'1CE4'E5B9ULL);
    }
    if (key_lo64 == 0ULL && key_hi64 == 0ULL) {
        uint64_t z = static_cast<uint64_t>(account_id) + 0x9E37'79B9'7F4A'7C15ULL;
        z = (z ^ (z >> 30U)) * 0xBF58'476D'1CE4'E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D0'49BB'1331'11EBULL;
        return (z ^ (z >> 31U)) | (1ULL << 63U);
    }
    const uint64_t m = (4ULL << 56U) | static_cast<uint64_t>(account_id);
    uint64_t v0 = key_lo64 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key_hi64 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key_lo64 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key_hi64 ^ 0x7465646279746573ULL ^ m;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= m;
    v2 ^= 0xFFULL;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    return (v0 ^ v1 ^ v2 ^ v3) | (1ULL << 63U);
}

inline constexpr uint64_t unpack_spread_leg2_qty(
    uint64_t              aux_param1,
    const ArenaWireFrame* frame = nullptr
) noexcept {
    if (frame != nullptr &&
        ((aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) == 0ULL ||
         (aux_param1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) != 0ULL)) {
        return unpack_quote_ask_qty(aux_param1, read_be16_wire(&frame->bytes[41]));
    }
    if ((aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) != 0ULL &&
        (aux_param1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16) != 0ULL) {
        return aux_param1 & 0xFFFFFFULL;
    }
    return aux_param1 & QUOTE_AUX_QTY_MASK;
}

inline constexpr ArenaWireFrame ArenaWireFrame::make_auto_liquidate_sweep(
    uint32_t account_id,
    uint16_t market_id,
    uint32_t target_account_id,
    uint64_t max_qty_lots,
    int64_t  min_bounty_micro,
    bool     auto_offload_to_book,
    uint16_t seq_lo,
    uint64_t seq_hi50,
    uint64_t key_lo64,
    uint64_t key_hi64,
    StpMode  stp,
    bool     hedge_margin_spot
) noexcept {
    ArenaHeader hdr{};
    hdr.op          = BaseOp::LiquidateAccount;
    hdr.flags       = ArenaFlags{auto_offload_to_book ? TimeInForce::IOC : TimeInForce::GTC, stp};
    hdr.market_id   = market_id;
    hdr.account_id  = account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = min_bounty_micro;
    hdr.qty_lots    = max_qty_lots;
    const uint64_t aux1 = LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP |
                          (auto_offload_to_book ? 0ULL : LIQ_AUX1_FLAG_NO_OFFLOAD) |
                          (hedge_margin_spot ? LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT : 0ULL);
    return pack_wire_frame(hdr, static_cast<uint64_t>(target_account_id), aux1, seq_hi50, key_lo64, key_hi64);
}

inline constexpr void unpack_wire_frame(
    const ArenaWireFrame& frame,
    ArenaHeader&          hdr_out,
    uint64_t&             rx_mac40_out,
    uint64_t&             aux_param0_out,
    uint64_t&             aux_param1_out
) noexcept {
    const uint64_t m0 = read_be64(&frame.bytes[0]);
    const uint64_t m1 = read_be64(&frame.bytes[8]);
    const uint64_t hi24 =
        (static_cast<uint64_t>(frame.bytes[16]) << 16U) |
        (static_cast<uint64_t>(frame.bytes[17]) << 8U) |
        static_cast<uint64_t>(frame.bytes[18]);

    const uint8_t op_fl = static_cast<uint8_t>((m0 >> 56U) & 0xFFULL);
    hdr_out.op          = static_cast<BaseOp>((op_fl >> 4U) & 0xFU);
    hdr_out.flags       = ArenaFlags::unpack4(static_cast<uint8_t>(op_fl & 0xFU));
    hdr_out.market_id   = static_cast<uint16_t>((m0 >> 40U) & 0xFFFFULL);
    hdr_out.account_id  = static_cast<uint32_t>((m0 >> 16U) & 0xFFFFFFULL);
    const uint16_t sd_s = static_cast<uint16_t>(m0 & 0xFFFFULL);
    hdr_out.side        = static_cast<OrderSide>((sd_s >> 14U) & 0x3U);
    hdr_out.seq_lo      = static_cast<uint16_t>(sd_s & 0x3FFFU);

    const uint64_t p48 = (m1 >> 16U) & 0xFFFF'FFFF'FFFFULL;
    if ((p48 & (1ULL << 47U)) != 0ULL) {
        hdr_out.price_ticks = static_cast<int64_t>(p48 | 0xFFFF'0000'0000'0000ULL);
    } else {
        hdr_out.price_ticks = static_cast<int64_t>(p48);
    }
    hdr_out.qty_lots = (((m1 & 0xFFFFULL) << 24U) | hi24) & 0xFF'FFFF'FFFFULL;

    rx_mac40_out =
        (static_cast<uint64_t>(frame.bytes[19]) << 32U) |
        (static_cast<uint64_t>(frame.bytes[20]) << 24U) |
        (static_cast<uint64_t>(frame.bytes[21]) << 16U) |
        (static_cast<uint64_t>(frame.bytes[22]) << 8U) |
        static_cast<uint64_t>(frame.bytes[23]);

    aux_param0_out = read_be64(&frame.bytes[25]);
    aux_param1_out = read_be64(&frame.bytes[33]);
}

inline constexpr ArenaWireFrame pack_wire_basket_frame(
    uint32_t                            account_id,
    uint8_t                             num_legs,
    const std::array<WireBasketLeg, 4>& legs,
    StpMode                             stp,
    bool                                margin_spot,
    uint16_t                            seq_lo,
    uint64_t                            seq_hi50,
    uint64_t                            key_lo64,
    uint64_t                            key_hi64
) noexcept {
    if (account_id > 0xFF'FFFFU || num_legs < 2U || num_legs > 4U ||
        !is_valid_wire_price_ticks_48_val(legs[0].price_ticks) ||
        legs[0].qty_lots > MAX_WIRE_HEADER_QTY_LOTS ||
        !is_valid_wire_price_ticks_48_val(legs[1].price_ticks)) {
        return ArenaWireFrame{};
    }
    if (num_legs == 2U && legs[1].qty_lots > MAX_WIRE_EXT_QTY_LOTS) {
        return ArenaWireFrame{};
    }
    if (num_legs >= 3U) {
        const bool ext_m = (legs[2].market_id > 0xFFU) || (num_legs >= 4U && legs[3].market_id > 0xFFU);
        const uint64_t leg2_cap = ext_m ? MAX_WIRE_BASKET_LEG24_QTY_LOTS : QUOTE_AUX_QTY_MASK;
        if (legs[1].qty_lots > leg2_cap ||
            legs[2].qty_lots > MAX_WIRE_BASKET_LEG24_QTY_LOTS ||
            legs[2].price_ticks < MIN_WIRE_BASKET_LEG34_PRICE_TICKS ||
            legs[2].price_ticks > MAX_WIRE_BASKET_LEG34_PRICE_TICKS) {
            return ArenaWireFrame{};
        }
        if (num_legs >= 4U &&
            (legs[3].qty_lots > MAX_WIRE_BASKET_LEG24_QTY_LOTS ||
             legs[3].price_ticks < MIN_WIRE_BASKET_LEG34_PRICE_TICKS ||
             legs[3].price_ticks > MAX_WIRE_BASKET_LEG34_PRICE_TICKS)) {
            return ArenaWireFrame{};
        }
    }
    ArenaHeader hdr{};
    hdr.op          = BaseOp::AtomicSpread;
    hdr.flags.tif   = TimeInForce::FOK;
    hdr.flags.stp   = stp;
    hdr.market_id   = legs[0].market_id;
    hdr.account_id  = account_id;
    hdr.side        = legs[0].side;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = legs[0].price_ticks;
    hdr.qty_lots    = legs[0].qty_lots;

    bool any_margin_spot = margin_spot;
    for (uint8_t i = 0U; i < num_legs && i < 4U; ++i) {
        if (legs[i].margin_spot) any_margin_spot = true;
    }

    uint64_t aux0 = 0ULL;
    uint64_t aux1 = 0ULL;
    pack_atomic_spread_aux(
        legs[1].market_id,
        legs[1].side,
        legs[1].price_ticks,
        legs[1].qty_lots,
        legs[0].is_market,
        legs[0].reduce_only,
        legs[1].is_market,
        legs[1].reduce_only,
        aux0,
        aux1,
        any_margin_spot
    );
    aux1 |= SPREAD_AUX1_FLAG_MULTI_LEG_BASKET;
    if (num_legs == 2U) {
        aux1 |= SPREAD_AUX1_FLAG_BASKET_2_LEGS;
    } else if (num_legs >= 4U) {
        aux1 |= SPREAD_AUX1_FLAG_BASKET_4_LEGS;
    }
    if (num_legs >= 3U) {
        if (legs[2].side == OrderSide::Ask) aux1 |= SPREAD_AUX1_FLAG_LEG3_ASK;
        if (legs[2].is_market)              aux1 |= SPREAD_AUX1_FLAG_LEG3_MARKET;
        if (legs[2].reduce_only)            aux1 |= SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY;
    }
    if (num_legs >= 4U) {
        aux1 |= (static_cast<uint64_t>(legs[3].market_id & 0xFFU) << SPREAD_AUX1_LEG4_MKT_SHIFT);
        if (legs[3].side == OrderSide::Ask) aux1 |= SPREAD_AUX1_FLAG_LEG4_ASK;
        if (legs[3].is_market)              aux1 |= SPREAD_AUX1_FLAG_LEG4_MARKET;
        if (legs[3].reduce_only)            aux1 |= SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY;
    }
    if (num_legs >= 3U &&
        (legs[2].market_id > 0xFFU || (num_legs >= 4U && legs[3].market_id > 0xFFU))) {
        aux1 = (aux1 & ~0x0000'00FF'FF00'0000ULL) |
               SPREAD_AUX1_FLAG_BASKET_EXT_MKT16 |
               (static_cast<uint64_t>((legs[2].market_id >> 8U) & 0xFFU) << SPREAD_AUX1_LEG3_MKT_HI8_SHIFT) |
               ((num_legs >= 4U)
                    ? (static_cast<uint64_t>((legs[3].market_id >> 8U) & 0xFFU) << SPREAD_AUX1_LEG4_MKT_HI8_SHIFT)
                    : 0ULL);
    }

    ArenaWireFrame frame{};
    uint64_t m0 = 0ULL;
    uint64_t m1 = 0ULL;
    uint32_t hi24 = 0U;
    hdr.pack_words(m0, m1, hi24);

    write_be64(&frame.bytes[0], m0);
    write_be64(&frame.bytes[8], m1);
    frame.bytes[16] = static_cast<uint8_t>((hi24 >> 16U) & 0xFFU);
    frame.bytes[17] = static_cast<uint8_t>((hi24 >> 8U) & 0xFFU);
    frame.bytes[18] = static_cast<uint8_t>(hi24 & 0xFFU);

    const uint64_t mac40 = calc_pre_siphash40(hdr, seq_hi50, key_lo64, key_hi64);
    frame.bytes[19] = static_cast<uint8_t>((mac40 >> 32U) & 0xFFULL);
    frame.bytes[20] = static_cast<uint8_t>((mac40 >> 24U) & 0xFFULL);
    frame.bytes[21] = static_cast<uint8_t>((mac40 >> 16U) & 0xFFULL);
    frame.bytes[22] = static_cast<uint8_t>((mac40 >> 8U) & 0xFFULL);
    frame.bytes[23] = static_cast<uint8_t>(mac40 & 0xFFULL);

    frame.bytes[24] = 0x01U;
    write_be64(&frame.bytes[25], aux0);
    write_be64(&frame.bytes[33], aux1);

    if (num_legs == 2U) {
        write_be16_wire(&frame.bytes[41], pack_quote_ask_qty_hi16(legs[1].qty_lots));
    } else if (num_legs >= 3U) {
        write_be32_wire(&frame.bytes[41], static_cast<uint32_t>(legs[2].price_ticks));
        const uint32_t q3 = static_cast<uint32_t>(legs[2].qty_lots & 0xFFFFFFULL);
        frame.bytes[49] = static_cast<uint8_t>((q3 >> 16U) & 0xFFU);
        frame.bytes[50] = static_cast<uint8_t>((q3 >> 8U) & 0xFFU);
        frame.bytes[51] = static_cast<uint8_t>(q3 & 0xFFU);
        frame.bytes[55] = static_cast<uint8_t>(legs[2].market_id & 0xFFU);
    }
    if (num_legs >= 4U) {
        write_be32_wire(&frame.bytes[45], static_cast<uint32_t>(legs[3].price_ticks));
        const uint32_t q4 = static_cast<uint32_t>(legs[3].qty_lots & 0xFFFFFFULL);
        frame.bytes[52] = static_cast<uint8_t>((q4 >> 16U) & 0xFFU);
        frame.bytes[53] = static_cast<uint8_t>((q4 >> 8U) & 0xFFU);
        frame.bytes[54] = static_cast<uint8_t>(q4 & 0xFFU);
    }

    const uint64_t tail_mac48 = calc_tail_siphash48(frame.bytes, seq_hi50, key_lo64, key_hi64);
    frame.set_tail_siphash48(tail_mac48);
    frame.bytes[62] = 0xA1U;
    frame.bytes[63] = 0xE0U;
    return frame;
}

[[nodiscard]] inline constexpr bool try_pack_wire_basket_frame(
    uint32_t                            account_id,
    uint8_t                             num_legs,
    const std::array<WireBasketLeg, 4>& legs,
    StpMode                             stp,
    bool                                margin_spot,
    uint16_t                            seq_lo,
    uint64_t                            seq_hi50,
    uint64_t                            key_lo64,
    uint64_t                            key_hi64,
    ArenaWireFrame&                     frame_out
) noexcept {
    frame_out = pack_wire_basket_frame(
        account_id, num_legs, legs, stp, margin_spot, seq_lo, seq_hi50, key_lo64, key_hi64
    );
    return frame_out.bytes[24] == 0x01U && frame_out.bytes[62] == 0xA1U && frame_out.bytes[63] == 0xE0U;
}

inline constexpr void unpack_wire_basket_legs34(
    const ArenaWireFrame& frame,
    uint64_t              aux_param1,
    uint8_t&              num_legs_out,
    WireBasketLeg&        leg3_out,
    WireBasketLeg&        leg4_out
) noexcept {
    if ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_2_LEGS) != 0ULL ||
        (aux_param1 & SPREAD_AUX1_FLAG_MULTI_LEG_BASKET) == 0ULL) {
        num_legs_out = 2U;
        return;
    }
    num_legs_out = ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_4_LEGS) != 0ULL) ? 4U : 3U;

    const bool ext_mkt16 = ((aux_param1 & SPREAD_AUX1_FLAG_BASKET_EXT_MKT16) != 0ULL);
    const uint16_t leg3_hi8 = ext_mkt16
        ? static_cast<uint16_t>(((aux_param1 >> SPREAD_AUX1_LEG3_MKT_HI8_SHIFT) & 0xFFULL) << 8U)
        : 0U;
    leg3_out.market_id   = static_cast<uint16_t>(static_cast<uint16_t>(frame.bytes[55]) | leg3_hi8);
    leg3_out.side        = ((aux_param1 & SPREAD_AUX1_FLAG_LEG3_ASK) != 0ULL) ? OrderSide::Ask : OrderSide::Bid;
    leg3_out.price_ticks = static_cast<int64_t>(static_cast<int32_t>(read_be32_wire(&frame.bytes[41])));
    leg3_out.qty_lots    = (static_cast<uint64_t>(frame.bytes[49]) << 16U) |
                           (static_cast<uint64_t>(frame.bytes[50]) << 8U)  |
                           static_cast<uint64_t>(frame.bytes[51]);
    leg3_out.is_market   = ((aux_param1 & SPREAD_AUX1_FLAG_LEG3_MARKET) != 0ULL);
    leg3_out.reduce_only = ((aux_param1 & SPREAD_AUX1_FLAG_LEG3_REDUCE_ONLY) != 0ULL);

    if (num_legs_out >= 4U) {
        const uint16_t leg4_hi8 = ext_mkt16
            ? static_cast<uint16_t>(((aux_param1 >> SPREAD_AUX1_LEG4_MKT_HI8_SHIFT) & 0xFFULL) << 8U)
            : 0U;
        leg4_out.market_id   = static_cast<uint16_t>(
            static_cast<uint16_t>((aux_param1 >> SPREAD_AUX1_LEG4_MKT_SHIFT) & 0xFFULL) | leg4_hi8
        );
        leg4_out.side        = ((aux_param1 & SPREAD_AUX1_FLAG_LEG4_ASK) != 0ULL) ? OrderSide::Ask : OrderSide::Bid;
        leg4_out.price_ticks = static_cast<int64_t>(static_cast<int32_t>(read_be32_wire(&frame.bytes[45])));
        leg4_out.qty_lots    = (static_cast<uint64_t>(frame.bytes[52]) << 16U) |
                               (static_cast<uint64_t>(frame.bytes[53]) << 8U)  |
                               static_cast<uint64_t>(frame.bytes[54]);
        leg4_out.is_market   = ((aux_param1 & SPREAD_AUX1_FLAG_LEG4_MARKET) != 0ULL);
        leg4_out.reduce_only = ((aux_param1 & SPREAD_AUX1_FLAG_LEG4_REDUCE_ONLY) != 0ULL);
    }
}

// -----------------------------------------------------------------------------
// 64-Byte Cacheline-Aligned Egress Execution / Query Response (`ArenaWireResponse`)
// Layout (8 x big-endian 64-bit words):
//   w0 [0..7]   : (status_code << 56) | (order_status << 48) | (wal_seq & 0xFFFF'FFFF'FFFF)
//   w1 [8..15]  : order_id        (or bid_order_id on TwoSidedQuoteReplace)
//   w2 [16..23] : filled_lots     (or best_bid_lots on QueryBookBbo)
//   w3 [24..31] : resting_lots    (or best_ask_lots on QueryBookBbo)
//   w4 [32..39] : avg_price_ticks (or ask_order_id on TwoSidedQuoteReplace, free_usd_micro on QueryAccount)
//   w5 [40..47] : best_bid_ticks  (or equity_usd_micro on QueryAccount)
//   w6 [48..55] : best_ask_ticks  (or initial_margin_req_micro on QueryAccount)
//   w7 [56..63] : fee_or_position (net fee micro-USD on order, or perp_position_lots on QueryAccount)
// -----------------------------------------------------------------------------
struct ArenaWireResponse {
    WireStatusCode  status_code{WireStatusCode::Ok};
    WireOrderStatus order_status{WireOrderStatus::None};
    uint64_t        wal_seq{0};
    uint64_t        order_id{0};
    uint64_t        filled_lots{0};
    uint64_t        resting_lots{0};
    int64_t         avg_price_ticks{0};
    int64_t         best_bid_ticks{0};
    int64_t         best_ask_ticks{0};
    int64_t         fee_or_position{0};
    uint64_t        bid_filled_lots{0};
    uint64_t        ask_filled_lots{0};

    constexpr std::array<uint8_t, ARENA_WIRE_BYTES> pack_bytes() const noexcept {
        std::array<uint8_t, ARENA_WIRE_BYTES> out{};
        const bool has_quote_side_fills =
            (bid_filled_lots > 0ULL || ask_filled_lots > 0ULL) &&
            (bid_filled_lots <= 0xFFFFULL) &&
            (wal_seq <= 0xFFFF'FFFFULL);
        const uint8_t os_byte = static_cast<uint8_t>(
            (static_cast<uint8_t>(order_status) & 0x7FU) | (has_quote_side_fills ? 0x80U : 0x00U)
        );
        const uint64_t w0_low48 = has_quote_side_fills
            ? (((bid_filled_lots & 0xFFFFULL) << 32U) | (wal_seq & 0xFFFF'FFFFULL))
            : (wal_seq & 0xFFFF'FFFF'FFFFULL);
        const uint64_t w0 =
            (static_cast<uint64_t>(status_code) << 56U) |
            (static_cast<uint64_t>(os_byte) << 48U) |
            w0_low48;
        write_be64(&out[0],  w0);
        write_be64(&out[8],  order_id);
        write_be64(&out[16], filled_lots);
        write_be64(&out[24], resting_lots);
        write_be64(&out[32], static_cast<uint64_t>(avg_price_ticks));
        write_be64(&out[40], static_cast<uint64_t>(best_bid_ticks));
        write_be64(&out[48], static_cast<uint64_t>(best_ask_ticks));
        write_be64(&out[56], static_cast<uint64_t>(fee_or_position));
        return out;
    }

    static constexpr ArenaWireResponse unpack_bytes(
        const std::array<uint8_t, ARENA_WIRE_BYTES>& raw
    ) noexcept {
        ArenaWireResponse r{};
        const uint64_t w0     = read_be64(&raw[0]);
        const uint8_t  os_raw = static_cast<uint8_t>((w0 >> 48U) & 0xFFULL);
        r.status_code         = static_cast<WireStatusCode>((w0 >> 56U) & 0xFFULL);
        r.order_status        = static_cast<WireOrderStatus>(os_raw & 0x7FU);
        r.order_id            = read_be64(&raw[8]);
        r.filled_lots         = read_be64(&raw[16]);
        r.resting_lots        = read_be64(&raw[24]);
        r.avg_price_ticks     = static_cast<int64_t>(read_be64(&raw[32]));
        r.best_bid_ticks      = static_cast<int64_t>(read_be64(&raw[40]));
        r.best_ask_ticks      = static_cast<int64_t>(read_be64(&raw[48]));
        r.fee_or_position     = static_cast<int64_t>(read_be64(&raw[56]));
        if ((os_raw & 0x80U) != 0U) {
            r.wal_seq         = w0 & 0xFFFF'FFFFULL;
            r.bid_filled_lots = (w0 >> 32U) & 0xFFFFULL;
            r.ask_filled_lots = (r.filled_lots >= r.bid_filled_lots)
                              ? (r.filled_lots - r.bid_filled_lots)
                              : 0ULL;
        } else {
            r.wal_seq = w0 & 0xFFFF'FFFF'FFFFULL;
        }
        return r;
    }
};

// =============================================================================
// 64-Byte Cacheline-Aligned Binary L3 Market-Data Feed (`ArenaITCH` v1)
// Layout:
//   [0..1]   : Magic `0x4149` ("AI")
//   [2]      : Version `0x01`
//   [3]      : `ItchEventType` (`uint8_t`)
//   [4..5]   : `market_id` (`uint16_t` big-endian)
//   [6]      : `side` (`OrderSide`, `0=Bid`, `1=Ask`)
//   [7]      : `flags` (`bit 0 = reduce_only`, `bits [3:2] = ItchDeleteReason`)
//   [8..15]  : `itch_seq` (`uint64_t` monotonic feed sequence)
//   [16..23] : `wal_seq` (`uint64_t` engine WAL sequence)
//   [24..31] : `order_id` (`uint64_t`; `maker_order_id` on Execute, `oi_lots` on Mark, `order_cnt` on SnapshotEnd)
//   [32..39] : `price_ticks` (`int64_t`; order/exec/mark price in $0.01 ticks)
//   [40..47] : `qty_lots` (`uint64_t`; added/executed/new_remaining/deleted lots)
//   [48..55] : `aux_u64` (`uint64_t`; `account_id` or SipHash-anonymized tag on Add/Delete/SnapshotOrder, `trade_id` on Execute,
//                         `prev_remaining_lots` on Modify, `cumulative_funding_phi` on Mark)
//   [56..63] : `checksum64` (`uint64_t` SipHash-2-4 over bytes `[0..55]`)
// =============================================================================
inline constexpr uint16_t    ARENA_ITCH_MAGIC     = 0x4149U;     // "AI"
inline constexpr uint8_t     ARENA_ITCH_VERSION   = 0x01U;
inline constexpr std::size_t ARENA_ITCH_BYTES     = 64U;
inline constexpr uint32_t    ARENA_ITCH_REQ_MAGIC = 0x41495251U; // "AIRQ"
inline constexpr std::size_t ARENA_ITCH_REQ_BYTES = 16U;

enum class ItchEventType : uint8_t {
    OrderAdded     = 0x01,
    OrderExecuted  = 0x02,
    OrderModified  = 0x03, // Queue-preserving in-place quantity/price modification (reduce, keep-priority size-up, peg reprice, auto-compound)
    OrderDeleted   = 0x04,
    MarkAndFunding = 0x05,
    SnapshotBegin    = 0x06,
    SnapshotOrder    = 0x07,
    SnapshotEnd      = 0x08,
    LedgerCheckpoint = 0x09, // Rolling 256-bit Keccak-256 WAL hash chain checkpoint (`order_id || price_ticks || qty_lots || aux_u64`)
    MarketDirectory  = 0x0A, // Live / snapshot 64B instrument directory announcement (16B symbol + kind/formula/refs/mark)
    Heartbeat        = 0x0F
};

enum class ItchDeleteReason : uint8_t {
    UserCancel            = 0,
    SelfTradePrevention   = 1,
    CancelAllOrDisconnect = 2,
    Liquidation           = 3
};

inline constexpr uint8_t pack_itch_flags(bool reduce_only, ItchDeleteReason reason = ItchDeleteReason::UserCancel) noexcept {
    return static_cast<uint8_t>(
        (reduce_only ? 1U : 0U) |
        ((static_cast<uint8_t>(reason) & 0x3U) << 2U)
    );
}

struct alignas(64) ArenaItchFrame {
    std::array<uint8_t, ARENA_ITCH_BYTES> bytes{};
};

static_assert(sizeof(ArenaItchFrame) == 64, "ArenaItchFrame must be exactly 64 bytes");
static_assert(alignof(ArenaItchFrame) == 64, "ArenaItchFrame must be 64-byte aligned");

struct ArenaItchMessage {
    ItchEventType event_type  = ItchEventType::Heartbeat;
    uint16_t      market_id   = 0;
    OrderSide     side        = OrderSide::Bid;
    uint8_t       flags       = 0;
    uint64_t      itch_seq    = 0;
    uint64_t      wal_seq     = 0;
    uint64_t      order_id    = 0;
    int64_t       price_ticks = 0;
    uint64_t      qty_lots    = 0;
    uint64_t      aux_u64     = 0;

    static constexpr uint64_t compute_checksum64(
        const std::array<uint8_t, ARENA_ITCH_BYTES>& raw
    ) noexcept {
        constexpr uint64_t k0 = 0x4152'454E'4149'5443ULL; // "ARENAITC"
        constexpr uint64_t k1 = 0x485F'5631'5F4D'4143ULL; // "H_V1_MAC"
        uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
        uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
        uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
        uint64_t v3 = k1 ^ 0x7465646279746573ULL;

        for (std::size_t off = 0U; off < 56U; off += 8U) {
            const uint64_t m = read_be64(&raw[off]);
            v3 ^= m;
            sip_round(v0, v1, v2, v3);
            sip_round(v0, v1, v2, v3);
            v0 ^= m;
        }
        const uint64_t len_b = (56ULL << 56U);
        v3 ^= len_b;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= len_b;

        v2 ^= 0xFFULL;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        return v0 ^ v1 ^ v2 ^ v3;
    }

    [[nodiscard]] constexpr ArenaItchFrame pack_frame() const noexcept {
        ArenaItchFrame f{};
        write_be16_wire(&f.bytes[0], ARENA_ITCH_MAGIC);
        f.bytes[2] = ARENA_ITCH_VERSION;
        f.bytes[3] = static_cast<uint8_t>(event_type);
        write_be16_wire(&f.bytes[4], market_id);
        f.bytes[6] = static_cast<uint8_t>(side) & 0x1U;
        f.bytes[7] = flags;
        write_be64(&f.bytes[8],  itch_seq);
        write_be64(&f.bytes[16], wal_seq);
        write_be64(&f.bytes[24], order_id);
        write_be64(&f.bytes[32], static_cast<uint64_t>(price_ticks));
        write_be64(&f.bytes[40], qty_lots);
        write_be64(&f.bytes[48], aux_u64);
        const uint64_t chk = compute_checksum64(f.bytes);
        write_be64(&f.bytes[56], chk);
        return f;
    }

    static constexpr bool unpack_and_verify(
        const ArenaItchFrame& f,
        ArenaItchMessage&     out
    ) noexcept {
        if (read_be16_wire(&f.bytes[0]) != ARENA_ITCH_MAGIC ||
            f.bytes[2] != ARENA_ITCH_VERSION) {
            return false;
        }
        const uint64_t expected_chk = compute_checksum64(f.bytes);
        const uint64_t actual_chk   = read_be64(&f.bytes[56]);
        if (expected_chk != actual_chk) {
            return false;
        }
        out.event_type  = static_cast<ItchEventType>(f.bytes[3]);
        out.market_id   = read_be16_wire(&f.bytes[4]);
        out.side        = static_cast<OrderSide>(f.bytes[6] & 0x1U);
        out.flags       = f.bytes[7];
        out.itch_seq    = read_be64(&f.bytes[8]);
        out.wal_seq     = read_be64(&f.bytes[16]);
        out.order_id    = read_be64(&f.bytes[24]);
        out.price_ticks = static_cast<int64_t>(read_be64(&f.bytes[32]));
        out.qty_lots    = read_be64(&f.bytes[40]);
        out.aux_u64     = read_be64(&f.bytes[48]);
        return true;
    }

    static constexpr ArenaItchMessage make_ledger_checkpoint(
        uint64_t                      wal_seq,
        const std::array<uint8_t, 32>& hash32
    ) noexcept {
        ArenaItchMessage m{};
        m.event_type  = ItchEventType::LedgerCheckpoint;
        m.market_id   = 0U;
        m.wal_seq     = wal_seq;
        m.order_id    = read_be64(&hash32[0]);
        m.price_ticks = static_cast<int64_t>(read_be64(&hash32[8]));
        m.qty_lots    = read_be64(&hash32[16]);
        m.aux_u64     = read_be64(&hash32[24]);
        return m;
    }

    constexpr void extract_ledger_checkpoint_hash(std::array<uint8_t, 32>& hash32_out) const noexcept {
        write_be64(&hash32_out[0],  order_id);
        write_be64(&hash32_out[8],  static_cast<uint64_t>(price_ticks));
        write_be64(&hash32_out[16], qty_lots);
        write_be64(&hash32_out[24], aux_u64);
    }

    static constexpr ArenaItchMessage make_market_directory(
        uint16_t                    market_id,
        uint64_t                    wal_seq,
        uint8_t                     market_kind,
        uint8_t                     sub_kind,
        uint8_t                     base_asset_id,
        uint8_t                     inst_flags,
        uint16_t                    ref_market_1,
        uint16_t                    ref_market_2,
        uint16_t                    imr_bps,
        int64_t                     mark_price_ticks,
        const std::array<char, 16>& symbol16
    ) noexcept {
        std::array<uint8_t, 16> sbytes{};
        for (std::size_t i = 0U; i < 16U; ++i) {
            sbytes[i] = static_cast<uint8_t>(symbol16[i]);
        }
        ArenaItchMessage m{};
        m.event_type  = ItchEventType::MarketDirectory;
        m.market_id   = market_id;
        m.side        = OrderSide::Bid;
        m.flags       = static_cast<uint8_t>((market_kind & 0x07U) | ((sub_kind & 0x1FU) << 3U));
        m.wal_seq     = wal_seq;
        m.order_id    = read_be64(&sbytes[0]);
        m.price_ticks = std::max<int64_t>(0LL, mark_price_ticks);
        m.qty_lots    = read_be64(&sbytes[8]);
        m.aux_u64     = (static_cast<uint64_t>(base_asset_id) << 56U) |
                        (static_cast<uint64_t>(inst_flags)    << 48U) |
                        (static_cast<uint64_t>(ref_market_1)  << 32U) |
                        (static_cast<uint64_t>(ref_market_2)  << 16U) |
                        static_cast<uint64_t>(imr_bps);
        return m;
    }

    constexpr void unpack_market_directory(
        uint8_t&               market_kind_out,
        uint8_t&               sub_kind_out,
        uint8_t&               base_asset_id_out,
        uint8_t&               inst_flags_out,
        uint16_t&              ref_market_1_out,
        uint16_t&              ref_market_2_out,
        uint16_t&              imr_bps_out,
        std::array<char, 16>&  symbol16_out
    ) const noexcept {
        market_kind_out   = static_cast<uint8_t>(flags & 0x07U);
        sub_kind_out      = static_cast<uint8_t>((flags >> 3U) & 0x1FU);
        base_asset_id_out = static_cast<uint8_t>((aux_u64 >> 56U) & 0xFFULL);
        inst_flags_out    = static_cast<uint8_t>((aux_u64 >> 48U) & 0xFFULL);
        ref_market_1_out  = static_cast<uint16_t>((aux_u64 >> 32U) & 0xFFFFULL);
        ref_market_2_out  = static_cast<uint16_t>((aux_u64 >> 16U) & 0xFFFFULL);
        imr_bps_out       = static_cast<uint16_t>(aux_u64 & 0xFFFFULL);
        std::array<uint8_t, 16> sbytes{};
        write_be64(&sbytes[0], order_id);
        write_be64(&sbytes[8], qty_lots);
        for (std::size_t i = 0U; i < 16U; ++i) {
            symbol16_out[i] = static_cast<char>(sbytes[i]);
        }
    }
};

// 16-Byte Client Subscription / Sequence Gap-Replay Request on `--itch-port`
inline constexpr uint16_t ITCH_REQ_FLAG_REPLAY_FROM_SEQ = (1U << 0U);
inline constexpr uint16_t ITCH_REQ_FLAG_FULL_SNAPSHOT   = (1U << 1U);

struct ArenaItchSubscribeReq {
    uint16_t market_id     = 0; // 0 = all markets, >0 = filter to market_id
    uint16_t req_flags     = 0; // ITCH_REQ_FLAG_REPLAY_FROM_SEQ or ITCH_REQ_FLAG_FULL_SNAPSHOT
    uint64_t from_itch_seq = 0; // Inclusive start sequence when ITCH_REQ_FLAG_REPLAY_FROM_SEQ is set

    [[nodiscard]] constexpr std::array<uint8_t, ARENA_ITCH_REQ_BYTES> pack_bytes() const noexcept {
        std::array<uint8_t, ARENA_ITCH_REQ_BYTES> out{};
        write_be32_wire(&out[0], ARENA_ITCH_REQ_MAGIC);
        write_be16_wire(&out[4], market_id);
        write_be16_wire(&out[6], req_flags);
        write_be64(&out[8],      from_itch_seq);
        return out;
    }

    static constexpr bool unpack_bytes(
        const uint8_t*         raw16,
        ArenaItchSubscribeReq& out
    ) noexcept {
        if (read_be32_wire(&raw16[0]) != ARENA_ITCH_REQ_MAGIC) {
            return false;
        }
        out.market_id     = read_be16_wire(&raw16[4]);
        out.req_flags     = read_be16_wire(&raw16[6]);
        out.from_itch_seq = read_be64(&raw16[8]);
        return true;
    }
};

// -----------------------------------------------------------------------------
// v4.7 Self-Contained Incentive & Yield Expansion Wire Frame Helpers
// -----------------------------------------------------------------------------
inline constexpr ArenaWireFrame make_config_auto_repo_wire_frame(
    uint32_t account_id,
    uint32_t epoch_marks,
    uint16_t seq_lo          = 1U,
    uint64_t seq_hi50        = 1ULL,
    uint64_t key_lo64        = 0x0123'4567'89AB'CDEFULL,
    uint64_t key_hi64        = 0xCAFE'BABE'DEAD'BEEFULL,
    uint16_t clock_market_id = 0U
) noexcept {
    ArenaHeader hdr{};
    hdr.op          = BaseOp::UpdateMarkFunding;
    hdr.flags       = ArenaFlags{TimeInForce::GTC, StpMode::CancelResting};
    hdr.market_id   = clock_market_id;
    hdr.account_id  = account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = static_cast<int64_t>(epoch_marks);
    hdr.qty_lots    = static_cast<uint64_t>(epoch_marks);
    return pack_wire_frame(
        hdr,
        static_cast<uint64_t>(epoch_marks),
        MARK_AUX1_FLAG_CONFIG_AUTO_REPO,
        seq_hi50,
        key_lo64,
        key_hi64
    );
}

inline constexpr ArenaWireFrame make_fund_market_vault_wire_frame(
    uint32_t sponsor_account_id,
    uint16_t market_id,
    uint16_t asset_id,
    uint64_t amount,
    uint32_t duration_marks,
    uint16_t maker_share_bps = 7'500U,
    uint16_t seq_lo          = 1U,
    uint64_t seq_hi50        = 1ULL,
    uint64_t key_lo64        = 0x0123'4567'89AB'CDEFULL,
    uint64_t key_hi64        = 0xCAFE'BABE'DEAD'BEEFULL
) noexcept {
    ArenaHeader hdr{};
    hdr.op          = BaseOp::UpdateMarkFunding;
    hdr.flags       = ArenaFlags{TimeInForce::GTC, StpMode::CancelResting};
    hdr.market_id   = market_id;
    hdr.account_id  = sponsor_account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = static_cast<int64_t>(maker_share_bps);
    hdr.qty_lots    = (static_cast<uint64_t>(duration_marks) << 8U) |
                      static_cast<uint64_t>(asset_id & 0xFFU);
    const uint64_t aux1 =
        MARK_AUX1_FLAG_FUND_MARKET_VAULT |
        (static_cast<uint64_t>(asset_id) << 32U);
    return pack_wire_frame(
        hdr,
        amount,
        aux1,
        seq_hi50,
        key_lo64,
        key_hi64
    );
}

inline constexpr bool unpack_fund_market_vault_wire(
    const ArenaHeader& hdr,
    uint64_t           aux_param0,
    uint64_t           aux_param1,
    uint16_t&          asset_id_out,
    uint64_t&          amount_out,
    uint32_t&          duration_marks_out,
    uint16_t&          maker_share_bps_out
) noexcept {
    if (hdr.price_ticks < 0LL || hdr.price_ticks > 10'000LL) {
        return false;
    }
    const uint16_t hi_aid = static_cast<uint16_t>((aux_param1 >> 32U) & 0xFFFFULL);
    asset_id_out        = (hi_aid != 0U) ? hi_aid : static_cast<uint16_t>(hdr.qty_lots & 0xFFULL);
    amount_out          = aux_param0;
    duration_marks_out  = static_cast<uint32_t>((hdr.qty_lots >> 8U) & 0xFFFF'FFFFULL);
    maker_share_bps_out = static_cast<uint16_t>(hdr.price_ticks);
    return true;
}

inline constexpr ArenaWireFrame make_config_payout_portfolio_wire_frame(
    uint32_t account_id,
    uint16_t primary_asset_id,
    uint16_t primary_share_bps,
    uint16_t secondary_asset_id       = 0U,
    uint16_t secondary_share_bps      = 0U,
    uint16_t tertiary_asset_id        = 0U,
    uint16_t tertiary_share_bps       = 0U,
    uint8_t  payout_mode_flags        = 0U,
    uint32_t payout_target_account_id = 0U,
    uint16_t max_margin_util_bps      = 0U,
    int64_t  max_price_ticks          = 0LL,
    uint16_t seq_lo                   = 1U,
    uint64_t seq_hi50                 = 1ULL,
    uint64_t key_lo64                 = 0x0123'4567'89AB'CDEFULL,
    uint64_t key_hi64                 = 0xCAFE'BABE'DEAD'BEEFULL
) noexcept {
    const uint64_t p_bps_14 = (primary_share_bps > 0x3FFFU) ? 0x3FFFULL : static_cast<uint64_t>(primary_share_bps);
    const uint64_t s_bps_14 = (secondary_share_bps > 0x3FFFU) ? 0x3FFFULL : static_cast<uint64_t>(secondary_share_bps);
    const bool invalid_aid  = (primary_asset_id > 0xFFU) || (secondary_asset_id > 0xFFU) || (tertiary_asset_id > 0xFFU);
    ArenaHeader hdr{};
    hdr.op          = BaseOp::UpdateMarkFunding;
    hdr.flags       = ArenaFlags{TimeInForce::GTC, StpMode::CancelResting};
    hdr.market_id   = static_cast<uint16_t>(
        ((primary_asset_id & 0xFFU) << 8U) | (secondary_asset_id & 0xFFU)
    );
    hdr.account_id  = account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = max_price_ticks;
    hdr.qty_lots    = (p_bps_14 << 22U) | (s_bps_14 << 8U) | static_cast<uint64_t>(tertiary_asset_id & 0xFFU);
    const uint64_t aux0 =
        (static_cast<uint64_t>(payout_target_account_id) << 32U) |
        (static_cast<uint64_t>(tertiary_share_bps) << 16U) |
        static_cast<uint64_t>(max_margin_util_bps);
    const uint64_t aux1 =
        MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES |
        (invalid_aid ? (1ULL << 24U) : 0ULL) |
        (static_cast<uint64_t>(payout_mode_flags) << 32U);
    return pack_wire_frame(hdr, aux0, aux1, seq_hi50, key_lo64, key_hi64);
}

inline constexpr void unpack_payout_portfolio_wire(
    const ArenaHeader& hdr,
    uint64_t           aux_param0,
    uint64_t           aux_param1,
    uint16_t&          primary_asset_id_out,
    uint16_t&          primary_share_bps_out,
    uint16_t&          secondary_asset_id_out,
    uint16_t&          secondary_share_bps_out,
    uint16_t&          tertiary_asset_id_out,
    uint16_t&          tertiary_share_bps_out,
    uint8_t&           payout_mode_flags_out,
    uint32_t&          payout_target_account_id_out,
    uint16_t&          max_margin_util_bps_out,
    int64_t&           max_price_ticks_out
) noexcept {
    primary_asset_id_out         = ((aux_param1 & (1ULL << 24U)) != 0ULL)
                                 ? static_cast<uint16_t>(0xFFFFU)
                                 : static_cast<uint16_t>((hdr.market_id >> 8U) & 0xFFU);
    secondary_asset_id_out       = static_cast<uint16_t>(hdr.market_id & 0xFFU);
    primary_share_bps_out        = static_cast<uint16_t>((hdr.qty_lots >> 22U) & 0x3FFFULL);
    secondary_share_bps_out      = static_cast<uint16_t>((hdr.qty_lots >> 8U) & 0x3FFFULL);
    tertiary_asset_id_out        = static_cast<uint16_t>(hdr.qty_lots & 0xFFULL);
    payout_target_account_id_out = static_cast<uint32_t>((aux_param0 >> 32U) & 0xFFFF'FFFFULL);
    tertiary_share_bps_out       = static_cast<uint16_t>((aux_param0 >> 16U) & 0xFFFFULL);
    max_margin_util_bps_out      = static_cast<uint16_t>(aux_param0 & 0xFFFFULL);
    payout_mode_flags_out        = static_cast<uint8_t>((aux_param1 >> 32U) & 0xFFULL);
    max_price_ticks_out          = hdr.price_ticks;
}

inline constexpr ArenaWireFrame make_config_default_incentives_wire_frame(
    uint32_t account_id,
    uint8_t  pillar_mask                 = INCENTIVE_PILLARS_ALL_ON,
    uint32_t repo_epoch_marks            = 60U,
    uint16_t two_sided_bonus_bps         = 2'500U,
    uint16_t claim_collateral_weight_bps = 9'000U,
    uint16_t seq_lo                      = 1U,
    uint64_t seq_hi50                    = 1ULL,
    uint64_t key_lo64                    = 0x0123'4567'89AB'CDEFULL,
    uint64_t key_hi64                    = 0xCAFE'BABE'DEAD'BEEFULL
) noexcept {
    ArenaHeader hdr{};
    hdr.op          = BaseOp::UpdateMarkFunding;
    hdr.flags       = ArenaFlags{TimeInForce::GTC, StpMode::CancelResting};
    hdr.market_id   = two_sided_bonus_bps;
    hdr.account_id  = account_id;
    hdr.side        = OrderSide::Bid;
    hdr.seq_lo      = seq_lo;
    hdr.price_ticks = static_cast<int64_t>(claim_collateral_weight_bps);
    hdr.qty_lots    = static_cast<uint64_t>(repo_epoch_marks);
    return pack_wire_frame(
        hdr,
        static_cast<uint64_t>(pillar_mask),
        MARK_AUX1_FLAG_DEFAULT_INCENTIVES,
        seq_hi50,
        key_lo64,
        key_hi64
    );
}

inline constexpr bool unpack_default_incentives_wire(
    const ArenaHeader& hdr,
    uint64_t           aux_param0,
    uint8_t&           pillar_mask_out,
    uint32_t&          repo_epoch_marks_out,
    uint16_t&          two_sided_bonus_bps_out,
    uint16_t&          claim_collateral_weight_bps_out
) noexcept {
    if (hdr.price_ticks < 0LL ||
        hdr.price_ticks > 9'800LL ||
        hdr.market_id > 10'000U ||
        hdr.qty_lots > 1'000'000ULL ||
        aux_param0 > 0xFFULL) {
        return false;
    }
    pillar_mask_out                 = static_cast<uint8_t>(aux_param0 & 0xFFULL);
    repo_epoch_marks_out            = static_cast<uint32_t>(hdr.qty_lots);
    two_sided_bonus_bps_out         = hdr.market_id;
    claim_collateral_weight_bps_out = static_cast<uint16_t>(hdr.price_ticks);
    return true;
}

} // namespace arena::wire
