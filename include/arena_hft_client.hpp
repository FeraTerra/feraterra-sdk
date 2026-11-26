// =============================================================================
// HEADER: include/arena_hft_client.hpp
// PROJECT: Arena Exchange v4.9 (Zero-Fee All-Incentives-Default Sovereign HFT Protocol)
// PURPOSE:
//   Standalone, header-only C++23 HFT Binary Client SDK (`namespace arena::sdk`)
//   for direct, website-less colocation / bare-metal trading against
//   `arena-server` over:
//     1. 64-byte cacheline-aligned `ArenaWireFrame` TCP (`TCP_NODELAY`),
//        deadlock-free pipelined multi-frame TCP batches, and UDP datagrams
//        (`ArenaHftWireClient`).
//     2. 64-byte cacheline-aligned `ArenaITCH` L3 tick-by-tick market-data
//        feed with deterministic L3/L2 FIFO book reconstruction and live
//        256-bit `Keccak-256` Sovereign Execution Ledger checkpoint tracking
//        (`ArenaHftBookReconstructor` & `ArenaHftItchSubscriber`).
//     3. Zero-dependency offline Sovereign WAL Ledger cryptographic verifier
//        (`verify_sovereign_wal_ledger_file` & `compute_ledger_tip_digest`).
// =============================================================================
#pragma once

#include "arena_wire.hpp"

#ifdef _WIN32
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0601)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace arena::sdk {

using Bytes32 = std::array<uint8_t, 32>;

inline constexpr uint64_t DEFAULT_DEV_KEY_LO64 = 0x0123'4567'89AB'CDEFULL;
inline constexpr uint64_t DEFAULT_DEV_KEY_HI64 = 0xCAFE'BABE'DEAD'BEEFULL;
inline constexpr uint64_t DEFAULT_SEQ_HI50     = 1ULL;

inline constexpr uint16_t         DEFAULT_WIRE_TCP_PORT    = 19100U;
inline constexpr uint16_t         DEFAULT_WIRE_UDP_PORT    = 19101U;
inline constexpr uint16_t         DEFAULT_ITCH_TCP_PORT    = 19102U;
inline constexpr uint64_t         PUBLIC_TESTNET_CHAIN_ID  = 84532ULL; // Base Sepolia
inline constexpr std::string_view PUBLIC_DOMAIN            = "feraterra.app";
inline constexpr std::string_view PUBLIC_TESTNET_HOST      = "testnet.feraterra.app";
inline constexpr std::string_view PUBLIC_TESTNET_HTTPS_URL = "https://testnet.feraterra.app";
inline constexpr std::string_view PUBLIC_TESTNET_WS_URL    = "wss://testnet.feraterra.app/ws";

// =============================================================================
// 1. Standalone Ethereum Keccak-256 & Sovereign WAL Ledger Verifier
// =============================================================================
namespace detail {

[[nodiscard]] inline constexpr uint64_t rotl64_sdk(uint64_t x, unsigned int n) noexcept {
    return (n == 0U) ? x : ((x << n) | (x >> (64U - n)));
}

inline constexpr std::array<uint64_t, 24> kKeccakRC{{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
}};

inline constexpr std::array<unsigned int, 24> kKeccakRot{{
    1U,  3U,  6U, 10U, 15U, 21U, 28U, 36U, 45U, 55U,  2U, 14U,
    27U, 41U, 56U, 8U, 25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
}};

inline constexpr std::array<std::size_t, 24> kKeccakPi{{
    10U, 7U,  11U, 17U, 18U, 3U, 5U,  16U, 8U,  21U, 24U, 4U,
    15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U,  6U,  1U
}};

inline void keccak_f1600(std::array<uint64_t, 25>& st) noexcept {
    for (std::size_t round = 0U; round < 24U; ++round) {
        std::array<uint64_t, 5> bc{};
        for (std::size_t i = 0U; i < 5U; ++i) {
            bc[i] = st[i] ^ st[i + 5U] ^ st[i + 10U] ^ st[i + 15U] ^ st[i + 20U];
        }
        for (std::size_t i = 0U; i < 5U; ++i) {
            const uint64_t t = bc[(i + 4U) % 5U] ^ rotl64_sdk(bc[(i + 1U) % 5U], 1U);
            for (std::size_t j = 0U; j < 25U; j += 5U) {
                st[j + i] ^= t;
            }
        }
        uint64_t t = st[1];
        for (std::size_t i = 0U; i < 24U; ++i) {
            const std::size_t j = kKeccakPi[i];
            const uint64_t tmp  = st[j];
            st[j] = rotl64_sdk(t, kKeccakRot[i]);
            t     = tmp;
        }
        for (std::size_t j = 0U; j < 25U; j += 5U) {
            for (std::size_t i = 0U; i < 5U; ++i) {
                bc[i] = st[j + i];
            }
            for (std::size_t i = 0U; i < 5U; ++i) {
                st[j + i] ^= (~bc[(i + 1U) % 5U]) & bc[(i + 2U) % 5U];
            }
        }
        st[0] ^= kKeccakRC[round];
    }
}

inline void keccak_xor_block136(std::array<uint64_t, 25>& st, const uint8_t block[136]) noexcept {
    for (std::size_t i = 0U; i < 17U; ++i) {
        uint64_t lane = 0ULL;
        for (std::size_t b = 0U; b < 8U; ++b) {
            lane |= static_cast<uint64_t>(block[i * 8U + b]) << (b * 8U);
        }
        st[i] ^= lane;
    }
    keccak_f1600(st);
}

class Keccak256 {
public:
    void update(const uint8_t* data, std::size_t len) noexcept {
        std::size_t off = 0U;
        if (buf_len_ > 0U) {
            while (off < len && buf_len_ < 136U) {
                buf_[buf_len_++] = data[off++];
            }
            if (buf_len_ == 136U) {
                keccak_xor_block136(state_, buf_.data());
                buf_len_ = 0U;
            }
        }
        while (off + 136U <= len) {
            keccak_xor_block136(state_, data + off);
            off += 136U;
        }
        while (off < len) {
            buf_[buf_len_++] = data[off++];
        }
    }

    void update(std::string_view sv) noexcept {
        update(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
    }

    [[nodiscard]] Bytes32 finalize() noexcept {
        return finalize_exact(buf_len_);
    }

    [[nodiscard]] Bytes32 finalize_exact(std::size_t exact_buf_len) noexcept {
        for (std::size_t i = exact_buf_len; i < 136U; ++i) {
            buf_[i] = 0U;
        }
        buf_[exact_buf_len] ^= 0x01U;
        buf_[135U]          ^= 0x80U;
        keccak_xor_block136(state_, buf_.data());

        Bytes32 out{};
        for (std::size_t i = 0U; i < 4U; ++i) {
            const uint64_t lane = state_[i];
            for (std::size_t b = 0U; b < 8U; ++b) {
                out[i * 8U + b] = static_cast<uint8_t>((lane >> (b * 8U)) & 0xFFULL);
            }
        }
        return out;
    }

    [[nodiscard]] std::size_t buffered_len() const noexcept { return buf_len_; }

private:
    std::array<uint64_t, 25> state_{};
    std::array<uint8_t, 136> buf_{};
    std::size_t              buf_len_{0U};
};

#ifdef _WIN32
using SdkSocketHandle = SOCKET;
inline constexpr SdkSocketHandle SDK_INVALID_SOCK = INVALID_SOCKET;

struct SdkWinsockGuard {
    SdkWinsockGuard() noexcept {
        WSADATA wsa{};
        (void)::WSAStartup(MAKEWORD(2, 2), &wsa);
    }
};

inline void ensure_winsock_initialized() noexcept {
    static SdkWinsockGuard guard{};
    (void)guard;
}
#else
using SdkSocketHandle = int;
inline constexpr SdkSocketHandle SDK_INVALID_SOCK = -1;
inline void ensure_winsock_initialized() noexcept {}
#endif

inline void sdk_close_socket(SdkSocketHandle s) noexcept {
    if (s == SDK_INVALID_SOCK) return;
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
}

inline bool sdk_set_nonblocking(SdkSocketHandle s, bool nonblocking) noexcept {
    if (s == SDK_INVALID_SOCK) return false;
#ifdef _WIN32
    u_long mode = nonblocking ? 1UL : 0UL;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    const int next = nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return ::fcntl(s, F_SETFL, next) == 0;
#endif
}

#if !defined(_WIN32) && defined(MSG_NOSIGNAL)
inline constexpr int SDK_SEND_FLAGS = MSG_NOSIGNAL;
#else
inline constexpr int SDK_SEND_FLAGS = 0;
#endif

inline bool sdk_is_eintr() noexcept {
#ifdef _WIN32
    return ::WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

inline bool sdk_would_block() noexcept {
#ifdef _WIN32
    const int err = ::WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EINTR;
#endif
}

inline bool sdk_recv_timed_out() noexcept {
#ifdef _WIN32
    const int err = ::WSAGetLastError();
    return err == WSAETIMEDOUT || err == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

inline void sdk_enable_tcp_nodelay(SdkSocketHandle s) noexcept {
    const int one = 1;
#ifdef _WIN32
    (void)::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
#else
    (void)::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#endif
}

inline void sdk_apply_io_timeout(SdkSocketHandle s, uint32_t timeout_ms) noexcept {
#ifdef _WIN32
    const DWORD tv = static_cast<DWORD>(timeout_ms);
    (void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    (void)::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{};
    tv.tv_sec  = static_cast<long>(timeout_ms / 1000U);
    tv.tv_usec = static_cast<long>((timeout_ms % 1000U) * 1000U);
    (void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

[[nodiscard]] inline uint64_t sdk_steady_ms() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

[[nodiscard]] inline bool sdk_connect_in_progress() noexcept {
#ifdef _WIN32
    const int err = ::WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY || err == WSAEINTR;
#else
    return errno == EINPROGRESS || errno == EALREADY || errno == EINTR;
#endif
}

[[nodiscard]] inline bool sdk_connect_with_timeout(
    SdkSocketHandle    s,
    const sockaddr_in& addr,
    uint32_t           timeout_ms
) noexcept {
    if (s == SDK_INVALID_SOCK) return false;
    if (!sdk_set_nonblocking(s, true)) {
        return ::connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0;
    }
    const int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        (void)sdk_set_nonblocking(s, false);
        return true;
    }
    if (!sdk_connect_in_progress()) {
        (void)sdk_set_nonblocking(s, false);
        return false;
    }

    const uint64_t deadline = sdk_steady_ms() + static_cast<uint64_t>(std::max<uint32_t>(timeout_ms, 1U));
    bool connected = false;
    for (;;) {
        const uint64_t now = sdk_steady_ms();
        if (now >= deadline) {
            break;
        }
        const int slice_ms = static_cast<int>(std::min<uint64_t>(deadline - now, 50ULL));
#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd     = s;
        pfd.events = POLLWRNORM;
        const int pr = ::WSAPoll(&pfd, 1UL, slice_ms);
        if (pr < 0) {
            if (sdk_is_eintr()) continue;
            break;
        }
        if (pr > 0 && (pfd.revents & (POLLWRNORM | POLLERR | POLLHUP)) != 0) {
            int so_err = 0;
            int optlen = static_cast<int>(sizeof(so_err));
            if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &optlen) == 0 &&
                so_err == 0 && (pfd.revents & (POLLERR | POLLHUP)) == 0) {
                connected = true;
            }
            break;
        }
#else
        pollfd pfd{};
        pfd.fd     = s;
        pfd.events = POLLOUT;
        const int pr = ::poll(&pfd, 1U, slice_ms);
        if (pr < 0) {
            if (sdk_is_eintr()) continue;
            break;
        }
        if (pr > 0 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
            int       so_err = 0;
            socklen_t optlen = static_cast<socklen_t>(sizeof(so_err));
            if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &optlen) == 0 && so_err == 0) {
                connected = true;
            }
            break;
        }
#endif
    }
    (void)sdk_set_nonblocking(s, false);
    return connected;
}

[[nodiscard]] inline bool sdk_resolve_ipv4_host(const char* host, in_addr& out_addr) noexcept {
    if (host == nullptr || host[0] == '\0') {
        return false;
    }
    if (::inet_pton(AF_INET, host, &out_addr) == 1) {
        return true;
    }
    ensure_winsock_initialized();
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host, nullptr, &hints, &res) != 0 || res == nullptr) {
        return false;
    }
    bool resolved = false;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET && p->ai_addr != nullptr &&
            p->ai_addrlen >= sizeof(sockaddr_in)) {
            out_addr = reinterpret_cast<const sockaddr_in*>(p->ai_addr)->sin_addr;
            resolved = true;
            break;
        }
    }
    ::freeaddrinfo(res);
    return resolved;
}

[[nodiscard]] inline uint64_t sdk_csprng_u64_nonzero() noexcept {
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint64_t v = 0ULL;
#ifdef _WIN32
        if (::BCryptGenRandom(
                nullptr,
                reinterpret_cast<PUCHAR>(&v),
                static_cast<ULONG>(sizeof(v)),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            ) != 0) {
            return 0ULL;
        }
#else
        const int fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            return 0ULL;
        }
        uint8_t* dst = reinterpret_cast<uint8_t*>(&v);
        std::size_t off = 0U;
        while (off < sizeof(v)) {
            const ssize_t got = ::read(fd, dst + off, sizeof(v) - off);
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ::close(fd);
                return 0ULL;
            }
            if (got == 0) {
                ::close(fd);
                return 0ULL;
            }
            off += static_cast<std::size_t>(got);
        }
        ::close(fd);
#endif
        if (v != 0ULL) {
            return v;
        }
    }
    return 0ULL;
}

} // namespace detail

[[nodiscard]] inline Bytes32 keccak256_bytes(const uint8_t* data, std::size_t len) noexcept {
    detail::Keccak256 k;
    k.update(data, len);
    return k.finalize_exact(k.buffered_len());
}

[[nodiscard]] inline Bytes32 keccak256_str(std::string_view sv) noexcept {
    return keccak256_bytes(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
}

[[nodiscard]] inline std::string to_hex_0x(const Bytes32& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(66U);
    out.push_back('0');
    out.push_back('x');
    for (const uint8_t v : b) {
        out.push_back(kHex[(v >> 4U) & 0xFU]);
        out.push_back(kHex[v & 0xFU]);
    }
    return out;
}

[[nodiscard]] inline Bytes32 sovereign_ledger_genesis_hash() noexcept {
    return keccak256_str("ARENA_SOVEREIGN_LEDGER_GENESIS_V2_0");
}

[[nodiscard]] inline Bytes32 compute_ledger_tip_digest(
    uint64_t                       wal_seq,
    const Bytes32&                 ledger_chain_hash,
    const Bytes32&                 state_root,
    uint64_t                       chain_id            = 0ULL,
    const std::array<uint8_t, 20>* clearinghouse_bytes = nullptr
) noexcept {
    detail::Keccak256 kh;
    kh.update("ARENA_LEDGER_TIP_V2_1");
    std::array<uint8_t, 8> b64{};
    arena::wire::write_be64(b64.data(), chain_id);
    kh.update(b64.data(), 8U);
    std::array<uint8_t, 20> ch{};
    if (clearinghouse_bytes != nullptr) {
        ch = *clearinghouse_bytes;
    }
    kh.update(ch.data(), 20U);
    arena::wire::write_be64(b64.data(), wal_seq);
    kh.update(b64.data(), 8U);
    kh.update(ledger_chain_hash.data(), 32U);
    kh.update(state_root.data(), 32U);
    return kh.finalize_exact(kh.buffered_len());
}

struct SovereignWalVerifyResult {
    bool        ok{false};
    bool        snapshot_anchored{false};
    uint64_t    first_wal_seq{0};
    uint64_t    records_verified{0};
    uint64_t    final_wal_seq{0};
    std::size_t torn_tail_bytes{0};
    Bytes32     final_chain_hash{};
    std::string error{};
};

[[nodiscard]] inline bool peek_sovereign_snapshot_anchor(
    const std::string&      snap_path,
    uint64_t&               snap_wal_seq_out,
    std::array<uint8_t, 64>& snap_last_rec_out,
    Bytes32&                chain_hash_out
) noexcept {
    if (snap_path.empty()) {
        return false;
    }
    std::FILE* sfp = std::fopen(snap_path.c_str(), "rb");
    if (sfp == nullptr) {
        return false;
    }
#ifdef _WIN32
    if (_fseeki64(sfp, 0, SEEK_END) != 0) {
        std::fclose(sfp);
        return false;
    }
    const __int64 snap_len = _ftelli64(sfp);
    (void)_fseeki64(sfp, 0, SEEK_SET);
#else
    if (::fseeko(sfp, 0, SEEK_END) != 0) {
        std::fclose(sfp);
        return false;
    }
    const off_t snap_len = ::ftello(sfp);
    (void)::fseeko(sfp, 0, SEEK_SET);
#endif
    constexpr uint64_t kHeaderBytes = 8ULL + 4ULL + 8ULL + 32ULL + 32ULL + 64ULL; // 148
    constexpr uint64_t kMaxSnapBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    if (snap_len <= 0 ||
        static_cast<uint64_t>(snap_len) < (kHeaderBytes + 32ULL) ||
        static_cast<uint64_t>(snap_len) > kMaxSnapBytes) {
        std::fclose(sfp);
        return false;
    }
    std::array<uint8_t, kHeaderBytes> hdr{};
    if (std::fread(hdr.data(), 1U, kHeaderBytes, sfp) != kHeaderBytes) {
        std::fclose(sfp);
        return false;
    }
    uint32_t snap_ver = 0U;
    uint64_t snap_seq = 0ULL;
    std::memcpy(&snap_ver, hdr.data() + 8U, sizeof(snap_ver));
    std::memcpy(&snap_seq, hdr.data() + 12U, sizeof(snap_seq));
    if (std::memcmp(hdr.data(), "ARENASNP", 8U) != 0 ||
        (snap_ver < 44U || snap_ver > 51U) ||
        snap_seq == 0ULL) {
        std::fclose(sfp);
        return false;
    }
    detail::Keccak256 kh;
    kh.update(hdr.data(), kHeaderBytes);
    uint64_t rem = static_cast<uint64_t>(snap_len) - kHeaderBytes - 32ULL;
    std::array<uint8_t, 4096U> chunk{};
    while (rem > 0ULL) {
        const std::size_t want = static_cast<std::size_t>(std::min<uint64_t>(rem, chunk.size()));
        if (std::fread(chunk.data(), 1U, want, sfp) != want) {
            std::fclose(sfp);
            return false;
        }
        kh.update(chunk.data(), want);
        rem -= static_cast<uint64_t>(want);
    }
    std::array<uint8_t, 32U> trailing{};
    const bool got_trail = (std::fread(trailing.data(), 1U, 32U, sfp) == 32U);
    std::fclose(sfp);
    if (!got_trail) {
        return false;
    }
    const Bytes32 digest = kh.finalize_exact(kh.buffered_len());
    if (std::memcmp(digest.data(), trailing.data(), 32U) != 0) {
        return false;
    }
    snap_wal_seq_out = snap_seq;
    std::memcpy(chain_hash_out.data(), hdr.data() + 20U, 32U);
    std::memcpy(snap_last_rec_out.data(), hdr.data() + 84U, 64U);
    return true;
}

[[nodiscard]] inline bool verify_sovereign_snapshot_anchor(
    const std::string& snap_path,
    uint64_t           expected_wal_seq,
    const uint8_t*     expected_rec0_bytes,
    Bytes32&           chain_hash_out
) noexcept {
    if (expected_rec0_bytes == nullptr || expected_wal_seq == 0ULL) {
        return false;
    }
    uint64_t snap_seq = 0ULL;
    std::array<uint8_t, 64> snap_rec{};
    Bytes32 ch{};
    if (!peek_sovereign_snapshot_anchor(snap_path, snap_seq, snap_rec, ch) ||
        snap_seq != expected_wal_seq ||
        std::memcmp(snap_rec.data(), expected_rec0_bytes, 64U) != 0) {
        return false;
    }
    chain_hash_out = ch;
    return true;
}

[[nodiscard]] inline SovereignWalVerifyResult verify_sovereign_wal_ledger_file(const std::string& wal_path) {
    SovereignWalVerifyResult res{};
    res.final_chain_hash = sovereign_ledger_genesis_hash();

    std::FILE* fp = std::fopen(wal_path.c_str(), "rb");
    if (fp == nullptr) {
        res.error = "cannot_open_wal_file";
        return res;
    }

#ifdef _WIN32
    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        res.error = "wal_fseek_failed";
        return res;
    }
    const __int64 file_len = _ftelli64(fp);
    if (file_len < 0) {
        std::fclose(fp);
        res.error = "wal_ftell_failed";
        return res;
    }
    (void)_fseeki64(fp, 0, SEEK_SET);
#else
    if (::fseeko(fp, 0, SEEK_END) != 0) {
        std::fclose(fp);
        res.error = "wal_fseek_failed";
        return res;
    }
    const off_t file_len = ::ftello(fp);
    if (file_len < 0) {
        std::fclose(fp);
        res.error = "wal_ftell_failed";
        return res;
    }
    (void)::fseeko(fp, 0, SEEK_SET);
#endif

    res.torn_tail_bytes = static_cast<std::size_t>(static_cast<uint64_t>(file_len) % 64ULL);
    uint64_t full_records = static_cast<uint64_t>(file_len) / 64ULL;
    if (res.torn_tail_bytes == 0U) {
        while (full_records > 0ULL) {
            const uint64_t chk_off = (full_records - 1ULL) * 64ULL;
#if defined(_WIN32)
            if (_fseeki64(fp, static_cast<__int64>(chk_off), SEEK_SET) != 0) {
#else
            if (::fseeko(fp, static_cast<off_t>(chk_off), SEEK_SET) != 0) {
#endif
                std::fclose(fp);
                res.error = "wal_fseek_failed";
                return res;
            }
            std::array<uint8_t, 64> tail_blk{};
            if (std::fread(tail_blk.data(), 1U, 64U, fp) != 64U) {
                std::fclose(fp);
                res.error = "wal_short_read";
                return res;
            }
            bool all_z = true;
            for (const uint8_t b : tail_blk) {
                if (b != 0U) {
                    all_z = false;
                    break;
                }
            }
            if (!all_z) {
                break;
            }
            --full_records;
            res.torn_tail_bytes += 64U;
        }
#if defined(_WIN32)
        (void)_fseeki64(fp, 0, SEEK_SET);
#else
        (void)::fseeko(fp, 0, SEEK_SET);
#endif
    }

    constexpr std::size_t kIoChunkRecords = 64U; // 4 KiB stack read buffer
    std::array<uint8_t, kIoChunkRecords * 64U> io_buf{};
    std::size_t io_pos = 0U;
    std::size_t io_len = 0U;

    // 16-record bounded circular lookahead window for multi-leg basket (<=16 legs)
    // and 2-record CreateMarket (op 13 -> 14) atomic tail verification.
    std::array<std::array<uint8_t, 64>, 16> win{};
    std::size_t win_head    = 0U;
    std::size_t win_cnt     = 0U;
    bool        corrupt_or_bad = false;
    bool        tail_broken    = false;
    uint64_t    uncommitted_valid_records = 0ULL;

    auto commit_single_record = [&](const std::array<uint8_t, 64>& rec) noexcept {
        detail::Keccak256 kh;
        kh.update(res.final_chain_hash.data(), 32U);
        kh.update(rec.data(), 64U);
        res.final_chain_hash = kh.finalize_exact(kh.buffered_len());
        res.final_wal_seq    = arena::wire::read_be64(&rec[8]);
        ++res.records_verified;
    };

    auto is_valid_wal_basket_leg = [](const std::array<uint8_t, 64>& rec, uint32_t expected_account_id) noexcept -> bool {
        if (rec[6] != 5U ||
            arena::wire::read_be32_wire(&rec[16]) != expected_account_id ||
            arena::wire::read_be16_wire(&rec[20]) == 0U ||
            arena::wire::read_be64(&rec[40]) == 0ULL) {
            return false;
        }
        const uint8_t tif_u = static_cast<uint8_t>((rec[7] >> 1U) & 0x3U);
        return tif_u == static_cast<uint8_t>(arena::wire::TimeInForce::FOK);
    };

    auto drain_ready_window = [&]() noexcept {
        while (win_cnt > 0U && !tail_broken && !corrupt_or_bad) {
            const auto& r0     = win[win_head & 15U];
            const uint8_t op0  = r0[6];
            const uint8_t fl0  = r0[7];
            if (op0 == 5U && (fl0 & 0x80U) != 0U) {
                const uint32_t r0_acct = arena::wire::read_be32_wire(&r0[16]);
                if (!is_valid_wal_basket_leg(r0, r0_acct)) {
                    res.error      = "wal_invalid_basket_leg";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                std::size_t k = 1U;
                bool bad_leg  = false;
                while (k < win_cnt &&
                       win[(win_head + k) & 15U][6] == 5U &&
                       (win[(win_head + k) & 15U][7] & 0x80U) != 0U &&
                       k < 15U) {
                    if (!is_valid_wal_basket_leg(win[(win_head + k) & 15U], r0_acct)) {
                        bad_leg = true;
                        break;
                    }
                    ++k;
                }
                if (bad_leg) {
                    res.error      = "wal_invalid_basket_leg";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                if (k >= win_cnt) {
                    break; // Need more lookahead records (win_cnt <= 15)
                }
                const auto& rk = win[(win_head + k) & 15U];
                if (rk[6] != 5U || (rk[7] & 0x80U) != 0U ||
                    !is_valid_wal_basket_leg(rk, r0_acct) || (k + 1U) > 16U) {
                    res.error      = "wal_invalid_basket_group";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                const std::size_t group_len = k + 1U;
                for (std::size_t g = 0U; g < group_len; ++g) {
                    commit_single_record(win[(win_head + g) & 15U]);
                }
                win_head += group_len;
                win_cnt  -= group_len;
            } else if (op0 == 13U) {
                if (win_cnt < 2U) {
                    break; // Need Part2 lookahead record
                }
                const auto& r1 = win[(win_head + 1U) & 15U];
                if (r1[6] != 14U) {
                    tail_broken = true;
                    uncommitted_valid_records += win_cnt;
                    win_cnt = 0U;
                    break;
                }
                commit_single_record(r0);
                commit_single_record(r1);
                win_head += 2U;
                win_cnt  -= 2U;
            } else if (op0 == 11U && (fl0 & 0x0CU) != 0U) {
                if ((fl0 & 0x04U) == 0U) {
                    res.error      = "wal_orphan_override_root_p2";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                if (win_cnt < 2U) {
                    break; // Need P2 lookahead record
                }
                const auto& r1 = win[(win_head + 1U) & 15U];
                if (r1[6] != 11U || (r1[7] & 0x08U) == 0U ||
                    arena::wire::read_be64(&r1[24]) != arena::wire::read_be64(&r0[24]) ||
                    arena::wire::read_be64(&r1[40]) != arena::wire::read_be64(&r0[40])) {
                    res.error      = "wal_mismatched_override_root_pair";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                commit_single_record(r0);
                commit_single_record(r1);
                win_head += 2U;
                win_cnt  -= 2U;
            } else if (op0 == 20U) {
                if (win_cnt < 2U) {
                    break; // Need companion NewOrder lookahead record
                }
                const auto& r1 = win[(win_head + 1U) & 15U];
                if (arena::wire::read_be16_wire(&r0[22]) > arena::wire::MAX_PRIORITY_FEE_PPM ||
                    r1[6] != 5U || (r1[7] & 0x80U) != 0U ||
                    arena::wire::read_be32_wire(&r1[16]) != arena::wire::read_be32_wire(&r0[16]) ||
                    arena::wire::read_be16_wire(&r1[20]) != arena::wire::read_be16_wire(&r0[20]) ||
                    arena::wire::read_be64(&r1[24]) != arena::wire::read_be64(&r0[24])) {
                    res.error      = "wal_mismatched_order_tag_ext_pair";
                    corrupt_or_bad = true;
                    win_cnt        = 0U;
                    break;
                }
                commit_single_record(r0);
                commit_single_record(r1);
                win_head += 2U;
                win_cnt  -= 2U;
            } else {
                commit_single_record(r0);
                ++win_head;
                --win_cnt;
            }
        }
    };

    uint64_t                expected_seq        = 1ULL;
    bool                    awaiting_snap_anchor = false;
    uint64_t                snap_anchor_seq      = 0ULL;
    std::array<uint8_t, 64> snap_anchor_rec{};
    Bytes32                 snap_anchor_chain{};
    for (uint64_t idx = 0ULL; idx < full_records; ++idx) {
        if (io_pos + 64U > io_len) {
            if (io_pos < io_len) {
                std::memmove(io_buf.data(), io_buf.data() + io_pos, io_len - io_pos);
                io_len -= io_pos;
            } else {
                io_len = 0U;
            }
            io_pos = 0U;
            const uint64_t rem_recs = full_records - idx;
            const std::size_t max_bytes_needed = static_cast<std::size_t>(
                std::min<uint64_t>(rem_recs * 64ULL, static_cast<uint64_t>(io_buf.size()))
            );
            if (io_len < max_bytes_needed) {
                const std::size_t want = max_bytes_needed - io_len;
                const std::size_t got  = std::fread(io_buf.data() + io_len, 1U, want, fp);
                io_len += got;
            }
            if (io_len < 64U) {
                res.error      = "wal_short_read";
                corrupt_or_bad = true;
                break;
            }
        }

        const uint8_t* rec_ptr = io_buf.data() + io_pos;
        io_pos += 64U;

        // Verify magic "AWAL" (0x4157414C), format version 1, and SipHash-2-4 CRC64
        if (arena::wire::read_be32_wire(&rec_ptr[0]) != 0x4157414CU ||
            arena::wire::read_be16_wire(&rec_ptr[4]) != 1U) {
            res.error      = "wal_bad_magic_or_version";
            corrupt_or_bad = true;
            break;
        }
        constexpr uint64_t k0 = 0x4152'454E'4157'414CULL;
        constexpr uint64_t k1 = 0x5631'5F43'484B'534DULL;
        uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
        uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
        uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
        uint64_t v3 = k1 ^ 0x7465646279746573ULL;
        for (std::size_t off = 0U; off < 56U; off += 8U) {
            const uint64_t m = arena::wire::read_be64(&rec_ptr[off]);
            v3 ^= m;
            arena::wire::sip_round(v0, v1, v2, v3);
            arena::wire::sip_round(v0, v1, v2, v3);
            v0 ^= m;
        }
        constexpr uint64_t len_b = (56ULL << 56U);
        v3 ^= len_b;
        arena::wire::sip_round(v0, v1, v2, v3);
        arena::wire::sip_round(v0, v1, v2, v3);
        v0 ^= len_b;
        v2 ^= 0xFFULL;
        arena::wire::sip_round(v0, v1, v2, v3);
        arena::wire::sip_round(v0, v1, v2, v3);
        arena::wire::sip_round(v0, v1, v2, v3);
        arena::wire::sip_round(v0, v1, v2, v3);
        const uint64_t expected_chk = v0 ^ v1 ^ v2 ^ v3;
        const uint64_t actual_chk   = arena::wire::read_be64(&rec_ptr[56]);
        if (expected_chk != actual_chk) {
            res.error      = "wal_checksum_mismatch";
            corrupt_or_bad = true;
            break;
        }
        const uint64_t rec_seq = arena::wire::read_be64(&rec_ptr[8]);
        if (idx == 0ULL) {
            if (rec_seq == 0ULL || rec_seq == std::numeric_limits<uint64_t>::max()) {
                res.error      = "non_monotonic_wal_seq";
                corrupt_or_bad = true;
                break;
            }
            res.first_wal_seq = rec_seq;
            expected_seq      = rec_seq + 1ULL;
            if (rec_seq > 1ULL) {
                if (!peek_sovereign_snapshot_anchor(
                        wal_path + ".snap", snap_anchor_seq, snap_anchor_rec, snap_anchor_chain) ||
                    snap_anchor_seq < rec_seq) {
                    res.error      = "missing_or_invalid_snapshot_anchor";
                    corrupt_or_bad = true;
                    break;
                }
                if (rec_seq == snap_anchor_seq) {
                    if (std::memcmp(snap_anchor_rec.data(), rec_ptr, 64U) != 0) {
                        res.error      = "missing_or_invalid_snapshot_anchor";
                        corrupt_or_bad = true;
                        break;
                    }
                    res.snapshot_anchored = true;
                    res.final_chain_hash  = snap_anchor_chain;
                    res.final_wal_seq     = rec_seq;
                    res.records_verified  = 1ULL;
                } else {
                    awaiting_snap_anchor = true;
                }
                continue;
            }
        } else {
            if (rec_seq != expected_seq || rec_seq == std::numeric_limits<uint64_t>::max()) {
                res.error      = "non_monotonic_wal_seq";
                corrupt_or_bad = true;
                break;
            }
            ++expected_seq;
            if (awaiting_snap_anchor) {
                if (rec_seq < snap_anchor_seq) {
                    continue;
                }
                if (rec_seq == snap_anchor_seq) {
                    if (std::memcmp(snap_anchor_rec.data(), rec_ptr, 64U) != 0) {
                        res.error      = "missing_or_invalid_snapshot_anchor";
                        corrupt_or_bad = true;
                        break;
                    }
                    awaiting_snap_anchor  = false;
                    res.snapshot_anchored = true;
                    res.final_chain_hash  = snap_anchor_chain;
                    res.final_wal_seq     = snap_anchor_seq;
                    res.records_verified  = (snap_anchor_seq - res.first_wal_seq) + 1ULL;
                    continue;
                }
            }
        }

        if (tail_broken) {
            ++uncommitted_valid_records;
        } else {
            auto& dst = win[(win_head + win_cnt) & 15U];
            std::memcpy(dst.data(), rec_ptr, 64U);
            ++win_cnt;
            drain_ready_window();
            if (corrupt_or_bad) {
                break;
            }
        }
    }
    std::fclose(fp);

    if (win_cnt > 0U) {
        // Any records still waiting in the lookahead window at EOF (or pre-corruption)
        // belong to an uncommitted trailing multi-leg basket/spread or CreateMarket pair.
        uncommitted_valid_records += win_cnt;
        win_cnt = 0U;
    }
    res.torn_tail_bytes += static_cast<std::size_t>(uncommitted_valid_records * 64ULL);

    if (awaiting_snap_anchor && !corrupt_or_bad) {
        res.error      = "missing_or_invalid_snapshot_anchor";
        corrupt_or_bad = true;
    }
    if (!corrupt_or_bad && res.torn_tail_bytes != 0U) {
        res.error = "wal_torn_tail_bytes";
    }
    res.ok = !corrupt_or_bad && (res.torn_tail_bytes == 0U);
    return res;
}

// =============================================================================
// 2. `ArenaHftWireClient` — 64-Byte Binary TCP (`TCP_NODELAY`), Batch & UDP SDK
// =============================================================================
inline constexpr int64_t  MIN_WIRE_PRICE_TICKS_48 = -140'737'488'355'328LL;
inline constexpr int64_t  MAX_WIRE_PRICE_TICKS_48 =  140'737'488'355'327LL;
inline constexpr uint32_t MAX_WIRE_ACCOUNT_ID_24  =  0x00FF'FFFFU;

[[nodiscard]] inline constexpr bool is_valid_wire_price_ticks_48(int64_t price_ticks) noexcept {
    return price_ticks >= MIN_WIRE_PRICE_TICKS_48 && price_ticks <= MAX_WIRE_PRICE_TICKS_48;
}

[[nodiscard]] inline constexpr bool is_valid_wire_account_id_24(uint32_t account_id) noexcept {
    return account_id <= MAX_WIRE_ACCOUNT_ID_24;
}

class ArenaHftWireClient {
public:
    static constexpr int64_t  MIN_PRICE_TICKS_48 = MIN_WIRE_PRICE_TICKS_48;
    static constexpr int64_t  MAX_PRICE_TICKS_48 = MAX_WIRE_PRICE_TICKS_48;
    static constexpr uint32_t MAX_ACCOUNT_ID_24  = MAX_WIRE_ACCOUNT_ID_24;

    [[nodiscard]] static constexpr bool is_valid_price_ticks(int64_t price_ticks) noexcept {
        return is_valid_wire_price_ticks_48(price_ticks);
    }

    [[nodiscard]] static constexpr bool is_valid_account_id(uint32_t account_id) noexcept {
        return is_valid_wire_account_id_24(account_id);
    }

    [[nodiscard]] static constexpr bool is_valid_frame(const arena::wire::ArenaWireFrame& f) noexcept {
        return f.bytes[24] == 0x01U && f.bytes[62] == 0xA1U && f.bytes[63] == 0xE0U;
    }

    [[nodiscard]] static constexpr bool is_non_mutating_op(arena::wire::BaseOp op) noexcept {
        return op == arena::wire::BaseOp::Heartbeat ||
               op == arena::wire::BaseOp::QueryBookBbo ||
               op == arena::wire::BaseOp::QueryAccount ||
               op == arena::wire::BaseOp::SetCancelOnDisconnect;
    }

    ArenaHftWireClient(
        uint32_t account_id = 1U,
        uint64_t key_lo64   = DEFAULT_DEV_KEY_LO64,
        uint64_t key_hi64   = DEFAULT_DEV_KEY_HI64,
        uint64_t seq_hi50   = DEFAULT_SEQ_HI50,
        uint16_t init_seq14 = 1U
    ) noexcept
        : account_id_(account_id)
        , signer_account_id_(account_id)
        , key_lo64_(key_lo64)
        , key_hi64_(key_hi64)
        , seq_hi50_(seq_hi50 & ((1ULL << 50U) - 1ULL))
        , default_init_seq_hi50_(seq_hi50 & ((1ULL << 50U) - 1ULL))
        , default_init_seq_lo_(static_cast<uint16_t>(init_seq14 & 0x3FFFU))
    {
        const uint32_t init_acct                  = seq_bucket_account(account_id_);
        next_seq_by_account_[init_acct]           = default_init_seq_lo_;
        seq_hi50_by_account_[init_acct]           = default_init_seq_hi50_;
        pending_hi50_wrap_by_account_[init_acct]  = false;
        cred_key_by_account_[init_acct]           = {key_lo64_, key_hi64_};
        saved_cred_seq_state_[{init_acct, key_lo64_, key_hi64_}] =
            SavedCredSeqState{default_init_seq_hi50_, default_init_seq_lo_, false};
        detail::ensure_winsock_initialized();
    }

    ~ArenaHftWireClient() noexcept {
        disconnect();
    }

    ArenaHftWireClient(const ArenaHftWireClient&)            = delete;
    ArenaHftWireClient& operator=(const ArenaHftWireClient&) = delete;

    void set_auto_retry_mutating_on_resync(bool enable) noexcept {
        auto_retry_mutating_on_resync_ = enable;
    }

    [[nodiscard]] bool auto_retry_mutating_on_resync() const noexcept {
        return auto_retry_mutating_on_resync_;
    }

    [[nodiscard]] bool has_ambiguous_disconnect(uint32_t account_id = 0U) const noexcept {
        const uint32_t eff_acct = (account_id != 0U) ? account_id : account_id_;
        const uint32_t seq_acct = seq_bucket_account(eff_acct);
        const auto     it       = ambiguous_disconnect_by_account_.find(seq_acct);
        return it != ambiguous_disconnect_by_account_.end() && it->second;
    }

    void clear_ambiguous_disconnect(uint32_t account_id = 0U) noexcept {
        if (account_id == 0U) {
            ambiguous_disconnect_by_account_.clear();
            return;
        }
        ambiguous_disconnect_by_account_.erase(seq_bucket_account(account_id));
    }

    void set_account_id(uint32_t account_id) noexcept {
        account_id_             = account_id;
        const uint32_t seq_acct = seq_bucket_account(account_id_);
        next_seq_by_account_.try_emplace(seq_acct, default_init_seq_lo_);
        auto [it_h, _] = seq_hi50_by_account_.try_emplace(seq_acct, default_init_seq_hi50_);
        seq_hi50_      = it_h->second;
    }

    void set_credentials(uint32_t account_id, uint64_t key_lo64, uint64_t key_hi64) noexcept {
        {
            const uint32_t prev_acct = seq_bucket_account(account_id_);
            const auto     prev_kit  = cred_key_by_account_.find(prev_acct);
            if (prev_kit != cred_key_by_account_.end()) {
                const uint64_t prev_hi = seq_hi50_by_account_.count(prev_acct) > 0U
                    ? seq_hi50_by_account_[prev_acct]
                    : default_init_seq_hi50_;
                const uint16_t prev_ns = next_seq_by_account_.count(prev_acct) > 0U
                    ? next_seq_by_account_[prev_acct]
                    : default_init_seq_lo_;
                const bool prev_pw = pending_hi50_wrap_by_account_.count(prev_acct) > 0U
                    ? pending_hi50_wrap_by_account_[prev_acct]
                    : false;
                saved_cred_seq_state_[{prev_acct, prev_kit->second.first, prev_kit->second.second}] =
                    SavedCredSeqState{prev_hi, prev_ns, prev_pw};
            }
        }
        account_id_        = account_id;
        signer_account_id_ = account_id;
        key_lo64_          = key_lo64;
        key_hi64_          = key_hi64;
        tried_resync_hi50_ = false;
        const uint32_t seq_acct = seq_bucket_account(account_id_);
        const auto     kit      = cred_key_by_account_.find(seq_acct);
        const std::pair<uint64_t, uint64_t> new_key{key_lo64, key_hi64};
        if (kit == cred_key_by_account_.end()) {
            cred_key_by_account_.emplace(seq_acct, new_key);
            if (const auto sit = saved_cred_seq_state_.find({seq_acct, key_lo64, key_hi64});
                sit != saved_cred_seq_state_.end()) {
                seq_hi50_by_account_[seq_acct]          = sit->second.seq_hi50;
                next_seq_by_account_[seq_acct]          = sit->second.next_seq;
                pending_hi50_wrap_by_account_[seq_acct] = sit->second.pending_wrap;
            } else {
                next_seq_by_account_.try_emplace(seq_acct, default_init_seq_lo_);
                seq_hi50_by_account_.try_emplace(seq_acct, default_init_seq_hi50_);
                pending_hi50_wrap_by_account_.try_emplace(seq_acct, false);
            }
        } else if (kit->second != new_key) {
            saved_cred_seq_state_[{seq_acct, kit->second.first, kit->second.second}] = SavedCredSeqState{
                seq_hi50_by_account_.count(seq_acct) > 0U ? seq_hi50_by_account_[seq_acct] : default_init_seq_hi50_,
                next_seq_by_account_.count(seq_acct) > 0U ? next_seq_by_account_[seq_acct] : default_init_seq_lo_,
                pending_hi50_wrap_by_account_.count(seq_acct) > 0U ? pending_hi50_wrap_by_account_[seq_acct] : false
            };
            kit->second = new_key;
            if (const auto sit = saved_cred_seq_state_.find({seq_acct, key_lo64, key_hi64});
                sit != saved_cred_seq_state_.end()) {
                seq_hi50_by_account_[seq_acct]          = sit->second.seq_hi50;
                next_seq_by_account_[seq_acct]          = sit->second.next_seq;
                pending_hi50_wrap_by_account_[seq_acct] = sit->second.pending_wrap;
            } else {
                next_seq_by_account_[seq_acct]          = default_init_seq_lo_;
                seq_hi50_by_account_[seq_acct]          = default_init_seq_hi50_;
                pending_hi50_wrap_by_account_[seq_acct] = false;
            }
        }
        verified_seq_by_account_.erase(seq_acct);
        ambiguous_disconnect_by_account_.erase(seq_acct);
        seq_hi50_ = seq_hi50_by_account_[seq_acct];
        saved_cred_seq_state_[{seq_acct, key_lo64_, key_hi64_}] = SavedCredSeqState{
            seq_hi50_, next_seq_by_account_[seq_acct], pending_hi50_wrap_by_account_[seq_acct]
        };
    }

    void set_seq_epoch(uint64_t seq_hi50, uint16_t next_seq14 = 1U) noexcept {
        const uint64_t masked_hi50 = seq_hi50 & ((1ULL << 50U) - 1ULL);
        seq_hi50_                  = masked_hi50;
        default_init_seq_hi50_     = masked_hi50;
        tried_resync_hi50_         = false;
        seq_hi50_by_account_.clear();
        verified_seq_by_account_.clear();
        ambiguous_disconnect_by_account_.clear();
        pending_hi50_wrap_by_account_.clear();
        saved_cred_seq_state_.clear();
        const uint32_t seq_acct                    = seq_bucket_account(account_id_);
        seq_hi50_by_account_[seq_acct]             = masked_hi50;
        next_seq_by_account_[seq_acct]             = static_cast<uint16_t>(next_seq14 & 0x3FFFU);
        pending_hi50_wrap_by_account_[seq_acct]    = false;
        saved_cred_seq_state_[{seq_acct, key_lo64_, key_hi64_}] =
            SavedCredSeqState{masked_hi50, next_seq_by_account_[seq_acct], false};
    }

    void set_account_next_seq_lo(uint32_t account_id, uint16_t next_seq14) noexcept {
        const uint32_t seq_acct                    = seq_bucket_account(account_id);
        next_seq_by_account_[seq_acct]             = static_cast<uint16_t>(next_seq14 & 0x3FFFU);
        pending_hi50_wrap_by_account_[seq_acct]    = false;
        verified_seq_by_account_.erase(seq_acct);
    }

    [[nodiscard]] uint32_t account_id() const noexcept { return account_id_; }
    [[nodiscard]] uint16_t peek_next_seq_lo() const noexcept {
        return peek_next_seq_lo(account_id_);
    }
    [[nodiscard]] uint16_t peek_next_seq_lo(uint32_t account_id) const noexcept {
        const uint32_t seq_acct = seq_bucket_account(account_id);
        const auto     it       = next_seq_by_account_.find(seq_acct);
        return (it != next_seq_by_account_.end()) ? it->second : default_init_seq_lo_;
    }
    [[nodiscard]] bool     is_connected() const noexcept { return tcp_sock_ != detail::SDK_INVALID_SOCK; }

    bool connect_tcp(uint16_t port, const char* host = "127.0.0.1", uint32_t io_timeout_ms = 2'500U) noexcept {
        detail::ensure_winsock_initialized();
        disconnect();
        io_timeout_ms_ = (io_timeout_ms > 0U) ? io_timeout_ms : 2'500U;
        tcp_sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tcp_sock_ == detail::SDK_INVALID_SOCK) return false;

        detail::sdk_enable_tcp_nodelay(tcp_sock_);
        detail::sdk_apply_io_timeout(tcp_sock_, io_timeout_ms_);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (port == 0U || !detail::sdk_resolve_ipv4_host(host, addr.sin_addr)) {
            disconnect();
            return false;
        }
        if (!detail::sdk_connect_with_timeout(tcp_sock_, addr, io_timeout_ms_)) {
            disconnect();
            return false;
        }
        return true;
    }

    void disconnect() noexcept {
        tried_resync_hi50_ = false;
        detail::sdk_close_socket(tcp_sock_);
        tcp_sock_ = detail::SDK_INVALID_SOCK;
    }

    void disconnect_tcp() noexcept {
        disconnect();
    }

    // -------------------------------------------------------------------------
    // Frame Builders (advance 14-bit RFC-1982 modular `seq_lo` per account)
    // -------------------------------------------------------------------------
    [[nodiscard]] arena::wire::ArenaWireFrame build_raw_frame(
        arena::wire::BaseOp      op,
        uint16_t                 market_id           = 0U,
        arena::wire::OrderSide   side                = arena::wire::OrderSide::Bid,
        int64_t                  price_ticks         = 0LL,
        uint64_t                 qty_lots            = 0ULL,
        arena::wire::TimeInForce tif                 = arena::wire::TimeInForce::GTC,
        arena::wire::StpMode     stp                 = arena::wire::StpMode::CancelResting,
        uint64_t                 aux_param0          = 0ULL,
        uint64_t                 aux_param1          = 0ULL,
        uint16_t                 ext_qty_hi16        = 0U,
        uint32_t                 account_id_override = 0U
    ) noexcept {
        if (!is_valid_wire_price_ticks_48(price_ticks) ||
            qty_lots > arena::wire::MAX_WIRE_HEADER_QTY_LOTS ||
            static_cast<uint8_t>(side) > 1U ||
            !arena::wire::is_canonical_ext_qty_hi16(ext_qty_hi16)) {
            return arena::wire::ArenaWireFrame{};
        }
        const uint32_t eff_acct   = (account_id_override != 0U) ? account_id_override : account_id_;
        if (!is_valid_wire_account_id_24(eff_acct)) {
            return arena::wire::ArenaWireFrame{};
        }
        uint16_t       frame_seq  = 0U;
        uint64_t       frame_hi50 = seq_hi50_;
        allocate_seq_for_frame(eff_acct, frame_seq, frame_hi50);
        last_built_seq_hi50_      = frame_hi50;
        arena::wire::ArenaHeader hdr{};
        hdr.op          = op;
        hdr.flags       = arena::wire::ArenaFlags{tif, stp};
        hdr.market_id   = market_id;
        hdr.account_id  = eff_acct;
        hdr.side        = side;
        hdr.seq_lo      = frame_seq;
        hdr.price_ticks = price_ticks;
        hdr.qty_lots    = qty_lots;
        return arena::wire::pack_wire_frame(hdr, aux_param0, aux_param1, frame_hi50, key_lo64_, key_hi64_, ext_qty_hi16);
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_order_frame(
        uint16_t                 market_id,
        arena::wire::OrderSide   side,
        int64_t                  price_ticks,
        uint64_t                 qty_lots,
        arena::wire::TimeInForce tif                   = arena::wire::TimeInForce::GTC,
        arena::wire::StpMode     stp                   = arena::wire::StpMode::CancelResting,
        uint64_t                 client_tag            = 0ULL,
        bool                     reduce_only           = false,
        bool                     is_market             = false,
        bool                     cancel_on_disconnect  = false,
        bool                     post_only_slide       = false,
        uint64_t                 min_qty_lots          = 0ULL,
        bool                     primary_peg           = false,
        bool                     midpoint_peg          = false,
        bool                     margin_spot           = false,
        uint64_t                 display_qty_lots      = 0ULL,
        bool                     dark_midpoint         = false,
        int16_t                  auto_skew_ticks       = 0,
        int16_t                  peg_offset_ticks      = 0,
        bool                     oco_linked            = false,
        uint16_t                 max_lifetime_wal_seqs = 0U,
        uint8_t                  jit_elastic_mult         = 0U,
        bool                     mark_peg                 = false,
        int16_t                  auto_flip_ticks          = 0,
        bool                     trailing_peg             = false,
        bool                     stp_decrement_and_cancel = false,
        uint16_t                 priority_fee_ppm         = 0U
    ) noexcept {
        if (qty_lots > 0xFF'FFFF'FFFFULL ||
            priority_fee_ppm > arena::wire::MAX_PRIORITY_FEE_PPM) {
            return arena::wire::ArenaWireFrame{};
        }
        if (!dark_midpoint && !trailing_peg) {
            const uint64_t max_hi_qty = (max_lifetime_wal_seqs > 0U)
                ? arena::wire::ORDER_AUX_MIN_QTY_GTS_MASK
                : arena::wire::ORDER_AUX_MIN_QTY_MASK;
            if (min_qty_lots > max_hi_qty || display_qty_lots > max_hi_qty) {
                return arena::wire::ArenaWireFrame{};
            }
        }
        const uint64_t aux1 = arena::wire::pack_order_aux1(
            reduce_only, is_market, cancel_on_disconnect, post_only_slide,
            min_qty_lots, primary_peg, midpoint_peg, margin_spot, display_qty_lots,
            dark_midpoint, auto_skew_ticks, peg_offset_ticks, oco_linked, max_lifetime_wal_seqs,
            jit_elastic_mult, mark_peg, auto_flip_ticks, trailing_peg
        );
        auto frm = build_raw_frame(
            arena::wire::BaseOp::NewOrder, market_id, side, price_ticks, qty_lots, tif, stp, client_tag, aux1
        );
        if (stp_decrement_and_cancel && is_valid_frame(frm)) {
            arena::wire::pack_order_ext_stp_decrement_cancel(
                frm, true, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        if (priority_fee_ppm > 0U &&
            tif != arena::wire::TimeInForce::PostOnly &&
            !post_only_slide && !primary_peg && !midpoint_peg &&
            !dark_midpoint && !mark_peg && !trailing_peg &&
            is_valid_frame(frm)) {
            arena::wire::pack_order_ext_priority_fee_ppm(
                frm, priority_fee_ppm, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_cancel_frame(uint16_t market_id, uint64_t order_id) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::Cancel, market_id, arena::wire::OrderSide::Bid, 0LL, 0ULL,
            arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting, order_id, 0ULL
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_modify_frame(
        uint16_t market_id,
        uint64_t order_id,
        int64_t  new_price_ticks,
        uint64_t new_qty_lots,
        bool     keep_priority = false
    ) noexcept {
        const uint64_t aux1 = keep_priority ? arena::wire::MODIFY_AUX_FLAG_KEEP_PRIORITY : 0ULL;
        return build_raw_frame(
            arena::wire::BaseOp::ModifyInPlace, market_id, arena::wire::OrderSide::Bid,
            new_price_ticks, new_qty_lots,
            arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting, order_id, aux1
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_quote_frame(
        uint16_t                 market_id,
        int64_t                  bid_price_ticks,
        uint64_t                 bid_qty_lots,
        int64_t                  ask_price_ticks,
        uint64_t                 ask_qty_lots,
        arena::wire::TimeInForce tif                   = arena::wire::TimeInForce::PostOnly,
        arena::wire::StpMode     stp                   = arena::wire::StpMode::CancelResting,
        bool                     cancel_on_disconnect  = false,
        bool                     post_only_slide       = false,
        bool                     margin_spot           = false,
        int16_t                  auto_skew_ticks       = 0,
        bool                     oco_linked            = false,
        uint16_t                 max_lifetime_wal_seqs = 0U,
        uint8_t                  jit_elastic_mult      = 0U,
        int16_t                  auto_flip_ticks       = 0,
        uint8_t                  quote_peg_mode        = 0U,
        int16_t                  peg_offset_ticks      = 0,
        uint64_t                 client_tag            = 0ULL,
        bool                     ladder_by_tag         = false
    ) noexcept {
        if (!is_valid_wire_price_ticks_48(bid_price_ticks) ||
            !is_valid_wire_price_ticks_48(ask_price_ticks) ||
            bid_qty_lots > arena::wire::MAX_WIRE_HEADER_QTY_LOTS ||
            ask_qty_lots > arena::wire::MAX_WIRE_EXT_QTY_LOTS) {
            return arena::wire::ArenaWireFrame{};
        }
        uint16_t ask_qty_hi16 = 0U;
        const uint64_t aux1 = arena::wire::pack_quote_aux1(
            ask_qty_lots, cancel_on_disconnect, post_only_slide, margin_spot,
            auto_skew_ticks, oco_linked, max_lifetime_wal_seqs, jit_elastic_mult, auto_flip_ticks,
            quote_peg_mode, peg_offset_ticks, &ask_qty_hi16
        );
        auto frm = build_raw_frame(
            arena::wire::BaseOp::TwoSidedQuoteReplace,
            market_id,
            arena::wire::OrderSide::Bid,
            bid_price_ticks,
            bid_qty_lots,
            tif,
            stp,
            static_cast<uint64_t>(ask_price_ticks),
            aux1,
            ask_qty_hi16
        );
        if ((client_tag != 0ULL || ladder_by_tag) && is_valid_frame(frm)) {
            arena::wire::pack_quote_ext_tag_and_ladder(
                frm, client_tag, ladder_by_tag, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_atomic_spread_frame(
        uint16_t               leg1_market_id,
        arena::wire::OrderSide leg1_side,
        int64_t                leg1_price_ticks,
        uint64_t               leg1_qty_lots,
        uint16_t               leg2_market_id,
        arena::wire::OrderSide leg2_side,
        int64_t                leg2_price_ticks,
        uint64_t               leg2_qty_lots,
        bool                   leg1_is_market   = false,
        bool                   leg1_reduce_only = false,
        bool                   leg2_is_market   = false,
        bool                   leg2_reduce_only = false,
        arena::wire::StpMode   stp                     = arena::wire::StpMode::CancelResting,
        bool                   margin_spot             = false,
        uint16_t               express_surplus_bid_bps = 0U
    ) noexcept {
        if (!is_valid_wire_price_ticks_48(leg1_price_ticks) ||
            !is_valid_wire_price_ticks_48(leg2_price_ticks) ||
            leg1_qty_lots == 0ULL ||
            leg1_qty_lots > arena::wire::MAX_WIRE_HEADER_QTY_LOTS ||
            leg2_qty_lots == 0ULL ||
            leg2_qty_lots > arena::wire::MAX_WIRE_EXT_QTY_LOTS ||
            express_surplus_bid_bps > arena::wire::MAX_EXPRESS_SURPLUS_BID_BPS) {
            return arena::wire::ArenaWireFrame{};
        }
        uint64_t aux0 = 0ULL;
        uint64_t aux1 = 0ULL;
        uint16_t leg2_qty_hi16 = 0U;
        arena::wire::pack_atomic_spread_aux(
            leg2_market_id,
            leg2_side,
            leg2_price_ticks,
            leg2_qty_lots,
            leg1_is_market,
            leg1_reduce_only,
            leg2_is_market,
            leg2_reduce_only,
            aux0,
            aux1,
            margin_spot,
            &leg2_qty_hi16
        );
        auto frm = build_raw_frame(
            arena::wire::BaseOp::AtomicSpread,
            leg1_market_id,
            leg1_side,
            leg1_price_ticks,
            leg1_qty_lots,
            arena::wire::TimeInForce::IOC,
            stp,
            aux0,
            aux1,
            leg2_qty_hi16
        );
        if (express_surplus_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_express_surplus_bid_bps(
                frm, express_surplus_bid_bps, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_atomic_basket_frame(
        uint8_t                                           num_legs,
        const std::array<arena::wire::WireBasketLeg, 4>&  legs,
        arena::wire::StpMode                              stp                     = arena::wire::StpMode::CancelResting,
        bool                                              margin_spot             = false,
        uint32_t                                          account_id_override     = 0U,
        uint16_t                                          express_surplus_bid_bps = 0U
    ) noexcept {
        if (num_legs < 2U || num_legs > 4U ||
            express_surplus_bid_bps > arena::wire::MAX_EXPRESS_SURPLUS_BID_BPS ||
            (num_legs >= 4U && express_surplus_bid_bps > 0U)) {
            return arena::wire::ArenaWireFrame{};
        }
        if (!is_valid_wire_price_ticks_48(legs[0].price_ticks) ||
            !is_valid_wire_price_ticks_48(legs[1].price_ticks) ||
            legs[0].qty_lots == 0ULL ||
            legs[0].qty_lots > arena::wire::MAX_WIRE_HEADER_QTY_LOTS ||
            legs[1].qty_lots == 0ULL) {
            return arena::wire::ArenaWireFrame{};
        }
        const bool ext_mkt16 = (num_legs >= 3U) &&
            (legs[2].market_id > 0xFFU || (num_legs >= 4U && legs[3].market_id > 0xFFU));
        const uint64_t max_leg2_qty = (num_legs == 2U)
            ? arena::wire::MAX_WIRE_EXT_QTY_LOTS
            : (ext_mkt16 ? arena::wire::MAX_WIRE_BASKET_LEG24_QTY_LOTS : arena::wire::QUOTE_AUX_QTY_MASK);
        if (legs[1].qty_lots > max_leg2_qty) {
            return arena::wire::ArenaWireFrame{};
        }
        for (uint8_t i = 2U; i < num_legs; ++i) {
            if (legs[i].price_ticks < arena::wire::MIN_WIRE_BASKET_LEG34_PRICE_TICKS ||
                legs[i].price_ticks > arena::wire::MAX_WIRE_BASKET_LEG34_PRICE_TICKS ||
                legs[i].qty_lots == 0ULL ||
                legs[i].qty_lots > arena::wire::MAX_WIRE_BASKET_LEG24_QTY_LOTS) {
                return arena::wire::ArenaWireFrame{};
            }
        }
        const uint32_t eff_acct   = (account_id_override != 0U) ? account_id_override : account_id_;
        if (!is_valid_wire_account_id_24(eff_acct)) {
            return arena::wire::ArenaWireFrame{};
        }
        uint16_t       frame_seq  = 0U;
        uint64_t       frame_hi50 = seq_hi50_;
        allocate_seq_for_frame(eff_acct, frame_seq, frame_hi50);
        auto frm = arena::wire::pack_wire_basket_frame(
            eff_acct,
            num_legs,
            legs,
            stp,
            margin_spot,
            frame_seq,
            frame_hi50,
            key_lo64_,
            key_hi64_
        );
        if (express_surplus_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_express_surplus_bid_bps(
                frm, express_surplus_bid_bps, frame_hi50, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_atomic_basket_frame(
        const std::vector<arena::wire::WireBasketLeg>& legs,
        arena::wire::StpMode                           stp                     = arena::wire::StpMode::CancelResting,
        bool                                           margin_spot             = false,
        uint16_t                                       express_surplus_bid_bps = 0U
    ) noexcept {
        if (legs.size() < 2U || legs.size() > 4U) {
            return arena::wire::ArenaWireFrame{};
        }
        std::array<arena::wire::WireBasketLeg, 4> arr{};
        const uint8_t n = static_cast<uint8_t>(legs.size());
        for (uint8_t i = 0U; i < n; ++i) {
            arr[i] = legs[i];
        }
        return build_atomic_basket_frame(n, arr, stp, margin_spot, 0U, express_surplus_bid_bps);
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_distribute_yield_frame(
        int64_t  reward_usd_micro,
        uint32_t sponsor_account_id = 0U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            reward_usd_micro,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(sponsor_account_id),
            arena::wire::MARK_AUX1_FLAG_DISTRIBUTE_YIELD
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_set_protocol_account_frame(
        uint32_t protocol_account_id
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(protocol_account_id),
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(protocol_account_id),
            arena::wire::MARK_AUX1_FLAG_SET_PROTOCOL_ACCOUNT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_mint_redeem_frame(
        uint16_t               market_id,
        arena::wire::OrderSide side,
        uint64_t               qty_lots,
        int64_t                limit_cost_or_payout_micro = 0LL
    ) noexcept {
        if (qty_lots == 0ULL || qty_lots > arena::wire::MAX_WIRE_HEADER_QTY_LOTS) {
            return arena::wire::ArenaWireFrame{};
        }
        constexpr int64_t kMax48Signed = 0x7FFF'FFFF'FFFFLL;
        const int64_t hdr_px = (limit_cost_or_payout_micro < 0LL)
                             ? -1LL
                             : std::min<int64_t>(limit_cost_or_payout_micro, kMax48Signed);
        return build_raw_frame(
            arena::wire::BaseOp::MintRedeemSet,
            market_id,
            side,
            hdr_px,
            qty_lots,
            arena::wire::TimeInForce::IOC,
            arena::wire::StpMode::CancelResting,
            (limit_cost_or_payout_micro > 0LL) ? static_cast<uint64_t>(limit_cost_or_payout_micro) : 0ULL,
            0ULL
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_flash_arbitrage_frame(
        uint16_t               market_id,
        arena::wire::OrderSide side,
        uint64_t               qty_lots,
        int64_t                limit_price_ticks       = 0LL,
        int64_t                min_profit_micro        = 0LL,
        bool                   is_market               = false,
        arena::wire::StpMode   stp                     = arena::wire::StpMode::CancelResting,
        uint16_t               express_surplus_bid_bps = 0U
    ) noexcept {
        if (express_surplus_bid_bps > arena::wire::MAX_EXPRESS_SURPLUS_BID_BPS) {
            return arena::wire::ArenaWireFrame{};
        }
        uint64_t aux1 = arena::wire::MINT_AUX1_FLAG_FLASH_ARB;
        if (is_market || limit_price_ticks <= 0LL) {
            aux1 |= arena::wire::MINT_AUX1_FLAG_FLASH_MARKET;
        }
        auto frm = build_raw_frame(
            arena::wire::BaseOp::MintRedeemSet,
            market_id,
            side,
            limit_price_ticks,
            qty_lots,
            arena::wire::TimeInForce::IOC,
            stp,
            static_cast<uint64_t>(min_profit_micro),
            aux1
        );
        if (express_surplus_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_express_surplus_bid_bps(
                frm, express_surplus_bid_bps, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_knockout_frame(
        uint16_t market_id,
        int64_t  knockout_price_ticks
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::LiquidateAccount,
            market_id,
            arena::wire::OrderSide::Bid,
            knockout_price_ticks,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(account_id_),
            arena::wire::LIQ_AUX1_FLAG_SET_KNOCKOUT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_drawdown_stop_frame(
        int64_t stop_equity_usd_micro
    ) noexcept {
        return build_knockout_frame(0U, stop_equity_usd_micro);
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_auto_delta_hedge_frame(
        uint16_t base_asset_id       = 0U,
        uint16_t preferred_market_id = 0U,
        uint64_t max_qty_lots        = 0ULL,
        uint16_t max_slippage_bps    = 500U,
        bool     allow_margin_spot   = false
    ) noexcept {
        uint64_t aux1 = arena::wire::LIQ_AUX1_FLAG_AUTO_DELTA_HEDGE;
        if (allow_margin_spot) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT;
        }
        return build_raw_frame(
            arena::wire::BaseOp::LiquidateAccount,
            preferred_market_id,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(max_slippage_bps),
            max_qty_lots,
            arena::wire::TimeInForce::IOC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(base_asset_id),
            aux1
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_link_sub_account_frame(
        uint32_t sub_account_id,
        int64_t  max_guaranty_usd_micro = 0LL,
        uint32_t master_account_id      = 0U
    ) noexcept {
        // Preserve `-2LL` (UNLINK), `-1LL` (freeze / 0 guaranty), `0LL` (unlimited),
        // and `> 0LL` (explicit cap); pass `-3LL` for out-of-range negatives so the
        // server rejects with RejectInvalidParams instead of clamping to unlimited `0LL`.
        const int64_t encoded_guaranty = (max_guaranty_usd_micro < -2LL)
                                       ? -3LL
                                       : max_guaranty_usd_micro;
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            encoded_guaranty,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(sub_account_id),
            arena::wire::MARK_AUX1_FLAG_LINK_SUB_ACCOUNT,
            0U,
            master_account_id
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_bind_builder_frame(
        uint32_t builder_account_id,
        uint16_t builder_fee_share_bps,
        uint32_t trader_account_id = 0U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(builder_fee_share_bps),
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(builder_account_id),
            arena::wire::MARK_AUX1_FLAG_BIND_BUILDER,
            0U,
            trader_account_id
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_configure_mmp_frame(
        uint32_t window_wal_seqs,
        uint64_t max_fill_lots,
        uint64_t max_delta_lots    = 0ULL,
        uint32_t cooldown_wal_seqs = 0U
    ) noexcept {
        const uint64_t aux0 =
            ((static_cast<uint64_t>(window_wal_seqs) & 0xFFFF'FFFFULL) << 32U) |
            (static_cast<uint64_t>(cooldown_wal_seqs) & 0xFFFF'FFFFULL);
        const int64_t clamped_delta = static_cast<int64_t>(
            std::min<uint64_t>(max_delta_lots, static_cast<uint64_t>(MAX_WIRE_PRICE_TICKS_48))
        );
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            clamped_delta,
            max_fill_lots,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            aux0,
            arena::wire::MARK_AUX1_FLAG_CONFIG_MMP
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_configure_payout_frame(
        uint16_t payout_asset_id          = 0U,
        uint8_t  payout_mode_flags        = 0U,
        uint32_t payout_target_account_id = 0U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            payout_asset_id,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(payout_mode_flags),
            static_cast<uint64_t>(payout_asset_id),
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(payout_target_account_id),
            arena::wire::MARK_AUX1_FLAG_CONFIG_PAYOUT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_distribute_base_yield_frame(
        uint16_t base_asset_id,
        uint64_t total_lots
    ) noexcept {
        if (total_lots == 0ULL || total_lots > static_cast<uint64_t>(MAX_WIRE_PRICE_TICKS_48)) {
            return arena::wire::ArenaWireFrame{};
        }
        const int64_t  hdr_lots = static_cast<int64_t>(total_lots);
        const uint64_t wire_qty = (total_lots <= arena::wire::MAX_WIRE_HEADER_QTY_LOTS) ? total_lots : 0ULL;
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            base_asset_id,
            arena::wire::OrderSide::Bid,
            hdr_lots,
            wire_qty,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(base_asset_id),
            arena::wire::MARK_AUX1_FLAG_BASE_YIELD
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_configure_auto_repo_frame(
        uint32_t epoch_marks,
        uint16_t clock_market_id = 0U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            clock_market_id,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(epoch_marks),
            static_cast<uint64_t>(epoch_marks),
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(epoch_marks),
            arena::wire::MARK_AUX1_FLAG_CONFIG_AUTO_REPO
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_configure_payout_portfolio_frame(
        uint16_t primary_asset_id,
        uint16_t primary_share_bps,
        uint16_t secondary_asset_id       = 0U,
        uint16_t secondary_share_bps      = 0U,
        uint16_t tertiary_asset_id        = 0U,
        uint16_t tertiary_share_bps       = 0U,
        uint8_t  payout_mode_flags        = 0U,
        uint32_t payout_target_account_id = 0U,
        uint16_t max_margin_util_bps      = 0U,
        int64_t  max_price_ticks          = 0LL
    ) noexcept {
        const uint64_t p_bps_14 = (primary_share_bps > 0x3FFFU) ? 0x3FFFULL : static_cast<uint64_t>(primary_share_bps);
        const uint64_t s_bps_14 = (secondary_share_bps > 0x3FFFU) ? 0x3FFFULL : static_cast<uint64_t>(secondary_share_bps);
        const bool invalid_aid  = (primary_asset_id > 0xFFU) || (secondary_asset_id > 0xFFU) || (tertiary_asset_id > 0xFFU);
        const uint16_t packed_mkt = static_cast<uint16_t>(
            ((primary_asset_id & 0xFFU) << 8U) | (secondary_asset_id & 0xFFU)
        );
        const uint64_t packed_qty =
            (p_bps_14 << 22U) | (s_bps_14 << 8U) | static_cast<uint64_t>(tertiary_asset_id & 0xFFU);
        const uint64_t aux0 =
            (static_cast<uint64_t>(payout_target_account_id) << 32U) |
            (static_cast<uint64_t>(tertiary_share_bps) << 16U) |
            static_cast<uint64_t>(max_margin_util_bps);
        const uint64_t aux1 =
            arena::wire::MARK_AUX1_FLAG_CONFIG_PAYOUT_RULES |
            (invalid_aid ? (1ULL << 24U) : 0ULL) |
            (static_cast<uint64_t>(payout_mode_flags) << 32U);
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            packed_mkt,
            arena::wire::OrderSide::Bid,
            max_price_ticks,
            packed_qty,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            aux0,
            aux1
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_fund_market_vault_frame(
        uint16_t market_id,
        uint16_t asset_id,
        uint64_t amount,
        uint32_t duration_marks,
        uint16_t maker_share_bps = 7'500U
    ) noexcept {
        const uint64_t packed_qty =
            (static_cast<uint64_t>(duration_marks) << 8U) |
            static_cast<uint64_t>(asset_id & 0xFFU);
        const uint64_t aux1 =
            arena::wire::MARK_AUX1_FLAG_FUND_MARKET_VAULT |
            (static_cast<uint64_t>(asset_id) << 32U);
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            market_id,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(maker_share_bps),
            packed_qty,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            amount,
            aux1
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_configure_default_incentives_frame(
        uint8_t  pillar_mask                 = arena::wire::INCENTIVE_PILLARS_ALL_ON,
        uint32_t repo_epoch_marks            = 60U,
        uint16_t two_sided_bonus_bps         = 2'500U,
        uint16_t claim_collateral_weight_bps = 9'000U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            two_sided_bonus_bps,
            arena::wire::OrderSide::Bid,
            static_cast<int64_t>(claim_collateral_weight_bps),
            static_cast<uint64_t>(repo_epoch_marks),
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(pillar_mask),
            arena::wire::MARK_AUX1_FLAG_DEFAULT_INCENTIVES
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_subscribe_express_port_frame(
        uint32_t duration_epochs,
        int64_t  max_fee_usd_micro = 0LL
    ) noexcept {
        constexpr uint32_t kMaxExpressPortLeaseEpochs = 1'051'200U;
        if (duration_epochs == 0U || duration_epochs > kMaxExpressPortLeaseEpochs || max_fee_usd_micro < 0LL) {
            return arena::wire::ArenaWireFrame{};
        }
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            max_fee_usd_micro,
            static_cast<uint64_t>(duration_epochs),
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            0ULL,
            arena::wire::MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_set_express_port_fee_frame(
        int64_t fee_per_epoch_usd_micro
    ) noexcept {
        constexpr int64_t kMinExpressPortFeeMicro = 1'000LL;
        constexpr int64_t kMaxExpressPortFeeMicro = 10'000'000'000LL;
        if (fee_per_epoch_usd_micro < kMinExpressPortFeeMicro ||
            fee_per_epoch_usd_micro > kMaxExpressPortFeeMicro) {
            return arena::wire::ArenaWireFrame{};
        }
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            fee_per_epoch_usd_micro,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            (1ULL << 63U),
            arena::wire::MARK_AUX1_FLAG_SUBSCRIBE_EXPRESS_PORT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_prime_transfer_frame(
        uint32_t to_account_id,
        int64_t  amount,
        uint16_t asset_id        = 0U,
        uint32_t from_account_id = 0U
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            asset_id,
            arena::wire::OrderSide::Bid,
            amount,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(to_account_id),
            arena::wire::MARK_AUX1_FLAG_SUB_TRANSFER,
            0U,
            from_account_id
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_auto_cross_arb_frame(
        uint16_t market_id_1             = 0U,
        uint16_t market_id_2             = 0U,
        uint64_t max_qty_lots            = 0ULL,
        int64_t  min_profit_ticks        = 1LL,
        bool     allow_margin_spot       = false,
        uint16_t express_surplus_bid_bps = 0U
    ) noexcept {
        if (express_surplus_bid_bps > arena::wire::MAX_EXPRESS_SURPLUS_BID_BPS) {
            return arena::wire::ArenaWireFrame{};
        }
        uint64_t aux1 = arena::wire::LIQ_AUX1_FLAG_AUTO_CROSS_ARB;
        if (allow_margin_spot) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT;
        }
        auto frm = build_raw_frame(
            arena::wire::BaseOp::LiquidateAccount,
            market_id_1,
            arena::wire::OrderSide::Bid,
            min_profit_ticks,
            max_qty_lots,
            arena::wire::TimeInForce::IOC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(market_id_2),
            aux1
        );
        if (express_surplus_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_express_surplus_bid_bps(
                frm, express_surplus_bid_bps, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_auto_liquidation_sweep_frame(
        uint16_t             market_id             = 0U,
        uint32_t             target_account_id     = 0U,
        uint64_t             max_qty_lots          = 0ULL,
        int64_t              min_bounty_micro      = 0LL,
        bool                 auto_offload_to_book  = true,
        arena::wire::StpMode stp                   = arena::wire::StpMode::CancelResting,
        bool                 hedge_margin_spot     = false,
        uint16_t             bounty_rebate_bid_bps = 0U
    ) noexcept {
        if (bounty_rebate_bid_bps > arena::wire::MAX_LIQ_BOUNTY_REBATE_BID_BPS ||
            (bounty_rebate_bid_bps > 0U && target_account_id != 0U && target_account_id == account_id_)) {
            return arena::wire::ArenaWireFrame{};
        }
        uint64_t aux1 = arena::wire::LIQ_AUX1_FLAG_AUTO_LIQ_SWEEP;
        if (!auto_offload_to_book) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_NO_OFFLOAD;
        }
        if (hedge_margin_spot) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT;
        }
        auto frm = build_raw_frame(
            arena::wire::BaseOp::LiquidateAccount,
            market_id,
            arena::wire::OrderSide::Bid,
            min_bounty_micro,
            max_qty_lots,
            auto_offload_to_book ? arena::wire::TimeInForce::IOC : arena::wire::TimeInForce::GTC,
            stp,
            static_cast<uint64_t>(target_account_id),
            aux1
        );
        if (bounty_rebate_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_liq_bounty_rebate_bid_bps(
                frm, bounty_rebate_bid_bps, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_auto_liquidate_sweep_frame(
        uint16_t             market_id             = 0U,
        uint32_t             target_account_id     = 0U,
        uint64_t             max_qty_lots          = 0ULL,
        int64_t              min_bounty_micro      = 0LL,
        bool                 auto_offload_to_book  = true,
        arena::wire::StpMode stp                   = arena::wire::StpMode::CancelResting,
        bool                 hedge_margin_spot     = false,
        uint16_t             bounty_rebate_bid_bps = 0U
    ) noexcept {
        return build_auto_liquidation_sweep_frame(
            market_id,
            target_account_id,
            max_qty_lots,
            min_bounty_micro,
            auto_offload_to_book,
            stp,
            hedge_margin_spot,
            bounty_rebate_bid_bps
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_save_wal_snapshot_frame() noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            0LL,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            0ULL,
            arena::wire::MARK_AUX1_FLAG_SAVE_SNAPSHOT
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_sweep_insurance_frame(
        int64_t reserve_floor_usd_micro = 0LL,
        int64_t max_sweep_usd_micro     = 0LL
    ) noexcept {
        if (reserve_floor_usd_micro < 0LL || max_sweep_usd_micro < 0LL ||
            reserve_floor_usd_micro > MAX_WIRE_PRICE_TICKS_48) {
            return arena::wire::ArenaWireFrame{};
        }
        const uint64_t full_max_u64 = static_cast<uint64_t>(max_sweep_usd_micro);
        const uint64_t hdr_qty_40   = std::min<uint64_t>(full_max_u64, arena::wire::MAX_WIRE_HEADER_QTY_LOTS);
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            reserve_floor_usd_micro,
            hdr_qty_40,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            full_max_u64,
            arena::wire::MARK_AUX1_FLAG_SWEEP_INSURANCE
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_harvest_custody_float_yield_frame(
        int64_t yield_rate_bps            = 1LL,
        int64_t protocol_spread_share_bps = -1LL
    ) noexcept {
        const uint64_t aux0 = (protocol_spread_share_bps >= 0LL)
                            ? (static_cast<uint64_t>(protocol_spread_share_bps) + 1ULL)
                            : 0ULL;
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            (yield_rate_bps > 0LL) ? yield_rate_bps : 1LL,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            aux0,
            arena::wire::MARK_AUX1_FLAG_HARVEST_FLOAT_YIELD
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_harvest_overnight_spot_repo_frame(
        uint16_t base_asset_id     = 1U,
        int64_t  override_rate_bps = 0LL
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            base_asset_id,
            arena::wire::OrderSide::Bid,
            (override_rate_bps > 0LL) ? override_rate_bps : 0LL,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            static_cast<uint64_t>(base_asset_id),
            arena::wire::MARK_AUX1_FLAG_HARVEST_SPOT_REPO
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_harvest_negative_usd_repo_frame(
        int64_t override_rate_bps = 0LL
    ) noexcept {
        return build_raw_frame(
            arena::wire::BaseOp::UpdateMarkFunding,
            0U,
            arena::wire::OrderSide::Bid,
            (override_rate_bps > 0LL) ? override_rate_bps : 0LL,
            0ULL,
            arena::wire::TimeInForce::GTC,
            arena::wire::StpMode::CancelResting,
            0ULL,
            arena::wire::MARK_AUX1_FLAG_HARVEST_USD_REPO
        );
    }

    // -------------------------------------------------------------------------
    // Synchronous Single-Frame & High-Throughput Pipelined Batch I/O
    // -------------------------------------------------------------------------
    bool send_frame_once(
        const arena::wire::ArenaWireFrame& req,
        arena::wire::ArenaWireResponse&    resp_out
    ) noexcept {
        if (!is_valid_frame(req)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        if (tcp_sock_ == detail::SDK_INVALID_SOCK) return false;
        arena::wire::ArenaHeader once_hdr{};
        uint64_t once_mac = 0ULL, once_a0 = 0ULL, once_a1 = 0ULL;
        arena::wire::unpack_wire_frame(req, once_hdr, once_mac, once_a0, once_a1);
        const bool is_mutating_frame = !is_non_mutating_op(once_hdr.op);
        const uint32_t once_seq_acct = seq_bucket_account(once_hdr.account_id);

        std::size_t tx = 0U;
        while (tx < 64U) {
            const int n = ::send(
                tcp_sock_,
                reinterpret_cast<const char*>(req.bytes.data() + tx),
                static_cast<int>(64U - tx),
                detail::SDK_SEND_FLAGS
            );
            if (n < 0 && detail::sdk_is_eintr()) {
                continue;
            }
            if (n <= 0) {
                if (tx > 0U && is_mutating_frame) {
                    ambiguous_disconnect_by_account_[once_seq_acct] = true;
                }
                disconnect_tcp();
                return false;
            }
            tx += static_cast<std::size_t>(n);
        }

        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max<uint32_t>(1U, io_timeout_ms_));
        std::array<uint8_t, 64> rx_buf{};
        std::size_t rx = 0U;
        bool tightened_timeout = false;
        while (rx < 64U) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                if (is_mutating_frame) {
                    ambiguous_disconnect_by_account_[once_seq_acct] = true;
                }
                disconnect_tcp();
                return false;
            }
            if (rx > 0U) {
                const long long rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
                detail::sdk_apply_io_timeout(
                    tcp_sock_, static_cast<uint32_t>(std::max<long long>(1LL, rem_ms))
                );
                tightened_timeout = true;
            }
            const int n = ::recv(
                tcp_sock_,
                reinterpret_cast<char*>(rx_buf.data() + rx),
                static_cast<int>(64U - rx),
                0
            );
            if (n < 0 && detail::sdk_is_eintr()) {
                continue;
            }
            if (n <= 0) {
                if (is_mutating_frame) {
                    ambiguous_disconnect_by_account_[once_seq_acct] = true;
                }
                disconnect_tcp();
                return false;
            }
            rx += static_cast<std::size_t>(n);
        }
        if (tightened_timeout) {
            detail::sdk_apply_io_timeout(tcp_sock_, io_timeout_ms_);
        }
        resp_out = arena::wire::ArenaWireResponse::unpack_bytes(rx_buf);
        return true;
    }

    bool send_frame(
        const arena::wire::ArenaWireFrame& req,
        arena::wire::ArenaWireResponse&    resp_out
    ) noexcept {
        if (!send_frame_once(req, resp_out)) {
            return false;
        }
        arena::wire::ArenaHeader hdr{};
        uint64_t rx_mac40 = 0ULL;
        uint64_t raw_aux0 = 0ULL;
        uint64_t raw_aux1 = 0ULL;
        arena::wire::unpack_wire_frame(req, hdr, rx_mac40, raw_aux0, raw_aux1);
        const bool uses_provisioned_key =
            (key_lo64_ != DEFAULT_DEV_KEY_LO64 || key_hi64_ != DEFAULT_DEV_KEY_HI64);
        const uint32_t seq_acct = uses_provisioned_key ? seq_bucket_account(hdr.account_id) : hdr.account_id;
        if (resp_out.status_code != arena::wire::WireStatusCode::RejectInvalidMac &&
            resp_out.status_code != arena::wire::WireStatusCode::RejectReplayOrStale) {
            verified_seq_by_account_[seq_acct] = true;
            tried_resync_hi50_                 = false;
            return true;
        }
        const bool is_latest_allocated =
            (peek_next_seq_lo(seq_acct) == static_cast<uint16_t>((hdr.seq_lo + 1U) & 0x3FFFU));
        const bool was_unverified_before_sync = !verified_seq_by_account_[seq_acct];
        const bool is_unverified_stale =
            uses_provisioned_key &&
            (resp_out.status_code == arena::wire::WireStatusCode::RejectReplayOrStale) &&
            was_unverified_before_sync &&
            is_latest_allocated;
        if (((resp_out.status_code == arena::wire::WireStatusCode::RejectInvalidMac &&
              uses_provisioned_key &&
              is_latest_allocated) ||
             is_unverified_stale) &&
            !resyncing_hi50_ &&
            !tried_resync_hi50_) {
            const bool     was_pre_exec_mac_reject =
                (resp_out.status_code == arena::wire::WireStatusCode::RejectInvalidMac);
            const uint64_t rx_tail48 = req.get_tail_siphash48();
            const auto     it_hi50   = seq_hi50_by_account_.find(seq_acct);
            const uint64_t acct_hi50 = (it_hi50 != seq_hi50_by_account_.end()) ? it_hi50->second : default_init_seq_hi50_;
            const bool     match_cur =
                (rx_mac40 == arena::wire::calc_pre_siphash40(hdr, acct_hi50, key_lo64_, key_hi64_));
            const bool     match_prev =
                (!match_cur && acct_hi50 > 0ULL &&
                 rx_mac40 == arena::wire::calc_pre_siphash40(hdr, acct_hi50 - 1ULL, key_lo64_, key_hi64_));
            const uint64_t used_hi50 = match_prev ? (acct_hi50 - 1ULL) : acct_hi50;
            const bool     mac_self  = match_cur || match_prev;
            if (mac_self && rx_tail48 == arena::wire::calc_tail_siphash48(req.bytes, used_hi50, key_lo64_, key_hi64_)) {
                tried_resync_hi50_ = true;
                resyncing_hi50_    = true;
                arena::wire::ArenaWireResponse sync_resp{};
                const bool sync_io_ok = sync_sequence_for_account(seq_acct, sync_resp, is_unverified_stale);
                resyncing_hi50_       = false;
                if (!sync_io_ok) {
                    return false;
                }
                if (sync_resp.status_code == arena::wire::WireStatusCode::Ok) {
                    const bool may_auto_resubmit =
                        is_non_mutating_op(hdr.op) ||
                        (!has_ambiguous_disconnect(hdr.account_id) &&
                         (auto_retry_mutating_on_resync_ ||
                          (was_pre_exec_mac_reject && was_unverified_before_sync)));
                    if (!may_auto_resubmit) {
                        return true;
                    }
                    uint64_t old_hi50 = acct_hi50;
                    if (old_hi50 > 0ULL &&
                        arena::wire::calc_pre_siphash40(hdr, old_hi50, key_lo64_, key_hi64_) != rx_mac40 &&
                        arena::wire::calc_pre_siphash40(hdr, old_hi50 - 1ULL, key_lo64_, key_hi64_) == rx_mac40) {
                        old_hi50 -= 1ULL;
                    }
                    const uint16_t old_seq  = hdr.seq_lo;
                    uint16_t       new_seq  = 0U;
                    uint64_t       new_hi50 = sync_resp.resting_lots & ((1ULL << 50U) - 1ULL);
                    allocate_seq_for_frame(hdr.account_id, new_seq, new_hi50);
                    hdr.seq_lo = new_seq;
                    arena::wire::ArenaWireFrame rebuilt = req;
                    uint64_t m0   = 0ULL;
                    uint64_t m1   = 0ULL;
                    uint32_t hi24 = 0U;
                    hdr.pack_words(m0, m1, hi24);
                    arena::wire::write_be64(&rebuilt.bytes[0], m0);
                    arena::wire::write_be64(&rebuilt.bytes[8], m1);
                    rebuilt.bytes[16] = static_cast<uint8_t>((hi24 >> 16U) & 0xFFU);
                    rebuilt.bytes[17] = static_cast<uint8_t>((hi24 >> 8U) & 0xFFU);
                    rebuilt.bytes[18] = static_cast<uint8_t>(hi24 & 0xFFU);
                    if (hdr.op == arena::wire::BaseOp::RegisterSessionKey &&
                        (rebuilt.bytes[51U] & arena::wire::WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0U) {
                        const uint64_t old_salt64 = arena::wire::read_be64(&rebuilt.bytes[41]);
                        if (old_salt64 == 0ULL) {
                            return false;
                        }
                        uint64_t old_pad_lo = 0ULL;
                        uint64_t old_pad_hi = 0ULL;
                        arena::wire::compute_session_key_wrap_pad(
                            key_lo64_, key_hi64_, old_hi50, old_seq, hdr.account_id, old_salt64, old_pad_lo, old_pad_hi
                        );
                        const uint64_t new_k_lo   = raw_aux0 ^ old_pad_lo;
                        const uint64_t new_k_hi   = raw_aux1 ^ old_pad_hi;
                        const uint64_t new_salt64 = detail::sdk_csprng_u64_nonzero();
                        if (new_salt64 == 0ULL) {
                            return false;
                        }
                        uint64_t new_pad_lo = 0ULL;
                        uint64_t new_pad_hi = 0ULL;
                        arena::wire::compute_session_key_wrap_pad(
                            key_lo64_, key_hi64_, new_hi50, new_seq, hdr.account_id, new_salt64, new_pad_lo, new_pad_hi
                        );
                        arena::wire::write_be64(&rebuilt.bytes[25], new_k_lo ^ new_pad_lo);
                        arena::wire::write_be64(&rebuilt.bytes[33], new_k_hi ^ new_pad_hi);
                        arena::wire::write_be64(&rebuilt.bytes[41], new_salt64);
                    }
                    const uint64_t new_pre40 =
                        arena::wire::calc_pre_siphash40(hdr, new_hi50, key_lo64_, key_hi64_);
                    rebuilt.bytes[19] = static_cast<uint8_t>((new_pre40 >> 32U) & 0xFFULL);
                    rebuilt.bytes[20] = static_cast<uint8_t>((new_pre40 >> 24U) & 0xFFULL);
                    rebuilt.bytes[21] = static_cast<uint8_t>((new_pre40 >> 16U) & 0xFFULL);
                    rebuilt.bytes[22] = static_cast<uint8_t>((new_pre40 >> 8U) & 0xFFULL);
                    rebuilt.bytes[23] = static_cast<uint8_t>(new_pre40 & 0xFFULL);
                    rebuilt.set_tail_siphash48(
                        arena::wire::calc_tail_siphash48(rebuilt.bytes, new_hi50, key_lo64_, key_hi64_)
                    );
                    if (!send_frame_once(rebuilt, resp_out)) {
                        return false;
                    }
                    if (resp_out.status_code != arena::wire::WireStatusCode::RejectInvalidMac &&
                        resp_out.status_code != arena::wire::WireStatusCode::RejectReplayOrStale) {
                        verified_seq_by_account_[seq_acct] = true;
                        tried_resync_hi50_                 = false;
                    }
                    return true;
                }
            }
        }
        return true;
    }

    bool send_batch(
        const std::vector<arena::wire::ArenaWireFrame>& reqs,
        std::vector<arena::wire::ArenaWireResponse>&    resps_out,
        uint32_t                                        timeout_ms = 5'000U
    ) {
        resps_out.clear();
        if (reqs.empty()) return true;
        for (const auto& req : reqs) {
            if (!is_valid_frame(req)) return false;
        }
        if (tcp_sock_ == detail::SDK_INVALID_SOCK) return false;

        const std::size_t total_bytes = reqs.size() * 64U;
        std::vector<uint8_t> tx_raw(total_bytes);
        std::vector<uint8_t> rx_raw(total_bytes);
        for (std::size_t i = 0U; i < reqs.size(); ++i) {
            std::memcpy(tx_raw.data() + i * 64U, reqs[i].bytes.data(), 64U);
        }

        if (!detail::sdk_set_nonblocking(tcp_sock_, true)) {
            return false;
        }

        std::size_t    tx_off   = 0U;
        std::size_t    rx_off   = 0U;
        const uint64_t deadline = detail::sdk_steady_ms() + timeout_ms;
        bool           ok       = true;

        while (tx_off < total_bytes || rx_off < total_bytes) {
            bool progress = false;
            if (tx_off < total_bytes) {
                const int chunk = static_cast<int>(std::min<std::size_t>(total_bytes - tx_off, 65'536U));
                int n = 0;
                do {
                    n = ::send(
                        tcp_sock_,
                        reinterpret_cast<const char*>(tx_raw.data() + tx_off),
                        chunk,
                        detail::SDK_SEND_FLAGS
                    );
                } while (n < 0 && detail::sdk_is_eintr());
                if (n > 0) {
                    tx_off  += static_cast<std::size_t>(n);
                    progress = true;
                } else if (n <= 0 && !detail::sdk_would_block()) {
                    ok = false;
                    break;
                }
            }
            if (rx_off < total_bytes) {
                const int chunk = static_cast<int>(std::min<std::size_t>(total_bytes - rx_off, 65'536U));
                int n = 0;
                do {
                    n = ::recv(
                        tcp_sock_,
                        reinterpret_cast<char*>(rx_raw.data() + rx_off),
                        chunk,
                        0
                    );
                } while (n < 0 && detail::sdk_is_eintr());
                if (n > 0) {
                    rx_off  += static_cast<std::size_t>(n);
                    progress = true;
                } else if (n == 0 || (n < 0 && !detail::sdk_would_block())) {
                    ok = false;
                    break;
                }
            }
            if (!progress) {
                if (detail::sdk_steady_ms() >= deadline) {
                    ok = false;
                    break;
                }
#ifdef _WIN32
                WSAPOLLFD pfd{};
                pfd.fd     = tcp_sock_;
                pfd.events = static_cast<SHORT>(
                    ((rx_off < total_bytes) ? POLLRDNORM : 0) |
                    ((tx_off < total_bytes) ? POLLWRNORM : 0)
                );
                (void)::WSAPoll(&pfd, 1UL, 1);
#else
                if (tcp_sock_ < 0) {
                    ok = false;
                    break;
                }
                pollfd pfd{};
                pfd.fd     = tcp_sock_;
                pfd.events = static_cast<short>(
                    ((rx_off < total_bytes) ? POLLIN : 0) |
                    ((tx_off < total_bytes) ? POLLOUT : 0)
                );
                (void)::poll(&pfd, 1U, 1);
#endif
            }
        }

        (void)detail::sdk_set_nonblocking(tcp_sock_, false);
        if (!ok) {
            if (tx_off > 0U) {
                for (std::size_t i = 0U; i < reqs.size() && i * 64U < tx_off; ++i) {
                    arena::wire::ArenaHeader h_tx{};
                    uint64_t m_tx = 0ULL, a0_tx = 0ULL, a1_tx = 0ULL;
                    arena::wire::unpack_wire_frame(reqs[i], h_tx, m_tx, a0_tx, a1_tx);
                    if (!is_non_mutating_op(h_tx.op)) {
                        ambiguous_disconnect_by_account_[seq_bucket_account(h_tx.account_id)] = true;
                    }
                }
            }
            disconnect_tcp();
            return false;
        }

        resps_out.resize(reqs.size());
        for (std::size_t i = 0U; i < reqs.size(); ++i) {
            std::array<uint8_t, 64> raw64{};
            std::memcpy(raw64.data(), rx_raw.data() + i * 64U, 64U);
            resps_out[i] = arena::wire::ArenaWireResponse::unpack_bytes(raw64);
        }

        const bool uses_provisioned_key =
            (key_lo64_ != DEFAULT_DEV_KEY_LO64 || key_hi64_ != DEFAULT_DEV_KEY_HI64);
        if (!resps_out.empty() &&
            !resyncing_hi50_ &&
            !tried_resync_hi50_) {
            bool contiguous_in_batch = true;
            std::unordered_map<uint32_t, uint16_t> last_seq_by_acct{};
            std::unordered_map<uint32_t, bool>     saw_max_seq_by_acct{};
            std::unordered_map<uint32_t, bool>     wrapped_in_batch{};
            for (const auto& req_f : reqs) {
                arena::wire::ArenaHeader h_f{};
                uint64_t m_f = 0ULL, a0_f = 0ULL, a1_f = 0ULL;
                arena::wire::unpack_wire_frame(req_f, h_f, m_f, a0_f, a1_f);
                const uint32_t seq_acct_f = uses_provisioned_key ? seq_bucket_account(h_f.account_id) : h_f.account_id;
                const auto it_prev = last_seq_by_acct.find(seq_acct_f);
                if (it_prev != last_seq_by_acct.end() &&
                    h_f.seq_lo != static_cast<uint16_t>((it_prev->second + 1U) & 0x3FFFU)) {
                    contiguous_in_batch = false;
                }
                if (saw_max_seq_by_acct[seq_acct_f] && h_f.seq_lo == 0U) {
                    wrapped_in_batch[seq_acct_f] = true;
                }
                if (h_f.seq_lo == 0x3FFFU) {
                    saw_max_seq_by_acct[seq_acct_f] = true;
                }
                last_seq_by_acct[seq_acct_f] = h_f.seq_lo;
            }
            bool all_pre_exec_auth_or_seq_rejects = contiguous_in_batch;
            std::vector<std::pair<uint32_t, bool>> accts_to_sync;
            for (std::size_t i = 0U; i < resps_out.size(); ++i) {
                const auto& r = resps_out[i];
                arena::wire::ArenaHeader h_i{};
                uint64_t mac_i = 0ULL, a0_i = 0ULL, a1_i = 0ULL;
                arena::wire::unpack_wire_frame(reqs[i], h_i, mac_i, a0_i, a1_i);
                const uint32_t seq_acct_i = uses_provisioned_key ? seq_bucket_account(h_i.account_id) : h_i.account_id;
                if (r.status_code != arena::wire::WireStatusCode::RejectInvalidMac &&
                    r.status_code != arena::wire::WireStatusCode::RejectReplayOrStale) {
                    all_pre_exec_auth_or_seq_rejects = false;
                    verified_seq_by_account_[seq_acct_i] = true;
                    tried_resync_hi50_                   = false;
                    continue;
                }
                if (!uses_provisioned_key ||
                    peek_next_seq_lo(seq_acct_i) !=
                        static_cast<uint16_t>((last_seq_by_acct[seq_acct_i] + 1U) & 0x3FFFU)) {
                    all_pre_exec_auth_or_seq_rejects = false;
                    continue;
                }
                if (r.status_code == arena::wire::WireStatusCode::RejectReplayOrStale &&
                    verified_seq_by_account_[seq_acct_i]) {
                    all_pre_exec_auth_or_seq_rejects = false;
                    continue;
                }
                const auto it_h = seq_hi50_by_account_.find(seq_acct_i);
                const uint64_t cand_hi50 = (it_h != seq_hi50_by_account_.end()) ? it_h->second : default_init_seq_hi50_;
                const bool match_cur =
                    (mac_i == arena::wire::calc_pre_siphash40(h_i, cand_hi50, key_lo64_, key_hi64_));
                const bool match_prev =
                    (!match_cur && wrapped_in_batch[seq_acct_i] && cand_hi50 > 0ULL &&
                     mac_i == arena::wire::calc_pre_siphash40(h_i, cand_hi50 - 1ULL, key_lo64_, key_hi64_));
                const uint64_t used_hi50 = match_prev ? (cand_hi50 - 1ULL) : cand_hi50;
                const bool mac_ok =
                    (match_cur || match_prev) &&
                    (reqs[i].get_tail_siphash48() ==
                     arena::wire::calc_tail_siphash48(reqs[i].bytes, used_hi50, key_lo64_, key_hi64_));
                if (!mac_ok) {
                    all_pre_exec_auth_or_seq_rejects = false;
                    continue;
                }
                const bool need_bump = (r.status_code == arena::wire::WireStatusCode::RejectReplayOrStale);
                bool found_a = false;
                for (auto& kv : accts_to_sync) {
                    if (kv.first == seq_acct_i) {
                        kv.second = kv.second || need_bump;
                        found_a = true;
                        break;
                    }
                }
                if (!found_a) {
                    accts_to_sync.emplace_back(seq_acct_i, need_bump);
                }
            }
            if (all_pre_exec_auth_or_seq_rejects && !accts_to_sync.empty()) {
                const uint64_t pre_sync_default_hi50 = default_init_seq_hi50_;
                const auto     pre_sync_hi50_map     = seq_hi50_by_account_;
                const auto     pre_sync_verified_map = verified_seq_by_account_;
                tried_resync_hi50_ = true;
                resyncing_hi50_    = true;
                bool synced        = true;
                for (const auto& [acct_id, bump_h] : accts_to_sync) {
                    arena::wire::ArenaWireResponse sync_resp{};
                    if (!sync_sequence_for_account(acct_id, sync_resp, bump_h) ||
                        sync_resp.status_code != arena::wire::WireStatusCode::Ok) {
                        synced = false;
                        break;
                    }
                }
                resyncing_hi50_ = false;
                if (synced) {
                    bool batch_may_auto_resubmit = true;
                    for (std::size_t idx_chk = 0U; idx_chk < reqs.size(); ++idx_chk) {
                        const auto& orig_chk = reqs[idx_chk];
                        arena::wire::ArenaHeader h_chk{};
                        uint64_t m_chk = 0ULL, a0_chk = 0ULL, a1_chk = 0ULL;
                        arena::wire::unpack_wire_frame(orig_chk, h_chk, m_chk, a0_chk, a1_chk);
                        const uint32_t chk_seq_acct = uses_provisioned_key ? seq_bucket_account(h_chk.account_id) : h_chk.account_id;
                        const auto     it_ver       = pre_sync_verified_map.find(chk_seq_acct);
                        const bool     was_unver    = (it_ver == pre_sync_verified_map.end() || !it_ver->second);
                        const bool     is_unver_mac =
                            (resps_out[idx_chk].status_code == arena::wire::WireStatusCode::RejectInvalidMac) &&
                            was_unver;
                        const bool frame_ok =
                            is_non_mutating_op(h_chk.op) ||
                            (!has_ambiguous_disconnect(h_chk.account_id) &&
                             (auto_retry_mutating_on_resync_ || is_unver_mac));
                        if (!frame_ok) {
                            batch_may_auto_resubmit = false;
                            break;
                        }
                    }
                    if (!batch_may_auto_resubmit) {
                        return true;
                    }
                    std::vector<arena::wire::ArenaWireFrame> rebuilt_reqs;
                    rebuilt_reqs.reserve(reqs.size());
                    for (const auto& orig : reqs) {
                        arena::wire::ArenaHeader hdr{};
                        uint64_t rx_mac40 = 0ULL;
                        uint64_t raw_aux0 = 0ULL;
                        uint64_t raw_aux1 = 0ULL;
                        arena::wire::unpack_wire_frame(orig, hdr, rx_mac40, raw_aux0, raw_aux1);
                        const uint32_t seq_acct_o = uses_provisioned_key ? seq_bucket_account(hdr.account_id) : hdr.account_id;
                        const auto it_old = pre_sync_hi50_map.find(seq_acct_o);
                        uint64_t old_hi50 = (it_old != pre_sync_hi50_map.end()) ? it_old->second : pre_sync_default_hi50;
                        if (old_hi50 > 0ULL &&
                            arena::wire::calc_pre_siphash40(hdr, old_hi50, key_lo64_, key_hi64_) != rx_mac40 &&
                            arena::wire::calc_pre_siphash40(hdr, old_hi50 - 1ULL, key_lo64_, key_hi64_) == rx_mac40) {
                            old_hi50 -= 1ULL;
                        }
                        const uint16_t old_seq  = hdr.seq_lo;
                        uint16_t       new_seq  = 0U;
                        uint64_t       new_hi50 = seq_hi50_;
                        allocate_seq_for_frame(hdr.account_id, new_seq, new_hi50);
                        hdr.seq_lo = new_seq;
                        arena::wire::ArenaWireFrame rebuilt = orig;
                        uint64_t m0   = 0ULL;
                        uint64_t m1   = 0ULL;
                        uint32_t hi24 = 0U;
                        hdr.pack_words(m0, m1, hi24);
                        arena::wire::write_be64(&rebuilt.bytes[0], m0);
                        arena::wire::write_be64(&rebuilt.bytes[8], m1);
                        rebuilt.bytes[16] = static_cast<uint8_t>((hi24 >> 16U) & 0xFFU);
                        rebuilt.bytes[17] = static_cast<uint8_t>((hi24 >> 8U) & 0xFFU);
                        rebuilt.bytes[18] = static_cast<uint8_t>(hi24 & 0xFFU);
                        if (hdr.op == arena::wire::BaseOp::RegisterSessionKey &&
                            (rebuilt.bytes[51U] & arena::wire::WIRE_EXT51_FLAG_ENCRYPTED_KEY_WRAP) != 0U) {
                            const uint64_t old_salt64 = arena::wire::read_be64(&rebuilt.bytes[41]);
                            if (old_salt64 == 0ULL) {
                                return false;
                            }
                            uint64_t old_pad_lo = 0ULL;
                            uint64_t old_pad_hi = 0ULL;
                            arena::wire::compute_session_key_wrap_pad(
                                key_lo64_, key_hi64_, old_hi50, old_seq, hdr.account_id, old_salt64, old_pad_lo, old_pad_hi
                            );
                            const uint64_t new_k_lo   = raw_aux0 ^ old_pad_lo;
                            const uint64_t new_k_hi   = raw_aux1 ^ old_pad_hi;
                            const uint64_t new_salt64 = detail::sdk_csprng_u64_nonzero();
                            if (new_salt64 == 0ULL) {
                                return false;
                            }
                            uint64_t new_pad_lo = 0ULL;
                            uint64_t new_pad_hi = 0ULL;
                            arena::wire::compute_session_key_wrap_pad(
                                key_lo64_, key_hi64_, new_hi50, new_seq, hdr.account_id, new_salt64, new_pad_lo, new_pad_hi
                            );
                            arena::wire::write_be64(&rebuilt.bytes[25], new_k_lo ^ new_pad_lo);
                            arena::wire::write_be64(&rebuilt.bytes[33], new_k_hi ^ new_pad_hi);
                            arena::wire::write_be64(&rebuilt.bytes[41], new_salt64);
                        }
                        const uint64_t new_pre40 =
                            arena::wire::calc_pre_siphash40(hdr, new_hi50, key_lo64_, key_hi64_);
                        rebuilt.bytes[19] = static_cast<uint8_t>((new_pre40 >> 32U) & 0xFFULL);
                        rebuilt.bytes[20] = static_cast<uint8_t>((new_pre40 >> 24U) & 0xFFULL);
                        rebuilt.bytes[21] = static_cast<uint8_t>((new_pre40 >> 16U) & 0xFFULL);
                        rebuilt.bytes[22] = static_cast<uint8_t>((new_pre40 >> 8U) & 0xFFULL);
                        rebuilt.bytes[23] = static_cast<uint8_t>(new_pre40 & 0xFFULL);
                        rebuilt.set_tail_siphash48(
                            arena::wire::calc_tail_siphash48(rebuilt.bytes, new_hi50, key_lo64_, key_hi64_)
                        );
                        rebuilt_reqs.push_back(rebuilt);
                    }
                    return send_batch(rebuilt_reqs, resps_out, timeout_ms);
                }
            }
        } else {
            for (std::size_t i = 0U; i < resps_out.size(); ++i) {
                if (resps_out[i].status_code != arena::wire::WireStatusCode::RejectInvalidMac &&
                    resps_out[i].status_code != arena::wire::WireStatusCode::RejectReplayOrStale) {
                    arena::wire::ArenaHeader h_i{};
                    uint64_t mac_i = 0ULL, a0_i = 0ULL, a1_i = 0ULL;
                    arena::wire::unpack_wire_frame(reqs[i], h_i, mac_i, a0_i, a1_i);
                    const uint32_t seq_acct_i = uses_provisioned_key ? seq_bucket_account(h_i.account_id) : h_i.account_id;
                    verified_seq_by_account_[seq_acct_i] = true;
                    tried_resync_hi50_                   = false;
                }
            }
        }
        return true;
    }

    static bool send_udp(
        uint16_t                           port,
        const arena::wire::ArenaWireFrame& req,
        arena::wire::ArenaWireResponse&    resp_out,
        const char*                        host          = "127.0.0.1",
        uint32_t                           io_timeout_ms = 2'500U
    ) noexcept {
        if (!is_valid_frame(req)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        detail::ensure_winsock_initialized();
        detail::SdkSocketHandle s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == detail::SDK_INVALID_SOCK) return false;
        detail::sdk_apply_io_timeout(s, io_timeout_ms);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (port == 0U || !detail::sdk_resolve_ipv4_host(host, addr.sin_addr)) {
            detail::sdk_close_socket(s);
            return false;
        }
        int sent = 0;
        do {
            sent = ::sendto(
                s,
                reinterpret_cast<const char*>(req.bytes.data()),
                64,
                0,
                reinterpret_cast<const sockaddr*>(&addr),
                sizeof(addr)
            );
        } while (sent < 0 && detail::sdk_is_eintr());
        if (sent != 64) {
            detail::sdk_close_socket(s);
            return false;
        }

        const uint32_t eff_timeout_ms = (io_timeout_ms > 0U) ? io_timeout_ms : 2'500U;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(eff_timeout_ms);
        std::array<uint8_t, 64> rx_buf{};
        int recvd = -1;
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                recvd = -1;
                break;
            }
            const long long rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            detail::sdk_apply_io_timeout(
                s, static_cast<uint32_t>(std::max<long long>(1LL, rem_ms))
            );
            sockaddr_in from_addr{};
#ifdef _WIN32
            int from_len = sizeof(from_addr);
#else
            socklen_t from_len = sizeof(from_addr);
#endif
            recvd = ::recvfrom(
                s,
                reinterpret_cast<char*>(rx_buf.data()),
                64,
                0,
                reinterpret_cast<sockaddr*>(&from_addr),
                &from_len
            );
            if (recvd < 0 && detail::sdk_is_eintr()) {
                continue;
            }
            if (recvd < 0) {
                break;
            }
            if (from_len != static_cast<decltype(from_len)>(sizeof(from_addr)) ||
                from_addr.sin_family != AF_INET ||
                from_addr.sin_addr.s_addr != addr.sin_addr.s_addr ||
                from_addr.sin_port != addr.sin_port) {
                recvd = -1;
                continue;
            }
            break;
        }
        detail::sdk_close_socket(s);
        if (recvd != 64) return false;
        resp_out = arena::wire::ArenaWireResponse::unpack_bytes(rx_buf);
        return true;
    }

    // -------------------------------------------------------------------------
    // Ergonomic Trading, Quoting, Risk & Session Helpers
    // -------------------------------------------------------------------------
    bool submit_order(
        uint16_t                        market_id,
        arena::wire::OrderSide          side,
        int64_t                         price_ticks,
        uint64_t                        qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        arena::wire::TimeInForce        tif                   = arena::wire::TimeInForce::GTC,
        arena::wire::StpMode            stp                   = arena::wire::StpMode::CancelResting,
        uint64_t                        client_tag            = 0ULL,
        bool                            reduce_only           = false,
        bool                            is_market             = false,
        bool                            cancel_on_disconnect  = false,
        bool                            post_only_slide       = false,
        uint64_t                        min_qty_lots          = 0ULL,
        bool                            primary_peg           = false,
        bool                            midpoint_peg          = false,
        bool                            margin_spot           = false,
        uint64_t                        display_qty_lots      = 0ULL,
        bool                            dark_midpoint         = false,
        int16_t                         auto_skew_ticks       = 0,
        int16_t                         peg_offset_ticks      = 0,
        bool                            oco_linked            = false,
        uint16_t                        max_lifetime_wal_seqs = 0U,
        uint8_t                         jit_elastic_mult         = 0U,
        bool                            mark_peg                 = false,
        int16_t                         auto_flip_ticks          = 0,
        bool                            trailing_peg             = false,
        bool                            stp_decrement_and_cancel = false,
        uint16_t                        priority_fee_ppm         = 0U
    ) noexcept {
        return send_frame(
            build_order_frame(
                market_id, side, price_ticks, qty_lots, tif, stp,
                client_tag, reduce_only, is_market, cancel_on_disconnect,
                post_only_slide, min_qty_lots, primary_peg, midpoint_peg, margin_spot, display_qty_lots,
                dark_midpoint, auto_skew_ticks, peg_offset_ticks, oco_linked, max_lifetime_wal_seqs,
                jit_elastic_mult, mark_peg, auto_flip_ticks, trailing_peg, stp_decrement_and_cancel,
                priority_fee_ppm
            ),
            resp_out
        );
    }

    bool cancel_order(uint16_t market_id, uint64_t order_id, arena::wire::ArenaWireResponse& resp_out) noexcept {
        return send_frame(build_cancel_frame(market_id, order_id), resp_out);
    }

    bool modify_in_place(
        uint16_t                        market_id,
        uint64_t                        order_id,
        int64_t                         new_price_ticks,
        uint64_t                        new_qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        bool                            keep_priority = false
    ) noexcept {
        return send_frame(build_modify_frame(market_id, order_id, new_price_ticks, new_qty_lots, keep_priority), resp_out);
    }

    bool cancel_all(
        uint16_t                        market_id,
        arena::wire::ArenaWireResponse& resp_out,
        uint64_t                        client_tag_filter = 0ULL,
        uint64_t                        market_bitmask    = 0ULL,
        uint8_t                         side_filter       = 0U
    ) noexcept {
        if ((client_tag_filter & ~arena::wire::CANCEL_ALL_TAG_MASK) != 0ULL ||
            side_filter > 2U) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        uint64_t aux0 = client_tag_filter & arena::wire::CANCEL_ALL_TAG_MASK;
        if (side_filter == 1U) {
            aux0 |= arena::wire::CANCEL_ALL_FLAG_BID_ONLY;
        } else if (side_filter == 2U) {
            aux0 |= arena::wire::CANCEL_ALL_FLAG_ASK_ONLY;
        }
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::CancelAllAccount,
                market_id,
                arena::wire::OrderSide::Bid,
                0LL,
                0ULL,
                arena::wire::TimeInForce::GTC,
                arena::wire::StpMode::CancelResting,
                aux0,
                market_bitmask
            ),
            resp_out
        );
    }

    bool two_sided_quote_replace(
        uint16_t                        market_id,
        int64_t                         bid_price_ticks,
        uint64_t                        bid_qty_lots,
        int64_t                         ask_price_ticks,
        uint64_t                        ask_qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        arena::wire::TimeInForce        tif                   = arena::wire::TimeInForce::PostOnly,
        arena::wire::StpMode            stp                   = arena::wire::StpMode::CancelResting,
        bool                            cancel_on_disconnect  = false,
        bool                            post_only_slide       = false,
        bool                            margin_spot           = false,
        int16_t                         auto_skew_ticks       = 0,
        bool                            oco_linked            = false,
        uint16_t                        max_lifetime_wal_seqs = 0U,
        uint8_t                         jit_elastic_mult      = 0U,
        int16_t                         auto_flip_ticks       = 0,
        uint8_t                         quote_peg_mode        = 0U,
        int16_t                         peg_offset_ticks      = 0,
        uint64_t                        client_tag            = 0ULL,
        bool                            ladder_by_tag         = false
    ) noexcept {
        return send_frame(
            build_quote_frame(
                market_id, bid_price_ticks, bid_qty_lots, ask_price_ticks, ask_qty_lots,
                tif, stp, cancel_on_disconnect, post_only_slide, margin_spot,
                auto_skew_ticks, oco_linked, max_lifetime_wal_seqs, jit_elastic_mult, auto_flip_ticks,
                quote_peg_mode, peg_offset_ticks, client_tag, ladder_by_tag
            ),
            resp_out
        );
    }

    bool set_cancel_on_disconnect(
        uint16_t                        market_id,
        bool                            enable,
        uint32_t                        timeout_ms,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::SetCancelOnDisconnect,
                market_id,
                arena::wire::OrderSide::Bid,
                0LL,
                0ULL,
                arena::wire::TimeInForce::GTC,
                arena::wire::StpMode::CancelResting,
                enable ? 1ULL : 0ULL,
                static_cast<uint64_t>(timeout_ms)
            ),
            resp_out
        );
    }

    bool query_bbo(uint16_t market_id, arena::wire::ArenaWireResponse& resp_out) noexcept {
        return send_frame(build_raw_frame(arena::wire::BaseOp::QueryBookBbo, market_id), resp_out);
    }

    bool query_account(uint16_t market_id, arena::wire::ArenaWireResponse& resp_out) noexcept {
        return send_frame(build_raw_frame(arena::wire::BaseOp::QueryAccount, market_id), resp_out);
    }

    bool deposit_usd(int64_t amount_micro, arena::wire::ArenaWireResponse& resp_out) noexcept {
        if (amount_micro <= 0LL) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::DepositCollateral, 0U, arena::wire::OrderSide::Bid,
                0LL, 0ULL, arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting,
                0ULL, static_cast<uint64_t>(amount_micro)
            ),
            resp_out
        );
    }

    bool deposit_base(uint16_t asset_id, uint64_t lots, arena::wire::ArenaWireResponse& resp_out) noexcept {
        if (asset_id == 0U || lots == 0ULL || lots > 0x7FFF'FFFF'FFFF'FFFFULL) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::DepositCollateral, 0U, arena::wire::OrderSide::Bid,
                0LL, 0ULL, arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting,
                static_cast<uint64_t>(asset_id), lots
            ),
            resp_out
        );
    }

    bool withdraw_usd(int64_t amount_micro, arena::wire::ArenaWireResponse& resp_out) noexcept {
        if (amount_micro <= 0LL) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::WithdrawCollateral, 0U, arena::wire::OrderSide::Bid,
                0LL, 0ULL, arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting,
                0ULL, static_cast<uint64_t>(amount_micro)
            ),
            resp_out
        );
    }

    bool withdraw_base(uint16_t asset_id, uint64_t lots, arena::wire::ArenaWireResponse& resp_out) noexcept {
        if (asset_id == 0U || lots == 0ULL || lots > 0x7FFF'FFFF'FFFF'FFFFULL) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(
            build_raw_frame(
                arena::wire::BaseOp::WithdrawCollateral, 0U, arena::wire::OrderSide::Bid,
                0LL, 0ULL, arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting,
                static_cast<uint64_t>(asset_id), lots
            ),
            resp_out
        );
    }

    [[nodiscard]] arena::wire::ArenaWireFrame build_liquidate_account_frame(
        uint16_t             market_id,
        uint32_t             target_account_id,
        uint64_t             partial_lots          = 0ULL,
        bool                 allow_l3_offload      = true,
        arena::wire::StpMode stp                   = arena::wire::StpMode::CancelResting,
        bool                 hedge_margin_spot     = false,
        uint16_t             bounty_rebate_bid_bps = 0U
    ) noexcept {
        if (bounty_rebate_bid_bps > arena::wire::MAX_LIQ_BOUNTY_REBATE_BID_BPS ||
            (bounty_rebate_bid_bps > 0U && target_account_id == account_id_)) {
            return arena::wire::ArenaWireFrame{};
        }
        uint64_t aux1 = 0ULL;
        if (!allow_l3_offload) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_NO_OFFLOAD;
        }
        if (hedge_margin_spot) {
            aux1 |= arena::wire::LIQ_AUX1_FLAG_HEDGE_MARGIN_SPOT;
        }
        auto frm = build_raw_frame(
            arena::wire::BaseOp::LiquidateAccount,
            market_id,
            arena::wire::OrderSide::Bid,
            0LL,
            partial_lots,
            allow_l3_offload ? arena::wire::TimeInForce::IOC : arena::wire::TimeInForce::GTC,
            stp,
            static_cast<uint64_t>(target_account_id),
            aux1
        );
        if (bounty_rebate_bid_bps > 0U && is_valid_frame(frm)) {
            arena::wire::pack_wire_liq_bounty_rebate_bid_bps(
                frm, bounty_rebate_bid_bps, last_built_seq_hi50_, key_lo64_, key_hi64_
            );
        }
        return frm;
    }

    bool liquidate_account(
        uint16_t                        market_id,
        uint32_t                        target_account_id,
        arena::wire::ArenaWireResponse& resp_out,
        uint64_t                        partial_lots          = 0ULL,
        bool                            allow_l3_offload      = true,
        arena::wire::StpMode            stp                   = arena::wire::StpMode::CancelResting,
        bool                            hedge_margin_spot     = false,
        uint16_t                        bounty_rebate_bid_bps = 0U
    ) noexcept {
        const auto frm = build_liquidate_account_frame(
            market_id,
            target_account_id,
            partial_lots,
            allow_l3_offload,
            stp,
            hedge_margin_spot,
            bounty_rebate_bid_bps
        );
        if (!is_valid_frame(frm)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(frm, resp_out);
    }

    bool set_position_knockout(
        uint16_t                        market_id,
        int64_t                         knockout_price_ticks,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(build_knockout_frame(market_id, knockout_price_ticks), resp_out);
    }

    bool set_account_drawdown_stop(
        int64_t                         stop_equity_usd_micro,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(build_drawdown_stop_frame(stop_equity_usd_micro), resp_out);
    }

    bool rotate_session_key(
        uint64_t                        new_key_lo64,
        uint64_t                        new_key_hi64,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        if (!is_valid_wire_account_id_24(account_id_)) {
            return false;
        }
        const uint64_t wrap_salt64 = detail::sdk_csprng_u64_nonzero();
        if (wrap_salt64 == 0ULL) {
            return false;
        }
        uint16_t frame_seq  = 0U;
        uint64_t frame_hi50 = seq_hi50_;
        allocate_seq_for_frame(account_id_, frame_seq, frame_hi50);
        const auto req = arena::wire::pack_encrypted_register_session_key_frame(
            account_id_,
            frame_seq,
            frame_hi50,
            key_lo64_,
            key_hi64_,
            new_key_lo64,
            new_key_hi64,
            wrap_salt64
        );
        if (!is_valid_frame(req) || !send_frame(req, resp_out)) return false;
        if (resp_out.status_code == arena::wire::WireStatusCode::Ok) {
            key_lo64_                          = new_key_lo64;
            key_hi64_                          = new_key_hi64;
            const uint32_t seq_acct            = seq_bucket_account(account_id_);
            cred_key_by_account_[seq_acct]     = {new_key_lo64, new_key_hi64};
            if (resp_out.resting_lots > 0ULL) {
                const uint64_t new_hi50                 = resp_out.resting_lots & ((1ULL << 50U) - 1ULL);
                seq_hi50_by_account_[seq_acct]          = new_hi50;
                seq_hi50_                               = new_hi50;
                next_seq_by_account_[seq_acct]          = 1U;
                pending_hi50_wrap_by_account_[seq_acct] = false;
                verified_seq_by_account_[seq_acct]      = true;
                tried_resync_hi50_                      = false;
            } else {
                verified_seq_by_account_[seq_acct]      = false;
                tried_resync_hi50_                      = false;
            }
            const uint64_t saved_hi = seq_hi50_by_account_.count(seq_acct) > 0U
                ? seq_hi50_by_account_[seq_acct]
                : default_init_seq_hi50_;
            const uint16_t saved_ns = next_seq_by_account_.count(seq_acct) > 0U
                ? next_seq_by_account_[seq_acct]
                : default_init_seq_lo_;
            const bool saved_pw = pending_hi50_wrap_by_account_.count(seq_acct) > 0U
                ? pending_hi50_wrap_by_account_[seq_acct]
                : false;
            saved_cred_seq_state_[{seq_acct, key_lo64_, key_hi64_}] =
                SavedCredSeqState{saved_hi, saved_ns, saved_pw};
        }
        return true;
    }

    bool heartbeat(arena::wire::ArenaWireResponse& resp_out) noexcept {
        return send_frame(build_raw_frame(arena::wire::BaseOp::Heartbeat), resp_out);
    }

    bool sync_sequence_for_account(
        uint32_t                        synced_acct,
        arena::wire::ArenaWireResponse& resp_out,
        bool                            bump_hi50 = false
    ) noexcept {
        if (!is_valid_wire_account_id_24(synced_acct)) {
            return false;
        }
        const auto raw_now_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        const uint32_t seq_acct        = seq_bucket_account(synced_acct);
        const auto     orig_hi_it      = seq_hi50_by_account_.find(seq_acct);
        const bool     had_hi          = (orig_hi_it != seq_hi50_by_account_.end());
        const uint64_t orig_hi         = had_hi ? orig_hi_it->second : 0ULL;
        const auto     orig_ns_it      = next_seq_by_account_.find(seq_acct);
        const bool     had_ns          = (orig_ns_it != next_seq_by_account_.end());
        const uint16_t orig_ns         = had_ns ? orig_ns_it->second : 0U;
        const auto     orig_pw_it      = pending_hi50_wrap_by_account_.find(seq_acct);
        const bool     had_pw          = (orig_pw_it != pending_hi50_wrap_by_account_.end());
        const bool     orig_pw         = had_pw ? orig_pw_it->second : false;
        const auto     orig_vf_it      = verified_seq_by_account_.find(seq_acct);
        const bool     had_vf          = (orig_vf_it != verified_seq_by_account_.end());
        const bool     orig_vf         = had_vf ? orig_vf_it->second : false;
        const uint64_t orig_main_hi50  = seq_hi50_;
        auto rollback_seq_state        = [&]() noexcept {
            if (had_hi) seq_hi50_by_account_[seq_acct] = orig_hi;
            else seq_hi50_by_account_.erase(seq_acct);
            if (had_ns) next_seq_by_account_[seq_acct] = orig_ns;
            else next_seq_by_account_.erase(seq_acct);
            if (had_pw) pending_hi50_wrap_by_account_[seq_acct] = orig_pw;
            else pending_hi50_wrap_by_account_.erase(seq_acct);
            if (had_vf) verified_seq_by_account_[seq_acct] = orig_vf;
            else verified_seq_by_account_.erase(seq_acct);
            seq_hi50_ = orig_main_hi50;
        };

        const uint64_t now_us     = next_process_sync_nonce_us(raw_now_us);
        uint64_t sync_nonce       = std::max<uint64_t>(last_sync_nonce_ + 1ULL, now_us);
        if (sync_nonce > now_us) {
            sync_nonce = next_process_sync_nonce_us(sync_nonce);
        }
        last_sync_nonce_          = sync_nonce;
        uint16_t sync_seq_lo      = 0U;
        uint64_t pre_alloc_hi50   = default_init_seq_hi50_;
        if (const auto hit = seq_hi50_by_account_.find(seq_acct); hit != seq_hi50_by_account_.end()) {
            pre_alloc_hi50 = hit->second;
        }
        uint64_t cur_hi50         = seq_hi50_;
        allocate_seq_for_frame(seq_acct, sync_seq_lo, cur_hi50);
        const bool wrapped_on_alloc = (cur_hi50 != pre_alloc_hi50);
        constexpr uint64_t kHi50Mask = (1ULL << 50U) - 1ULL;
        const uint64_t try_hi50   = (bump_hi50 && !wrapped_on_alloc) ? ((cur_hi50 + 1ULL) & kHi50Mask) : cur_hi50;

        arena::wire::ArenaHeader sync_hdr{};
        sync_hdr.op         = arena::wire::BaseOp::Heartbeat;
        sync_hdr.flags      = arena::wire::ArenaFlags{arena::wire::TimeInForce::GTC, arena::wire::StpMode::CancelResting};
        sync_hdr.market_id  = 0U;
        sync_hdr.account_id = seq_acct;
        sync_hdr.side       = arena::wire::OrderSide::Bid;
        sync_hdr.seq_lo     = sync_seq_lo;

        const auto req = arena::wire::pack_wire_frame(
            sync_hdr,
            arena::wire::HEARTBEAT_AUX0_SYNC_SEQ,
            sync_nonce,
            try_hi50,
            key_lo64_,
            key_hi64_
        );
        if (!send_frame_once(req, resp_out)) {
            rollback_seq_state();
            return false;
        }
        if (resp_out.status_code == arena::wire::WireStatusCode::RejectInvalidMac && !bump_hi50) {
            const uint64_t alt_hi50 = wrapped_on_alloc ? pre_alloc_hi50 : ((cur_hi50 + 1ULL) & kHi50Mask);
            sync_nonce              = next_process_sync_nonce_us(last_sync_nonce_ + 1ULL);
            last_sync_nonce_        = sync_nonce;
            const auto bump_req = arena::wire::pack_wire_frame(
                sync_hdr,
                arena::wire::HEARTBEAT_AUX0_SYNC_SEQ,
                sync_nonce,
                alt_hi50,
                key_lo64_,
                key_hi64_
            );
            if (!send_frame_once(bump_req, resp_out)) {
                rollback_seq_state();
                return false;
            }
        }
        if (resp_out.status_code == arena::wire::WireStatusCode::RejectInvalidMac &&
            try_hi50 != DEFAULT_SEQ_HI50) {
            sync_nonce       = next_process_sync_nonce_us(last_sync_nonce_ + 1ULL);
            last_sync_nonce_ = sync_nonce;
            const auto fallback_req = arena::wire::pack_wire_frame(
                sync_hdr,
                arena::wire::HEARTBEAT_AUX0_SYNC_SEQ,
                sync_nonce,
                DEFAULT_SEQ_HI50,
                key_lo64_,
                key_hi64_
            );
            if (!send_frame_once(fallback_req, resp_out)) {
                rollback_seq_state();
                return false;
            }
        }
        if (resp_out.status_code == arena::wire::WireStatusCode::Ok) {
            const uint64_t synced_hi50        = resp_out.resting_lots & kHi50Mask;
            const uint16_t synced_last_seq_lo = static_cast<uint16_t>(resp_out.order_id & 0x3FFFU);
            const uint16_t next_seq_lo        = static_cast<uint16_t>((synced_last_seq_lo + 1U) & 0x3FFFU);
            const uint64_t next_hi50          = (synced_last_seq_lo == 0x3FFFU)
                                              ? ((synced_hi50 + 1ULL) & kHi50Mask)
                                              : synced_hi50;
            seq_hi50_by_account_[seq_acct]          = next_hi50;
            if (seq_acct == seq_bucket_account(account_id_)) {
                seq_hi50_ = next_hi50;
            }
            next_seq_by_account_[seq_acct]          = next_seq_lo;
            pending_hi50_wrap_by_account_[seq_acct] = false;
            verified_seq_by_account_[seq_acct]      = true;
            saved_cred_seq_state_[{seq_acct, key_lo64_, key_hi64_}] =
                SavedCredSeqState{next_hi50, next_seq_lo, false};
        } else {
            rollback_seq_state();
        }
        return true;
    }

    bool sync_sequence(arena::wire::ArenaWireResponse& resp_out) noexcept {
        tried_resync_hi50_ = false;
        return sync_sequence_for_account(account_id_, resp_out, false);
    }

    bool bind_builder_code(
        uint32_t                        builder_account_id,
        uint16_t                        builder_fee_share_bps,
        arena::wire::ArenaWireResponse& resp_out,
        uint32_t                        trader_account_id = 0U
    ) noexcept {
        return send_frame(
            build_bind_builder_frame(builder_account_id, builder_fee_share_bps, trader_account_id),
            resp_out
        );
    }

    bool configure_mmp(
        uint32_t                        window_wal_seqs,
        uint64_t                        max_fill_lots,
        uint64_t                        max_delta_lots,
        uint32_t                        cooldown_wal_seqs,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_configure_mmp_frame(window_wal_seqs, max_fill_lots, max_delta_lots, cooldown_wal_seqs),
            resp_out
        );
    }

    bool configure_payout_preferences(
        uint16_t                        payout_asset_id,
        uint8_t                         payout_mode_flags,
        uint32_t                        payout_target_account_id,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_configure_payout_frame(payout_asset_id, payout_mode_flags, payout_target_account_id),
            resp_out
        );
    }

    bool distribute_base_asset_yield(
        uint16_t                        base_asset_id,
        uint64_t                        total_lots,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_distribute_base_yield_frame(base_asset_id, total_lots),
            resp_out
        );
    }

    bool configure_auto_repo_scheduler(
        uint32_t                        epoch_marks,
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        clock_market_id = 0U
    ) noexcept {
        return send_frame(
            build_configure_auto_repo_frame(epoch_marks, clock_market_id),
            resp_out
        );
    }

    bool configure_payout_portfolio(
        uint16_t                        primary_asset_id,
        uint16_t                        primary_share_bps,
        uint16_t                        secondary_asset_id,
        uint16_t                        secondary_share_bps,
        uint16_t                        tertiary_asset_id,
        uint16_t                        tertiary_share_bps,
        uint8_t                         payout_mode_flags,
        uint32_t                        payout_target_account_id,
        uint16_t                        max_margin_util_bps,
        int64_t                         max_price_ticks,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_configure_payout_portfolio_frame(
                primary_asset_id,
                primary_share_bps,
                secondary_asset_id,
                secondary_share_bps,
                tertiary_asset_id,
                tertiary_share_bps,
                payout_mode_flags,
                payout_target_account_id,
                max_margin_util_bps,
                max_price_ticks
            ),
            resp_out
        );
    }

    bool fund_market_liquidity_vault(
        uint16_t                        market_id,
        uint16_t                        asset_id,
        uint64_t                        amount,
        uint32_t                        duration_marks,
        uint16_t                        maker_share_bps,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(
            build_fund_market_vault_frame(market_id, asset_id, amount, duration_marks, maker_share_bps),
            resp_out
        );
    }

    bool configure_default_trader_incentives(
        arena::wire::ArenaWireResponse& resp_out,
        uint8_t                         pillar_mask                 = arena::wire::INCENTIVE_PILLARS_ALL_ON,
        uint32_t                        repo_epoch_marks            = 60U,
        uint16_t                        two_sided_bonus_bps         = 2'500U,
        uint16_t                        claim_collateral_weight_bps = 9'000U
    ) noexcept {
        return send_frame(
            build_configure_default_incentives_frame(
                pillar_mask, repo_epoch_marks, two_sided_bonus_bps, claim_collateral_weight_bps
            ),
            resp_out
        );
    }

    bool subscribe_express_port(
        uint32_t                        duration_epochs,
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         max_fee_usd_micro = 0LL
    ) noexcept {
        const auto frm = build_subscribe_express_port_frame(duration_epochs, max_fee_usd_micro);
        if (!is_valid_frame(frm)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(frm, resp_out);
    }

    bool set_express_port_fee_per_epoch(
        int64_t                         fee_per_epoch_usd_micro,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        const auto frm = build_set_express_port_fee_frame(fee_per_epoch_usd_micro);
        if (!is_valid_frame(frm)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(frm, resp_out);
    }

    bool harvest_custody_float_yield(
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         yield_rate_bps            = 1LL,
        int64_t                         protocol_spread_share_bps = -1LL
    ) noexcept {
        return send_frame(
            build_harvest_custody_float_yield_frame(yield_rate_bps, protocol_spread_share_bps),
            resp_out
        );
    }

    bool harvest_overnight_spot_repo(
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        base_asset_id     = 1U,
        int64_t                         override_rate_bps = 0LL
    ) noexcept {
        return send_frame(
            build_harvest_overnight_spot_repo_frame(base_asset_id, override_rate_bps),
            resp_out
        );
    }

    bool harvest_negative_usd_repo(
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         override_rate_bps = 0LL
    ) noexcept {
        return send_frame(
            build_harvest_negative_usd_repo_frame(override_rate_bps),
            resp_out
        );
    }

    bool atomic_spread(
        uint16_t                        leg1_market_id,
        arena::wire::OrderSide          leg1_side,
        int64_t                         leg1_price_ticks,
        uint64_t                        leg1_qty_lots,
        uint16_t                        leg2_market_id,
        arena::wire::OrderSide          leg2_side,
        int64_t                         leg2_price_ticks,
        uint64_t                        leg2_qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        bool                            leg1_is_market   = false,
        bool                            leg1_reduce_only = false,
        bool                            leg2_is_market   = false,
        bool                            leg2_reduce_only = false,
        arena::wire::StpMode            stp                     = arena::wire::StpMode::CancelResting,
        bool                            margin_spot             = false,
        uint16_t                        express_surplus_bid_bps = 0U
    ) noexcept {
        return send_frame(
            build_atomic_spread_frame(
                leg1_market_id, leg1_side, leg1_price_ticks, leg1_qty_lots,
                leg2_market_id, leg2_side, leg2_price_ticks, leg2_qty_lots,
                leg1_is_market, leg1_reduce_only, leg2_is_market, leg2_reduce_only, stp, margin_spot,
                express_surplus_bid_bps
            ),
            resp_out
        );
    }

    bool send_atomic_basket(
        const std::vector<arena::wire::WireBasketLeg>& legs,
        arena::wire::ArenaWireResponse&                resp_out,
        arena::wire::StpMode                           stp                     = arena::wire::StpMode::CancelResting,
        bool                                           margin_spot             = false,
        uint16_t                                       express_surplus_bid_bps = 0U
    ) noexcept {
        return send_frame(build_atomic_basket_frame(legs, stp, margin_spot, express_surplus_bid_bps), resp_out);
    }

    bool atomic_basket(
        const std::vector<arena::wire::WireBasketLeg>& legs,
        arena::wire::ArenaWireResponse&                resp_out,
        arena::wire::StpMode                           stp                     = arena::wire::StpMode::CancelResting,
        bool                                           margin_spot             = false,
        uint16_t                                       express_surplus_bid_bps = 0U
    ) noexcept {
        return send_atomic_basket(legs, resp_out, stp, margin_spot, express_surplus_bid_bps);
    }

    bool distribute_margin_yield(
        int64_t                         reward_usd_micro,
        arena::wire::ArenaWireResponse& resp_out,
        uint32_t                        sponsor_account_id = 0U
    ) noexcept {
        return send_frame(build_distribute_yield_frame(reward_usd_micro, sponsor_account_id), resp_out);
    }

    bool set_protocol_account(
        uint32_t                        protocol_account_id,
        arena::wire::ArenaWireResponse& resp_out
    ) noexcept {
        return send_frame(build_set_protocol_account_frame(protocol_account_id), resp_out);
    }

    bool mint_redeem_set(
        uint16_t                        market_id,
        arena::wire::OrderSide          side,
        uint64_t                        qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         limit_cost_or_payout_micro = 0LL
    ) noexcept {
        return send_frame(
            build_mint_redeem_frame(market_id, side, qty_lots, limit_cost_or_payout_micro),
            resp_out
        );
    }

    bool flash_arbitrage(
        uint16_t                        market_id,
        arena::wire::OrderSide          side,
        uint64_t                        qty_lots,
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         limit_price_ticks       = 0LL,
        int64_t                         min_profit_micro        = 0LL,
        bool                            is_market               = false,
        arena::wire::StpMode            stp                     = arena::wire::StpMode::CancelResting,
        uint16_t                        express_surplus_bid_bps = 0U
    ) noexcept {
        return send_frame(
            build_flash_arbitrage_frame(
                market_id, side, qty_lots, limit_price_ticks, min_profit_micro, is_market, stp,
                express_surplus_bid_bps
            ),
            resp_out
        );
    }

    bool auto_delta_hedge(
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        base_asset_id       = 0U,
        uint16_t                        preferred_market_id = 0U,
        uint64_t                        max_qty_lots        = 0ULL,
        uint16_t                        max_slippage_bps    = 500U,
        bool                            allow_margin_spot   = false
    ) noexcept {
        return send_frame(
            build_auto_delta_hedge_frame(
                base_asset_id, preferred_market_id, max_qty_lots, max_slippage_bps, allow_margin_spot
            ),
            resp_out
        );
    }

    bool link_sub_account(
        uint32_t                        sub_account_id,
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         max_guaranty_usd_micro = 0LL,
        uint32_t                        master_account_id      = 0U
    ) noexcept {
        return send_frame(
            build_link_sub_account_frame(sub_account_id, max_guaranty_usd_micro, master_account_id),
            resp_out
        );
    }

    bool prime_internal_transfer(
        uint32_t                        to_account_id,
        int64_t                         amount,
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        asset_id        = 0U,
        uint32_t                        from_account_id = 0U
    ) noexcept {
        return send_frame(
            build_prime_transfer_frame(to_account_id, amount, asset_id, from_account_id),
            resp_out
        );
    }

    bool auto_cross_arb(
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        market_id_1             = 0U,
        uint16_t                        market_id_2             = 0U,
        uint64_t                        max_qty_lots            = 0ULL,
        int64_t                         min_profit_ticks        = 1LL,
        bool                            allow_margin_spot       = false,
        uint16_t                        express_surplus_bid_bps = 0U
    ) noexcept {
        return send_frame(
            build_auto_cross_arb_frame(
                market_id_1, market_id_2, max_qty_lots, min_profit_ticks, allow_margin_spot,
                express_surplus_bid_bps
            ),
            resp_out
        );
    }

    bool auto_liquidation_sweep(
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        market_id             = 0U,
        uint32_t                        target_account_id     = 0U,
        uint64_t                        max_qty_lots          = 0ULL,
        int64_t                         min_bounty_micro      = 0LL,
        bool                            auto_offload_to_book  = true,
        arena::wire::StpMode            stp                   = arena::wire::StpMode::CancelResting,
        bool                            hedge_margin_spot     = false,
        uint16_t                        bounty_rebate_bid_bps = 0U
    ) noexcept {
        const auto frm = build_auto_liquidation_sweep_frame(
            market_id,
            target_account_id,
            max_qty_lots,
            min_bounty_micro,
            auto_offload_to_book,
            stp,
            hedge_margin_spot,
            bounty_rebate_bid_bps
        );
        if (!is_valid_frame(frm)) {
            resp_out              = arena::wire::ArenaWireResponse{};
            resp_out.status_code  = arena::wire::WireStatusCode::RejectInvalidParams;
            resp_out.order_status = arena::wire::WireOrderStatus::Rejected;
            return false;
        }
        return send_frame(frm, resp_out);
    }

    bool send_auto_liquidation_sweep(
        arena::wire::ArenaWireResponse& resp_out,
        uint16_t                        market_id             = 0U,
        uint32_t                        target_account_id     = 0U,
        uint64_t                        max_qty_lots          = 0ULL,
        int64_t                         min_bounty_micro      = 0LL,
        bool                            auto_offload_to_book  = true,
        arena::wire::StpMode            stp                   = arena::wire::StpMode::CancelResting,
        bool                            hedge_margin_spot     = false,
        uint16_t                        bounty_rebate_bid_bps = 0U
    ) noexcept {
        return auto_liquidation_sweep(
            resp_out, market_id, target_account_id, max_qty_lots, min_bounty_micro,
            auto_offload_to_book, stp, hedge_margin_spot, bounty_rebate_bid_bps
        );
    }

    bool save_wal_snapshot(arena::wire::ArenaWireResponse& resp_out) noexcept {
        return send_frame(build_save_wal_snapshot_frame(), resp_out);
    }

    bool send_save_wal_snapshot(arena::wire::ArenaWireResponse& resp_out) noexcept {
        return save_wal_snapshot(resp_out);
    }

    bool sweep_excess_insurance_fund(
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         reserve_floor_usd_micro = 0LL,
        int64_t                         max_sweep_usd_micro     = 0LL
    ) noexcept {
        return send_frame(
            build_sweep_insurance_frame(reserve_floor_usd_micro, max_sweep_usd_micro),
            resp_out
        );
    }

    bool sweep_insurance_fund(
        arena::wire::ArenaWireResponse& resp_out,
        int64_t                         reserve_floor_usd_micro = 0LL,
        int64_t                         max_sweep_usd_micro     = 0LL
    ) noexcept {
        return sweep_excess_insurance_fund(resp_out, reserve_floor_usd_micro, max_sweep_usd_micro);
    }

private:
    [[nodiscard]] uint32_t seq_bucket_account(uint32_t eff_acct) const noexcept {
        const bool uses_provisioned_signer_key =
            (key_lo64_ != DEFAULT_DEV_KEY_LO64 || key_hi64_ != DEFAULT_DEV_KEY_HI64);
        return uses_provisioned_signer_key ? signer_account_id_ : eff_acct;
    }

    void allocate_seq_for_frame(uint32_t eff_acct, uint16_t& out_seq_lo, uint64_t& out_seq_hi50) noexcept {
        const uint32_t seq_acct = seq_bucket_account(eff_acct);
        auto [it, _]     = next_seq_by_account_.try_emplace(seq_acct, default_init_seq_lo_);
        uint64_t& acct_hi50 =
            seq_hi50_by_account_.try_emplace(seq_acct, default_init_seq_hi50_).first->second;
        auto wrap_it = pending_hi50_wrap_by_account_.find(seq_acct);
        if (wrap_it != pending_hi50_wrap_by_account_.end() && wrap_it->second) {
            wrap_it->second = false;
            acct_hi50       = (acct_hi50 + 1ULL) & ((1ULL << 50U) - 1ULL);
        }
        if (seq_acct == seq_bucket_account(account_id_)) {
            seq_hi50_ = acct_hi50;
        }
        const uint16_t cur = it->second;
        it->second         = static_cast<uint16_t>((cur + 1U) & 0x3FFFU);
        if (cur == 0x3FFFU) {
            pending_hi50_wrap_by_account_[seq_acct] = true;
        }
        out_seq_lo   = cur;
        out_seq_hi50 = acct_hi50;
    }

    uint16_t allocate_seq_lo(uint32_t acct) noexcept {
        uint16_t seq_lo  = 0U;
        uint64_t hi50_ig = 0ULL;
        allocate_seq_for_frame(acct, seq_lo, hi50_ig);
        return seq_lo;
    }

    uint16_t allocate_seq_lo() noexcept {
        return allocate_seq_lo(account_id_);
    }

    static uint64_t next_process_sync_nonce_us(uint64_t floor_us) noexcept {
        uint64_t cur = s_global_last_sync_nonce_.load(std::memory_order_relaxed);
        for (;;) {
            const uint64_t cand = std::max<uint64_t>(cur + 1ULL, floor_us);
            if (s_global_last_sync_nonce_.compare_exchange_weak(
                    cur, cand, std::memory_order_relaxed, std::memory_order_relaxed)) {
                return cand;
            }
        }
    }

    inline static std::atomic<uint64_t>    s_global_last_sync_nonce_{0ULL};
    detail::SdkSocketHandle                tcp_sock_{detail::SDK_INVALID_SOCK};
    uint32_t                               io_timeout_ms_{2'500U};
    uint32_t                               account_id_{1U};
    uint32_t                               signer_account_id_{1U};
    uint64_t                               key_lo64_{DEFAULT_DEV_KEY_LO64};
    uint64_t                               key_hi64_{DEFAULT_DEV_KEY_HI64};
    uint64_t                               seq_hi50_{DEFAULT_SEQ_HI50};
    uint64_t                               last_built_seq_hi50_{DEFAULT_SEQ_HI50};
    uint64_t                               default_init_seq_hi50_{DEFAULT_SEQ_HI50};
    uint64_t                               last_sync_nonce_{0ULL};
    bool                                   resyncing_hi50_{false};
    bool                                   tried_resync_hi50_{false};
    bool                                   auto_retry_mutating_on_resync_{false};
    uint16_t                               default_init_seq_lo_{1U};
    struct SavedCredKey {
        uint32_t account_id{0U};
        uint64_t key_lo64{0ULL};
        uint64_t key_hi64{0ULL};
        [[nodiscard]] bool operator==(const SavedCredKey& o) const noexcept {
            return account_id == o.account_id && key_lo64 == o.key_lo64 && key_hi64 == o.key_hi64;
        }
    };

    struct SavedCredKeyHash {
        [[nodiscard]] std::size_t operator()(const SavedCredKey& k) const noexcept {
            std::size_t h = static_cast<std::size_t>(k.account_id) * 1099511628211ULL;
            h ^= static_cast<std::size_t>(k.key_lo64 + 0x9E3779B97F4A7C15ULL + (h << 6U) + (h >> 2U));
            h ^= static_cast<std::size_t>(k.key_hi64 + 0x9E3779B97F4A7C15ULL + (h << 6U) + (h >> 2U));
            return h;
        }
    };

    struct SavedCredSeqState {
        uint64_t seq_hi50{DEFAULT_SEQ_HI50};
        uint16_t next_seq{1U};
        bool     pending_wrap{false};
    };

    std::unordered_map<uint32_t, uint16_t> next_seq_by_account_{};
    std::unordered_map<uint32_t, bool>     pending_hi50_wrap_by_account_{};
    std::unordered_map<uint32_t, uint64_t> seq_hi50_by_account_{};
    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> cred_key_by_account_{};
    std::unordered_map<SavedCredKey, SavedCredSeqState, SavedCredKeyHash> saved_cred_seq_state_{};
    std::unordered_map<uint32_t, bool>     verified_seq_by_account_{};
    std::unordered_map<uint32_t, bool>     ambiguous_disconnect_by_account_{};
};

using ArenaHftClient = ArenaHftWireClient;

// =============================================================================
// 3. `ArenaHftBookReconstructor` & `ArenaHftItchSubscriber` (`ArenaITCH` v4.8)
// =============================================================================
struct L2Level {
    int64_t  price_ticks{0};
    uint64_t total_lots{0};
    uint32_t order_count{0};
};

struct BboSnapshot {
    int64_t  best_bid_ticks{0};
    uint64_t best_bid_lots{0};
    int64_t  best_ask_ticks{0};
    uint64_t best_ask_lots{0};
};

class ArenaHftBookReconstructor {
public:
    struct MarketDirectoryInfo {
        uint16_t    market_id{0};
        uint8_t     market_kind{0};
        uint8_t     sub_kind{0};
        uint8_t     base_asset_id{0};
        uint8_t     inst_flags{0};
        uint16_t    ref_market_1{0};
        uint16_t    ref_market_2{0};
        uint16_t    imr_bps{0};
        int64_t     mark_price_ticks{0};
        std::string symbol{};
    };

    struct RestingOrder {
        uint64_t               order_id{0};
        uint64_t               account_id{0};
        uint16_t               market_id{0};
        arena::wire::OrderSide side{arena::wire::OrderSide::Bid};
        int64_t                price_ticks{0};
        uint64_t               remaining_lots{0};
        bool                   reduce_only{false};
    };

    struct MarketBook {
        int64_t                                                        mark_price_ticks{0};
        uint64_t                                                       open_interest_lots{0};
        int64_t                                                        cumulative_funding_phi{0};
        uint64_t                                                       synthetic_supply_lots{0};
        int64_t                                                        synthetic_reserve_escrow_usd_micro{0};
        bool                                                           in_snapshot{false};
        bool                                                           snapshot_complete{false};
        std::unordered_map<uint64_t, RestingOrder>                     orders_by_id{};
        std::map<int64_t, std::deque<uint64_t>, std::greater<int64_t>> bid_queues{};
        std::map<int64_t, std::deque<uint64_t>, std::less<int64_t>>    ask_queues{};
    };

    void reset() noexcept {
        books_.clear();
        directory_.clear();
        last_itch_seq_             = 0ULL;
        last_wal_seq_              = 0ULL;
        snapshot_resync_seq_       = 0ULL;
        gap_detected_              = false;
        has_ledger_checkpoint_     = false;
        last_checkpoint_wal_seq_   = 0ULL;
        last_ledger_chain_hash_.fill(0U);
        active_snapshot_market_id_ = 0U;
    }

    void abort_incomplete_snapshot_for_reconnect() noexcept {
        if (active_snapshot_market_id_ != 0U) {
            if (auto it_ab = books_.find(active_snapshot_market_id_); it_ab != books_.end()) {
                it_ab->second.in_snapshot       = false;
                it_ab->second.snapshot_complete = false;
                it_ab->second.orders_by_id.clear();
                it_ab->second.bid_queues.clear();
                it_ab->second.ask_queues.clear();
            }
            active_snapshot_market_id_ = 0U;
        }
    }

    bool apply(const arena::wire::ArenaItchMessage& msg) {
        using arena::wire::ItchEventType;

        if (msg.event_type == ItchEventType::Heartbeat) {
            return true;
        }

        if (subscribed_market_id_ != 0U && msg.market_id != 0U && msg.market_id != subscribed_market_id_) {
            gap_detected_ = true;
            return false;
        }

        if (active_snapshot_market_id_ != 0U) {
            const bool is_active_snap_cont =
                (msg.event_type == ItchEventType::SnapshotOrder ||
                 msg.event_type == ItchEventType::SnapshotEnd) &&
                msg.market_id == active_snapshot_market_id_;
            if (!is_active_snap_cont) {
                if (auto it_ab = books_.find(active_snapshot_market_id_); it_ab != books_.end()) {
                    it_ab->second.in_snapshot       = false;
                    it_ab->second.snapshot_complete = false;
                    it_ab->second.orders_by_id.clear();
                    it_ab->second.bid_queues.clear();
                    it_ab->second.ask_queues.clear();
                }
                active_snapshot_market_id_ = 0U;
                gap_detected_              = true;
                return false;
            }
        }

        if (msg.event_type == ItchEventType::MarketDirectory) {
            if ((last_itch_seq_ > 0ULL && msg.itch_seq < last_itch_seq_) ||
                (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_)) {
                gap_detected_ = true;
                return false;
            }
            MarketDirectoryInfo di{};
            di.market_id        = msg.market_id;
            di.mark_price_ticks = msg.price_ticks;
            std::array<char, 16> sym16{};
            msg.unpack_market_directory(
                di.market_kind,
                di.sub_kind,
                di.base_asset_id,
                di.inst_flags,
                di.ref_market_1,
                di.ref_market_2,
                di.imr_bps,
                sym16
            );
            std::size_t slen = 0U;
            while (slen < 16U && sym16[slen] != '\0') ++slen;
            di.symbol.assign(sym16.data(), slen);
            directory_[msg.market_id] = di;
            if (auto mb_it = books_.find(msg.market_id); mb_it != books_.end()) {
                mb_it->second.mark_price_ticks = msg.price_ticks;
            } else if (subscribed_market_id_ == 0U || msg.market_id == subscribed_market_id_) {
                books_[msg.market_id].mark_price_ticks = msg.price_ticks;
            }
            if (msg.itch_seq > last_itch_seq_) {
                if (last_itch_seq_ > 0ULL && msg.itch_seq > last_itch_seq_ + 1ULL && track_sequence_gaps_) {
                    gap_detected_ = true;
                    return true;
                }
                last_itch_seq_ = msg.itch_seq;
            }
            if (msg.wal_seq > last_wal_seq_) {
                last_wal_seq_ = msg.wal_seq;
            }
            return true;
        }

        if (msg.event_type == ItchEventType::LedgerCheckpoint) {
            if (last_itch_seq_ > 0ULL && msg.itch_seq < last_itch_seq_) {
                gap_detected_ = true;
                return false;
            }
            if ((last_checkpoint_wal_seq_ > 0ULL && msg.wal_seq < last_checkpoint_wal_seq_) ||
                (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_)) {
                gap_detected_ = true;
                return false;
            }
            if (msg.itch_seq > last_itch_seq_) {
                if (last_itch_seq_ > 0ULL && msg.itch_seq > last_itch_seq_ + 1ULL && track_sequence_gaps_) {
                    gap_detected_ = true;
                    return false;
                }
                last_itch_seq_ = msg.itch_seq;
            }
            if (msg.wal_seq > last_wal_seq_) {
                last_wal_seq_ = msg.wal_seq;
            }
            last_checkpoint_wal_seq_ = msg.wal_seq;
            msg.extract_ledger_checkpoint_hash(last_ledger_chain_hash_);
            has_ledger_checkpoint_   = true;
            return true;
        }

        const auto* dir_entry  = find_market_directory(msg.market_id);
        const bool  is_spot_mk = (dir_entry != nullptr && dir_entry->market_kind == 0U);

        if (msg.event_type == ItchEventType::SnapshotBegin) {
            if (msg.market_id == 0U ||
                (last_itch_seq_ > 0ULL && msg.itch_seq < last_itch_seq_) ||
                (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_)) {
                gap_detected_ = true;
                return false;
            }
            if (subscribed_market_id_ != 0U && msg.market_id == subscribed_market_id_) {
                for (auto bit = books_.begin(); bit != books_.end();) {
                    if (bit->first != subscribed_market_id_) {
                        bit = books_.erase(bit);
                    } else {
                        ++bit;
                    }
                }
                snapshot_resync_seq_ = msg.itch_seq;
            } else if (last_itch_seq_ > 0ULL && msg.itch_seq > last_itch_seq_ + 1ULL) {
                if (snapshot_resync_seq_ != msg.itch_seq) {
                    for (auto& [mid_k, b_st] : books_) {
                        (void)mid_k;
                        b_st.orders_by_id.clear();
                        b_st.bid_queues.clear();
                        b_st.ask_queues.clear();
                        b_st.in_snapshot       = false;
                        b_st.snapshot_complete = false;
                    }
                    snapshot_resync_seq_ = msg.itch_seq;
                }
            }
            MarketBook& mb = books_[msg.market_id];
            mb.orders_by_id.clear();
            mb.bid_queues.clear();
            mb.ask_queues.clear();
            mb.mark_price_ticks = msg.price_ticks;
            if (is_spot_mk) {
                mb.open_interest_lots                 = 0ULL;
                mb.cumulative_funding_phi             = 0LL;
                mb.synthetic_supply_lots              = msg.order_id;
                mb.synthetic_reserve_escrow_usd_micro = static_cast<int64_t>(msg.aux_u64);
            } else {
                mb.open_interest_lots                 = msg.order_id;
                mb.cumulative_funding_phi             = static_cast<int64_t>(msg.aux_u64);
                mb.synthetic_supply_lots              = 0ULL;
                mb.synthetic_reserve_escrow_usd_micro = 0LL;
            }
            mb.in_snapshot             = true;
            mb.snapshot_complete       = false;
            active_snapshot_market_id_ = msg.market_id;
            last_itch_seq_             = msg.itch_seq;
            if (msg.wal_seq > last_wal_seq_) {
                last_wal_seq_ = msg.wal_seq;
            }
            return true;
        }

        if (msg.event_type == ItchEventType::SnapshotOrder) {
            auto mb_it = books_.find(msg.market_id);
            if (mb_it == books_.end() || !mb_it->second.in_snapshot || msg.itch_seq != last_itch_seq_ ||
                (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_) ||
                msg.qty_lots == 0ULL || !is_valid_order_price(msg.market_id, msg.price_ticks)) {
                if (mb_it != books_.end()) {
                    mb_it->second.in_snapshot       = false;
                    mb_it->second.snapshot_complete = false;
                    mb_it->second.orders_by_id.clear();
                    mb_it->second.bid_queues.clear();
                    mb_it->second.ask_queues.clear();
                }
                active_snapshot_market_id_ = 0U;
                gap_detected_              = true;
                return false;
            }
            insert_order(mb_it->second, msg);
            return true;
        }

        if (msg.event_type == ItchEventType::SnapshotEnd) {
            auto mb_it = books_.find(msg.market_id);
            if (mb_it == books_.end() || !mb_it->second.in_snapshot || msg.itch_seq != last_itch_seq_ ||
                (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_) ||
                mb_it->second.orders_by_id.size() != msg.order_id) {
                if (mb_it != books_.end()) {
                    mb_it->second.in_snapshot       = false;
                    mb_it->second.snapshot_complete = false;
                    mb_it->second.orders_by_id.clear();
                    mb_it->second.bid_queues.clear();
                    mb_it->second.ask_queues.clear();
                }
                active_snapshot_market_id_ = 0U;
                gap_detected_              = true;
                return false;
            }
            mb_it->second.in_snapshot       = false;
            mb_it->second.snapshot_complete = true;
            active_snapshot_market_id_      = 0U;
            last_itch_seq_                  = msg.itch_seq;
            if (msg.wal_seq > last_wal_seq_) {
                last_wal_seq_ = msg.wal_seq;
            }
            if (snapshot_resync_seq_ != 0ULL && msg.itch_seq == snapshot_resync_seq_) {
                gap_detected_ = false;
            }
            return true;
        }

        if (auto mb_it = books_.find(msg.market_id); mb_it != books_.end() && mb_it->second.in_snapshot) {
            mb_it->second.in_snapshot       = false;
            mb_it->second.snapshot_complete = false;
            mb_it->second.orders_by_id.clear();
            mb_it->second.bid_queues.clear();
            mb_it->second.ask_queues.clear();
            gap_detected_                   = true;
            return false;
        }

        if (last_itch_seq_ > 0ULL) {
            if (msg.itch_seq <= last_itch_seq_) {
                gap_detected_ = true;
                return false;
            }
            if (msg.itch_seq > last_itch_seq_ + 1ULL && track_sequence_gaps_) {
                gap_detected_ = true;
                return false;
            }
        }
        if (last_wal_seq_ > 0ULL && msg.wal_seq < last_wal_seq_) {
            gap_detected_ = true;
            return false;
        }
        last_itch_seq_ = msg.itch_seq;
        if (msg.wal_seq > last_wal_seq_) {
            last_wal_seq_ = msg.wal_seq;
        }

        MarketBook& mb = books_[msg.market_id];

        switch (msg.event_type) {
            case ItchEventType::OrderAdded:
                if (msg.qty_lots == 0ULL || !is_valid_order_price(msg.market_id, msg.price_ticks)) return false;
                insert_order(mb, msg);
                return true;
            case ItchEventType::OrderExecuted: {
                auto it = mb.orders_by_id.find(msg.order_id);
                if (it == mb.orders_by_id.end()) {
                    // Valid post-trade print on a 100% hidden Dark-Midpoint resting order
                    return true;
                }
                if (msg.qty_lots >= it->second.remaining_lots) {
                    erase_order(mb, it->second);
                } else {
                    it->second.remaining_lots -= msg.qty_lots;
                }
                return true;
            }
            case ItchEventType::OrderModified: {
                auto it = mb.orders_by_id.find(msg.order_id);
                if (it == mb.orders_by_id.end() || msg.qty_lots == 0ULL) {
                    if (it == mb.orders_by_id.end() && mb.snapshot_complete) {
                        gap_detected_ = true;
                    }
                    return false;
                }
                if (is_valid_order_price(msg.market_id, msg.price_ticks) &&
                    msg.price_ticks != it->second.price_ticks) {
                    const uint64_t oid    = it->second.order_id;
                    const int64_t  old_px = it->second.price_ticks;
                    if (it->second.side == arena::wire::OrderSide::Bid) {
                        auto qit = mb.bid_queues.find(old_px);
                        if (qit != mb.bid_queues.end()) {
                            auto& q = qit->second;
                            q.erase(std::remove(q.begin(), q.end(), oid), q.end());
                            if (q.empty()) mb.bid_queues.erase(qit);
                        }
                        mb.bid_queues[msg.price_ticks].push_back(oid);
                    } else {
                        auto qit = mb.ask_queues.find(old_px);
                        if (qit != mb.ask_queues.end()) {
                            auto& q = qit->second;
                            q.erase(std::remove(q.begin(), q.end(), oid), q.end());
                            if (q.empty()) mb.ask_queues.erase(qit);
                        }
                        mb.ask_queues[msg.price_ticks].push_back(oid);
                    }
                    it->second.price_ticks = msg.price_ticks;
                }
                it->second.remaining_lots = msg.qty_lots;
                return true;
            }
            case ItchEventType::OrderDeleted: {
                auto it = mb.orders_by_id.find(msg.order_id);
                if (it == mb.orders_by_id.end()) {
                    if (mb.snapshot_complete) {
                        gap_detected_ = true;
                    }
                    return false;
                }
                erase_order(mb, it->second);
                return true;
            }
            case ItchEventType::MarkAndFunding: {
                mb.mark_price_ticks = msg.price_ticks;
                if (is_spot_mk) {
                    mb.open_interest_lots                 = 0ULL;
                    mb.cumulative_funding_phi             = 0LL;
                    mb.synthetic_supply_lots              = msg.order_id;
                    mb.synthetic_reserve_escrow_usd_micro = static_cast<int64_t>(msg.aux_u64);
                } else {
                    mb.open_interest_lots     = msg.order_id;
                    mb.cumulative_funding_phi = static_cast<int64_t>(msg.aux_u64);
                }
                return true;
            }
            default:
                return false;
        }
    }

    void set_subscribed_market_id(uint16_t market_id) noexcept { subscribed_market_id_ = market_id; }
    [[nodiscard]] uint16_t subscribed_market_id() const noexcept { return subscribed_market_id_; }
    void set_track_sequence_gaps(bool enable) noexcept { track_sequence_gaps_ = enable; }
    void mark_gap_detected() noexcept { gap_detected_ = true; }
    void clear_gap_flag() noexcept { gap_detected_ = false; }
    [[nodiscard]] bool     gap_detected() const noexcept { return gap_detected_; }
    [[nodiscard]] bool     has_incomplete_snapshot() const noexcept { return active_snapshot_market_id_ != 0U; }
    [[nodiscard]] uint64_t last_itch_seq() const noexcept { return last_itch_seq_; }
    [[nodiscard]] bool     has_ledger_checkpoint() const noexcept { return has_ledger_checkpoint_; }
    [[nodiscard]] uint64_t last_checkpoint_wal_seq() const noexcept { return last_checkpoint_wal_seq_; }
    [[nodiscard]] const Bytes32& last_ledger_chain_hash() const noexcept { return last_ledger_chain_hash_; }
    [[nodiscard]] std::string last_ledger_chain_hash_hex() const { return to_hex_0x(last_ledger_chain_hash_); }

    [[nodiscard]] const MarketBook* find_market(uint16_t market_id) const noexcept {
        const auto it = books_.find(market_id);
        return (it != books_.end()) ? &it->second : nullptr;
    }

    [[nodiscard]] const MarketDirectoryInfo* find_market_directory(uint16_t market_id) const noexcept {
        const auto it = directory_.find(market_id);
        return (it != directory_.end()) ? &it->second : nullptr;
    }

    [[nodiscard]] const std::unordered_map<uint16_t, MarketDirectoryInfo>& directory() const noexcept {
        return directory_;
    }

    [[nodiscard]] BboSnapshot best_bbo(uint16_t market_id) const {
        BboSnapshot bbo{};
        const auto* mb = find_market(market_id);
        if (mb == nullptr) return bbo;
        for (const auto& [px, q] : mb->bid_queues) {
            if (q.empty()) continue;
            uint64_t sum = 0ULL;
            for (const uint64_t oid : q) {
                const auto oit = mb->orders_by_id.find(oid);
                if (oit != mb->orders_by_id.end()) sum += oit->second.remaining_lots;
            }
            if (sum > 0ULL) {
                bbo.best_bid_ticks = px;
                bbo.best_bid_lots  = sum;
                break;
            }
        }
        for (const auto& [px, q] : mb->ask_queues) {
            if (q.empty()) continue;
            uint64_t sum = 0ULL;
            for (const uint64_t oid : q) {
                const auto oit = mb->orders_by_id.find(oid);
                if (oit != mb->orders_by_id.end()) sum += oit->second.remaining_lots;
            }
            if (sum > 0ULL) {
                bbo.best_ask_ticks = px;
                bbo.best_ask_lots  = sum;
                break;
            }
        }
        return bbo;
    }

    void snapshot_l2(
        uint16_t               market_id,
        std::size_t            max_levels,
        std::vector<L2Level>&  bids_out,
        std::vector<L2Level>&  asks_out
    ) const {
        bids_out.clear();
        asks_out.clear();
        const auto* mb = find_market(market_id);
        if (mb == nullptr || max_levels == 0U) return;

        for (const auto& [px, q] : mb->bid_queues) {
            if (q.empty()) continue;
            uint64_t sum = 0ULL;
            for (const uint64_t oid : q) {
                const auto oit = mb->orders_by_id.find(oid);
                if (oit != mb->orders_by_id.end()) sum += oit->second.remaining_lots;
            }
            bids_out.push_back(L2Level{px, sum, static_cast<uint32_t>(q.size())});
            if (bids_out.size() >= max_levels) break;
        }
        for (const auto& [px, q] : mb->ask_queues) {
            if (q.empty()) continue;
            uint64_t sum = 0ULL;
            for (const uint64_t oid : q) {
                const auto oit = mb->orders_by_id.find(oid);
                if (oit != mb->orders_by_id.end()) sum += oit->second.remaining_lots;
            }
            asks_out.push_back(L2Level{px, sum, static_cast<uint32_t>(q.size())});
            if (asks_out.size() >= max_levels) break;
        }
    }

private:
    [[nodiscard]] bool is_valid_order_price(uint16_t market_id, int64_t price_ticks) const noexcept {
        const auto* dir = find_market_directory(market_id);
        if (dir != nullptr && dir->market_kind == 4U) {
            return is_valid_wire_price_ticks_48(price_ticks);
        }
        return price_ticks > 0LL;
    }

    void insert_order(MarketBook& mb, const arena::wire::ArenaItchMessage& msg) const {
        if (msg.qty_lots == 0ULL || !is_valid_order_price(msg.market_id, msg.price_ticks)) {
            return;
        }
        if (auto existing = mb.orders_by_id.find(msg.order_id); existing != mb.orders_by_id.end()) {
            erase_order(mb, existing->second);
        }
        RestingOrder ro{};
        ro.order_id       = msg.order_id;
        ro.account_id     = msg.aux_u64;
        ro.market_id      = msg.market_id;
        ro.side           = msg.side;
        ro.price_ticks    = msg.price_ticks;
        ro.remaining_lots = msg.qty_lots;
        ro.reduce_only    = (msg.flags & 0x1U) != 0U;
        mb.orders_by_id[ro.order_id] = ro;
        if (ro.side == arena::wire::OrderSide::Bid) {
            mb.bid_queues[ro.price_ticks].push_back(ro.order_id);
        } else {
            mb.ask_queues[ro.price_ticks].push_back(ro.order_id);
        }
    }

    static void erase_order(MarketBook& mb, const RestingOrder& ro) {
        const uint64_t oid = ro.order_id;
        const int64_t  px  = ro.price_ticks;
        if (ro.side == arena::wire::OrderSide::Bid) {
            auto qit = mb.bid_queues.find(px);
            if (qit != mb.bid_queues.end()) {
                auto& q = qit->second;
                q.erase(std::remove(q.begin(), q.end(), oid), q.end());
                if (q.empty()) mb.bid_queues.erase(qit);
            }
        } else {
            auto qit = mb.ask_queues.find(px);
            if (qit != mb.ask_queues.end()) {
                auto& q = qit->second;
                q.erase(std::remove(q.begin(), q.end(), oid), q.end());
                if (q.empty()) mb.ask_queues.erase(qit);
            }
        }
        mb.orders_by_id.erase(oid);
    }

    std::unordered_map<uint16_t, MarketBook>          books_{};
    std::unordered_map<uint16_t, MarketDirectoryInfo> directory_{};
    uint64_t                                          last_itch_seq_{0};
    uint64_t                                          last_wal_seq_{0};
    uint64_t                                          snapshot_resync_seq_{0};
    uint16_t                                          subscribed_market_id_{0};
    bool                                     track_sequence_gaps_{true};
    bool                                     gap_detected_{false};
    bool                                     has_ledger_checkpoint_{false};
    uint64_t                                 last_checkpoint_wal_seq_{0};
    Bytes32                                  last_ledger_chain_hash_{};
    uint16_t                                 active_snapshot_market_id_{0};
};

class ArenaHftItchSubscriber {
public:
    ArenaHftItchSubscriber() noexcept {
        detail::ensure_winsock_initialized();
    }

    ~ArenaHftItchSubscriber() noexcept {
        disconnect();
    }

    ArenaHftItchSubscriber(const ArenaHftItchSubscriber&)            = delete;
    ArenaHftItchSubscriber& operator=(const ArenaHftItchSubscriber&) = delete;

    bool connect_and_subscribe(
        uint16_t    port,
        uint16_t    market_id     = 0U,
        uint16_t    req_flags     = arena::wire::ITCH_REQ_FLAG_FULL_SNAPSHOT,
        uint64_t    from_itch_seq = 0ULL,
        const char* host          = "127.0.0.1",
        uint32_t    io_timeout_ms = 2'500U
    ) noexcept {
        detail::ensure_winsock_initialized();
        disconnect();
        rx_partial_len_ = 0U;
        rx_partial_.fill(0U);
        last_port_          = port;
        last_market_id_     = market_id;
        last_io_timeout_ms_ = io_timeout_ms;
        last_host_          = (host != nullptr) ? std::string(host) : std::string("127.0.0.1");
        sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ == detail::SDK_INVALID_SOCK) return false;
        detail::sdk_enable_tcp_nodelay(sock_);
        detail::sdk_apply_io_timeout(sock_, io_timeout_ms);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (port == 0U || !detail::sdk_resolve_ipv4_host(host, addr.sin_addr)) {
            disconnect();
            return false;
        }
        if (!detail::sdk_connect_with_timeout(sock_, addr, io_timeout_ms)) {
            disconnect();
            return false;
        }

        arena::wire::ArenaItchSubscribeReq sreq{};
        sreq.market_id     = market_id;
        sreq.req_flags     = req_flags;
        sreq.from_itch_seq = from_itch_seq;
        const auto raw16   = sreq.pack_bytes();

        std::size_t tx = 0U;
        while (tx < 16U) {
            const int n = ::send(
                sock_,
                reinterpret_cast<const char*>(raw16.data() + tx),
                static_cast<int>(16U - tx),
                detail::SDK_SEND_FLAGS
            );
            if (n < 0 && detail::sdk_is_eintr()) {
                continue;
            }
            if (n <= 0) {
                disconnect();
                return false;
            }
            tx += static_cast<std::size_t>(n);
        }
        if ((req_flags & arena::wire::ITCH_REQ_FLAG_FULL_SNAPSHOT) != 0U || from_itch_seq == 0ULL) {
            reconstructor_.reset();
        } else {
            reconstructor_.abort_incomplete_snapshot_for_reconnect();
            reconstructor_.clear_gap_flag();
        }
        reconstructor_.set_subscribed_market_id(market_id);
        reconstructor_.set_track_sequence_gaps(market_id == 0U);
        return true;
    }

    bool reconnect_and_replay(uint64_t from_itch_seq) noexcept {
        if (last_port_ == 0U) {
            return false;
        }
        return connect_and_subscribe(
            last_port_,
            last_market_id_,
            arena::wire::ITCH_REQ_FLAG_REPLAY_FROM_SEQ,
            from_itch_seq,
            last_host_.c_str(),
            last_io_timeout_ms_
        );
    }

    void disconnect() noexcept {
        detail::sdk_close_socket(sock_);
        sock_           = detail::SDK_INVALID_SOCK;
        rx_partial_len_ = 0U;
        rx_partial_.fill(0U);
    }

    bool recv_message(arena::wire::ArenaItchMessage& msg_out, uint32_t timeout_ms = 2'500U) noexcept {
        if (sock_ == detail::SDK_INVALID_SOCK) return false;
        const uint32_t eff_timeout_ms = (timeout_ms > 0U) ? timeout_ms : 1U;
        detail::sdk_apply_io_timeout(sock_, eff_timeout_ms);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(eff_timeout_ms);
        while (rx_partial_len_ < arena::wire::ARENA_ITCH_BYTES) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                return false;
            }
            const long long rem_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            detail::sdk_apply_io_timeout(
                sock_, static_cast<uint32_t>(std::max<long long>(1LL, rem_ms))
            );
            const int n = ::recv(
                sock_,
                reinterpret_cast<char*>(rx_partial_.data() + rx_partial_len_),
                static_cast<int>(arena::wire::ARENA_ITCH_BYTES - rx_partial_len_),
                0
            );
            if (n < 0 && detail::sdk_is_eintr()) {
                continue;
            }
            if (n <= 0) {
                if (n == 0 || !detail::sdk_recv_timed_out()) {
                    reconstructor_.mark_gap_detected();
                    disconnect();
                }
                return false;
            }
            rx_partial_len_ += static_cast<std::size_t>(n);
        }
        arena::wire::ArenaItchFrame f{};
        f.bytes         = rx_partial_;
        rx_partial_len_ = 0U;
        if (!arena::wire::ArenaItchMessage::unpack_and_verify(f, msg_out)) {
            reconstructor_.mark_gap_detected();
            disconnect();
            return false;
        }
        return true;
    }

    bool recv_and_apply(arena::wire::ArenaItchMessage& msg_out, uint32_t timeout_ms = 2'500U) {
        if (!recv_message(msg_out, timeout_ms)) return false;
        return reconstructor_.apply(msg_out);
    }

    [[nodiscard]] bool        is_connected() const noexcept        { return sock_ != detail::SDK_INVALID_SOCK; }
    [[nodiscard]] std::size_t partial_rx_buffered() const noexcept { return rx_partial_len_; }

    [[nodiscard]] ArenaHftBookReconstructor&       reconstructor() noexcept       { return reconstructor_; }
    [[nodiscard]] const ArenaHftBookReconstructor& reconstructor() const noexcept { return reconstructor_; }

private:
    detail::SdkSocketHandle                             sock_{detail::SDK_INVALID_SOCK};
    std::array<uint8_t, arena::wire::ARENA_ITCH_BYTES>  rx_partial_{};
    std::size_t                                         rx_partial_len_{0U};
    uint16_t                                            last_port_{0U};
    uint16_t                                            last_market_id_{0U};
    uint32_t                                            last_io_timeout_ms_{2'500U};
    std::string                                         last_host_{"127.0.0.1"};
    ArenaHftBookReconstructor                           reconstructor_{};
};

} // namespace arena::sdk
