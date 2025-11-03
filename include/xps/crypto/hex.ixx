module;

// ──────────────────────────────────────────────────────────────────────────────
// Global module fragment — standard headers (not exported)
// ──────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <optional>
#include <limits>
#include <algorithm>
#include <array>   // constexpr table

// ──────────────────────────────────────────────────────────────────────────────
export module xps.internal.hex;

// Project modules
import xps.expected; // xps::expected<T, std::string>

// ──────────────────────────────────────────────────────────────────────────────
// internal.hex — High-performance hex (lower/upper, separators, 0x-prefix) + streaming
//   • No deps; branch-light encode using LUTs
//   • Flexible decode: accepts separators/whitespace/0x prefixes (configurable)
//   • Streaming Encoder/Decoder for chunked I/O (مع دعم 0x عبر حدود الدُفعات)
//   • Back-compat helper: hex(const unsigned char*, int) → const char*
// ──────────────────────────────────────────────────────────────────────────────

export namespace xps::intx {

  using Bytes  = std::vector<std::byte>;
  template<class T>
  using Result = xps::expected<T, std::string>;
  using BytesView = std::span<const std::byte>;

  // ───────────── Options
  enum class LetterCase : std::uint8_t { Lower, Upper };

  struct EncodeOptions {
    LetterCase   casing { LetterCase::Lower };
    bool         prefix_0x { false };           // write "0x" before each byte
    std::string  separator { "" };              // inserted between groups
    std::size_t  group_every { 0 };             // 0=no grouping; else N bytes per group
  };

  struct DecodeOptions {
    bool         accept_whitespace { true };
    bool         accept_separators { true };
    std::string  separators { " \t\r\n:_-" }; // any char in this set will be skipped when accept_separators
    bool         accept_0x { true };            // tolerate 0x/0X anywhere
    bool         require_even_length { false }; // if true → error on dangling nibble
    bool         pad_low_if_odd { true };       // if false & odd and not required even → drop dangling nibble
  };

  namespace detail {
    inline constexpr char HEX_LOWER[] = "0123456789abcdef";
    inline constexpr char HEX_UPPER[] = "0123456789ABCDEF";

    // constexpr decode table: value 0..15; 0xFF invalid; 0xFE marks 'x' (for 0x/0X detection)
    inline consteval std::array<unsigned char,256> make_decode() {
      std::array<unsigned char,256> t{};
      for (auto& v : t) v = 0xFF; // invalid
      for (int i=0;i<10;i++) t[static_cast<unsigned char>('0'+i)] = static_cast<unsigned char>(i);
      for (int i=0;i<6;i++) {
        t[static_cast<unsigned char>('a'+i)] = static_cast<unsigned char>(10+i);
        t[static_cast<unsigned char>('A'+i)] = static_cast<unsigned char>(10+i);
      }
      t[static_cast<unsigned char>('x')] = 0xFE;
      t[static_cast<unsigned char>('X')] = 0xFE;
      return t;
    }

    inline constexpr std::array<unsigned char,256> DECODE = make_decode();

    inline bool is_space(unsigned char c) noexcept {
      return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\f'||c=='\v';
    }
    inline bool is_sep(unsigned char c, std::string_view set) noexcept {
      for (char s : set) if ((unsigned char)s == c) return true; return false;
    }

    inline std::size_t encoded_len_core(std::size_t n, const EncodeOptions& opt) {
      if (n==0) return 0;
      const std::size_t per_byte = (opt.prefix_0x?2:0) + 2; // 0x + two hex
      std::size_t len = per_byte * n;
      if (opt.group_every>0 && !opt.separator.empty()) {
        std::size_t groups = (n / opt.group_every);
        if (n % opt.group_every == 0) groups = (groups>0? groups-1 : 0);
        len += groups * opt.separator.size();
      }
      return len;
    }

  } // namespace detail

  // ───────────── Encode API
  inline std::size_t encoded_length(std::size_t input_len, const EncodeOptions& opt = {}) {
    return detail::encoded_len_core(input_len, opt);
  }

  inline Result<std::string> encode(BytesView src, const EncodeOptions& opt = {}) {
    if (src.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
      return xps::unexpected<std::string>(std::string{"[LengthOverflow] input too large"});
    const char* lut = (opt.casing==LetterCase::Lower) ? detail::HEX_LOWER : detail::HEX_UPPER;
    const std::size_t total = detail::encoded_len_core(src.size(), opt);
    std::string out; out.reserve(total);

    std::size_t count_in_group = 0;
    for (std::size_t i=0;i<src.size();++i) {
      if (opt.group_every>0 && count_in_group==opt.group_every) {
        if (!opt.separator.empty()) out.append(opt.separator);
        count_in_group = 0;
      }
      if (opt.prefix_0x) out.append("0x");
      unsigned v = std::to_integer<unsigned>(src[i]);
      out.push_back(lut[(v>>4)&0xF]);
      out.push_back(lut[v&0xF]);
      ++count_in_group;
    }

    return out;
  }

  inline Result<std::string> encode(std::string_view s, const EncodeOptions& opt = {}) {
    return encode(BytesView{ reinterpret_cast<const std::byte*>(s.data()), s.size() }, opt);
  }

  // ───────────── Decode API
  inline Result<Bytes> decode(std::string_view s, const DecodeOptions& opt = {}) {
    Bytes out; out.reserve(s.size()/2 + 1);
    int have_hi = -1; // -1 none, else 0..15

    for (size_t i=0;i<s.size(); ++i) {
      unsigned char c = static_cast<unsigned char>(s[i]);
      if (opt.accept_whitespace && detail::is_space(c)) continue;
      if (opt.accept_separators && detail::is_sep(c, opt.separators)) continue;

      if (opt.accept_0x && c=='0') {
        // peek next for x/X
        if (i+1<s.size() && detail::DECODE[ static_cast<unsigned char>(s[i+1]) ] == 0xFE) { i++; continue; }
      }

      unsigned char v = detail::DECODE[c];
      if (v==0xFF) return xps::unexpected<std::string>(std::string{"[Invalid] non-hex character"});
      if (v==0xFE) {
        if (opt.accept_0x) continue;                // stray 'x' tolerated only when accept_0x=true
        return xps::unexpected<std::string>(std::string{"[Invalid] unexpected 'x' without 0x enabled"});
      }

      if (have_hi<0) {
        have_hi = v;
      } else {
        out.push_back( std::byte( static_cast<unsigned char>((have_hi<<4) | v) ) );
        have_hi = -1;
      }
    }

    if (have_hi>=0) {
      if (opt.require_even_length) return xps::unexpected<std::string>(std::string{"[Invalid] odd number of hex digits"});
      if (opt.pad_low_if_odd) out.push_back( std::byte( static_cast<unsigned char>(have_hi<<4) ) );
      // else drop dangling nibble
    }

    return out;
  }

  inline Result<Bytes> decode(const char* s, const DecodeOptions& opt = {}) {
    if (!s) return xps::unexpected<std::string>(std::string{"[Invalid] null pointer"});
    return decode(std::string_view{s, std::strlen(s)}, opt);
  }

  // ───────────── Streaming encoder/decoder
  class Encoder {
  public:
    explicit Encoder(EncodeOptions opt = {}) : _opt(opt) {}

    void feed(BytesView chunk, std::string& out) {
      const char* lut = (_opt.casing==LetterCase::Lower) ? detail::HEX_LOWER : detail::HEX_UPPER;
      for (std::size_t i=0;i<chunk.size(); ++i) {
        if (_opt.group_every>0 && _in_group==_opt.group_every) {
          if (!_opt.separator.empty()) out.append(_opt.separator);
          _in_group = 0;
        }
        if (_opt.prefix_0x) out.append("0x");
        unsigned v = std::to_integer<unsigned>(chunk[i]);
        out.push_back(lut[(v>>4)&0xF]);
        out.push_back(lut[v&0xF]);
        ++_in_group;
      }
    }

    void finalize(std::string& /*out*/) {}

  private:
    EncodeOptions _opt{}; std::size_t _in_group{0};
  };

  class Decoder {
  public:
    explicit Decoder(DecodeOptions opt = {}) : _opt(opt) {}

    Result<void> feed(std::string_view s, Bytes& out) {
      // عالج حالة "0" المعلّقة من الدفعة السابقة (إن وُجدت)
      if (_opt.accept_0x && _pending_zero) {
        if (!s.empty() && (s.front()=='x' || s.front()=='X')) {
          // 0x: تخطَّ 'x' واعتبر البادئة مستهلكة
          s.remove_prefix(1);
        } else {
          // ليست بادئة؛ اعتبر '0' السابقة نصف بايت سداسي عشري
          if (_have_hi<0) _have_hi = 0;
          else { out.push_back(std::byte(static_cast<unsigned char>((_have_hi<<4)|0))); _have_hi=-1; }
        }
        _pending_zero = false;
      }

      for (size_t i=0;i<s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (_opt.accept_whitespace && detail::is_space(c)) continue;
        if (_opt.accept_separators && detail::is_sep(c, _opt.separators)) continue;

        if (_opt.accept_0x && c=='0') {
          if (i+1<s.size()) {
            if (detail::DECODE[ static_cast<unsigned char>(s[i+1]) ] == 0xFE) { i++; continue; } // skip 0x/0X
          } else {
            // قد تكون بادئة مجزّأة عبر حدود الدُفعات
            _pending_zero = true;
            continue;
          }
        }

        unsigned char v = detail::DECODE[c];
        if (v==0xFF) return xps::unexpected<std::string>(std::string{"[Invalid] non-hex character"});
        if (v==0xFE) {
          if (_opt.accept_0x) continue; // tolerate stray x/X only when enabled
          return xps::unexpected<std::string>(std::string{"[Invalid] unexpected 'x' without 0x enabled"});
        }
        if (_have_hi<0) _have_hi = v;
        else { out.push_back(std::byte(static_cast<unsigned char>((_have_hi<<4)|v))); _have_hi=-1; }
      }
      return {};
    }

    Result<void> finalize(Bytes& out) {
      // سَوِّ حالة '0' المعلقة إن بقيت ولم تتبعها 'x'
      if (_opt.accept_0x && _pending_zero) {
        if (_have_hi<0) _have_hi = 0;
        else { out.push_back(std::byte(static_cast<unsigned char>((_have_hi<<4)|0))); _have_hi=-1; }
        _pending_zero = false;
      }

      if (_have_hi>=0) {
        if (_opt.require_even_length) return xps::unexpected<std::string>(std::string{"[Invalid] odd number of hex digits"});
        if (_opt.pad_low_if_odd) out.push_back(std::byte(static_cast<unsigned char>(_have_hi<<4)));
        _have_hi = -1;
      }
      return {};
    }

  private:
    DecodeOptions _opt{};
    int  _have_hi{-1};
    bool _pending_zero{false}; // يتتبّع نهاية دفعة سابقة بحرف '0' لاحتمال 0x عبر الحدود
  };

  // ───────────── Self-test (quick)
  inline xps::expected<void, std::string> selftest_minimal() {
    static const unsigned char RAW[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23 };
    BytesView v{ reinterpret_cast<const std::byte*>(RAW), sizeof(RAW) };

    // Basic encode (lower)
    auto s1 = encode(v, EncodeOptions{.casing=LetterCase::Lower});
    if (!s1) return xps::unexpected<std::string>(s1.error());
    if (*s1 != std::string("deadbeef0123")) return xps::unexpected<std::string>(std::string{"encode lower mismatch"});

    // Upper + grouping + prefix
    auto s2 = encode(v, EncodeOptions{.casing=LetterCase::Upper, .prefix_0x=true, .separator=" ", .group_every=2});
    if (!s2) return xps::unexpected<std::string>(s2.error());
    if (*s2 != std::string("0xDE0xAD 0xBE0xEF 0x010x23")) return xps::unexpected<std::string>(std::string{"encode advanced mismatch"});

    // Decode with separators and 0x
    auto d1 = decode(*s2, DecodeOptions{});
    if (!d1) return xps::unexpected<std::string>(d1.error());
    if (d1->size()!=sizeof(RAW) || !std::equal(d1->begin(), d1->end(), (const std::byte*)RAW))
      return xps::unexpected<std::string>(std::string{"decode mismatch"});

    // Streaming encode/decode
    Encoder E{ EncodeOptions{} }; std::string enc; E.feed(v.first(3), enc); E.feed(v.subspan(3), enc); E.finalize(enc);
    auto d2 = decode(enc); if (!d2) return xps::unexpected<std::string>(d2->size()?"":"decode error");
    if (d2->size()!=sizeof(RAW) || !std::equal(d2->begin(), d2->end(), (const std::byte*)RAW))
      return xps::unexpected<std::string>(std::string{"streaming mismatch"});

    // Odd-length tolerant decode
    auto d3 = decode("abc", DecodeOptions{.require_even_length=false, .pad_low_if_odd=true});
    if (!d3) return xps::unexpected<std::string>(d3.error());
    if (d3->size()!=2 || std::to_integer<unsigned>(d3->at(0))!=0xAB || std::to_integer<unsigned>(d3->at(1))!=0xC0)
      return xps::unexpected<std::string>(std::string{"odd-length handling mismatch"});

    // New: stray 'x' should fail when accept_0x=false
    if (auto d4 = decode("12x3", DecodeOptions{.accept_0x=false}); d4) {
      return xps::unexpected<std::string>(std::string{"unexpected success on stray 'x' with accept_0x=false"});
    }

    // New: streaming 0x across chunk boundary: "0" | "xDE AD"
    {
      Decoder D{ DecodeOptions{.accept_0x=true} }; Bytes out;
      if (auto r = D.feed("0", out); !r) return xps::unexpected<std::string>(std::string{"stream 0x step1 fail"});
      if (auto r = D.feed("xDE AD", out); !r) return xps::unexpected<std::string>(std::string{"stream 0x step2 fail"});
      if (auto r = D.finalize(out); !r) return xps::unexpected<std::string>(std::string{"stream 0x finalize fail"});
      if (out.size()!=2 || std::to_integer<unsigned>(out[0])!=0xDE || std::to_integer<unsigned>(out[1])!=0xAD)
        return xps::unexpected<std::string>(std::string{"stream 0x across-boundary mismatch"});
    }

    return {};
  }

  // ───────────── Backwards-compat helper (as in skeleton)
  // Returns pointer to thread-local buffer valid until next call on same thread.
  inline const char* hex(const unsigned char* p, int n) {
    thread_local std::string buf;
    if (!p || n<=0) { buf.clear(); return buf.c_str(); }
    BytesView v{ reinterpret_cast<const std::byte*>(p), static_cast<std::size_t>(n) };
    auto r = encode(v, EncodeOptions{ .casing=LetterCase::Lower, .prefix_0x=false, .separator="", .group_every=0 });
    buf = r ? *r : std::string{};
    return buf.c_str();
  }

} // namespace xps::intx

