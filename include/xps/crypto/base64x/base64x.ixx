module; // ─────────────────────────────────────────────────────────────────────
// Global module fragment — standard headers (not exported)
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <array>
#include <optional>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <limits>
#include <cmath>

#if defined(__x86_64__) || defined(__i386__)
  #define XPS_B64X_ON_X86 1
  #include <immintrin.h>   
  #include <smmintrin.h>   
#else
  #define XPS_B64X_ON_X86 0
#endif

#ifndef XPS_B64X_ENABLE_THREATS
  #define XPS_B64X_ENABLE_THREATS 1
#endif
// ─────────────────────────────────────────────────────────────────────────────
export module xps.base64x;

// Project modules
import xps.crypto.internal.common;
import xps.expected;        // expected<T, string> wrapper
import xps.internal.base64; // exports xps::intx::{encode, decode, EncodeOptions, DecodeOptions, Variant}

// ─────────────────────────────────────────────────────────────────────────────
// experimental.base64x — Base64 extensions over RFC 4648
//   • Profiles: Standard/URL + experimental (AI/Blockchain/Quantum)
//   • Analytics (optional), CRC32 helpers, simple stego
//   • Threat scanning & content heuristics (bank/API/keys/PII) [gated]
//   • SIMD map path (runtime) for Standard→URL mapping ('+','/' → '-','_'): AVX2 > SSE4.1 > Scalar
// ─────────────────────────────────────────────────────────────────────────────

export namespace xps::b64x {

  using Bytes     = std::vector<std::byte>;
  template<class T>
  using Result    = xps::expected<T, std::string>;
  using BytesView = std::span<const std::byte>;

  // ------------------------------ Profiles -----------------------------------
  enum class ProfileId : std::uint8_t {
    Standard,
    Url,
    // Experimental alphabets (non-standard; private ecosystems)
    AI_Optimized,
    Blockchain,
    Quantum
  };

  struct AlphabetProfile {
    std::string_view               name{};
    std::array<char,64>            map{};   // index→char
    std::array<unsigned char,256>  rev{};   // char→index or 0x80 invalid
    char                           pad{'='};
  };

  namespace detail {

    inline constexpr char ALPH_STD[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    inline constexpr char ALPH_URL[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    inline constexpr char ALPH_AI[] =
      "aeionsrhltdcumfgpywbvkjxqzAEIONSRHLTDCUMFGPYWBVKJXQZ0123456789+/";
    inline constexpr char ALPH_BLOCKCHAIN[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    inline constexpr char ALPH_QUANTUM[] =
      "kLmNoPqRsTuVwXyZaBcDeFgHiJkMnOpQrStUvWxYzAbCdEfGhIjKl0123456789+/";

    inline AlphabetProfile make_profile(std::string_view name, const char* alpha64) {
      AlphabetProfile p;
      p.name = name;
      for (int i=0;i<64;i++) p.map[static_cast<std::size_t>(i)] = alpha64[i];
      p.rev.fill(0x80);
      for (int i=0;i<64;i++) {
        p.rev[ static_cast<unsigned char>(alpha64[i]) ] = static_cast<unsigned char>(i);
      }
      p.pad = '=';
      return p;
    }

    inline const AlphabetProfile& std_profile() {
      static AlphabetProfile P = make_profile("standard", ALPH_STD);
      return P;
    }
    inline const AlphabetProfile& url_profile() {
      static AlphabetProfile P = make_profile("url", ALPH_URL);
      return P;
    }
    inline const AlphabetProfile& ai_profile() {
      static AlphabetProfile P = make_profile("ai", ALPH_AI);
      return P;
    }
    inline const AlphabetProfile& blockchain_profile() {
      static AlphabetProfile P = make_profile("blockchain", ALPH_BLOCKCHAIN);
      return P;
    }
    inline const AlphabetProfile& quantum_profile() {
      static AlphabetProfile P = make_profile("quantum", ALPH_QUANTUM);
      return P;
    }

    inline const AlphabetProfile& get_profile(ProfileId id) {
      switch (id) {
        case ProfileId::Standard:    return std_profile();
        case ProfileId::Url:         return url_profile();
        case ProfileId::AI_Optimized:return ai_profile();
        case ProfileId::Blockchain:  return blockchain_profile();
        case ProfileId::Quantum:     return quantum_profile();
      }
      return std_profile();
    }

    inline const std::array<unsigned char,256>& std_rev() {
      static std::array<unsigned char,256> R = []{
        std::array<unsigned char,256> T{}; T.fill(0x80);
        for (int i=0;i<64;i++) T[ static_cast<unsigned char>(ALPH_STD[i]) ] = static_cast<unsigned char>(i);
        return T;
      }();
      return R;
    }

    inline bool is_ws(unsigned char c) noexcept {
      return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f' || c=='\v';
    }

    // (1) Helper: URL-safe char check & logical index for analytics
    inline constexpr bool is_b64url_char(unsigned char c) noexcept {
      return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_';
    }

    inline unsigned char logical_index(ProfileId prof, unsigned char ch) noexcept {
      if (prof == ProfileId::Url) {
        if (ch=='-') return 62;
        if (ch=='_') return 63;
        unsigned char idx = std_rev()[ch]; // other chars same as Standard
        return idx;
      }
      if (prof == ProfileId::Standard) {
        return std_rev()[ch];
      }
      // experimental profiles: use their reverse maps
      const auto& pr = get_profile(prof);
      return pr.rev[ch];
    }

    // CRC32 (poly 0xEDB88320) — thread-safe static
    inline std::uint32_t crc32(const std::byte* data, std::size_t n) {
      static const std::array<std::uint32_t,256> table = []{
        std::array<std::uint32_t,256> T{};
        for (std::uint32_t i=0;i<256;i++){
          std::uint32_t c=i;
          for (int j=0;j<8;j++) c = (c&1) ? (0xEDB88320u ^ (c>>1)) : (c>>1);
          T[i]=c;
        }
        return T;
      }();
      std::uint32_t crc = 0xFFFFFFFFu;
      const unsigned char* p = reinterpret_cast<const unsigned char*>(data);
      for (std::size_t i=0;i<n;i++) crc = table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
      return crc ^ 0xFFFFFFFFu;
    }

    inline std::string to_hex32(std::uint32_t v){
      static const char* HEX="0123456789abcdef";
      std::string s; s.resize(8);
      for (int i=7;i>=0;--i){ s[i]=HEX[v & 0xF]; v >>= 4; }
      return s;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SIMD helpers (runtime) — AVX2 / SSE4.1 mapping: '+'→'-', '/'→'_'
    // ─────────────────────────────────────────────────────────────────────────
#if XPS_B64X_ON_X86
    inline bool has_avx2() noexcept {
    #if defined(__GNUC__) || defined(__clang__)
      return __builtin_cpu_supports("avx2");
    #else
      return false;
    #endif
    }
    inline bool has_sse41() noexcept {
    #if defined(__GNUC__) || defined(__clang__)
      return __builtin_cpu_supports("sse4.1");
    #else
      return false;
    #endif
    }

    // AVX2 implementation
    [[gnu::target("avx2")]]
     void avx2_map_std_to_url(char* dst, const char* src, std::size_t len) {
      const __m256i plus  = _mm256_set1_epi8('+');
      const __m256i slash = _mm256_set1_epi8('/');
      const __m256i dash  = _mm256_set1_epi8('-');
      const __m256i under = _mm256_set1_epi8('_');
      std::size_t i=0;
      for (; i+32<=len; i+=32) {
        __m256i v  = _mm256_loadu_si256((const __m256i*)(src+i));
        __m256i v1 = _mm256_blendv_epi8(v,  dash,  _mm256_cmpeq_epi8(v, plus));
        __m256i v2 = _mm256_blendv_epi8(v1, under, _mm256_cmpeq_epi8(v, slash));
        _mm256_storeu_si256((__m256i*)(dst+i), v2);
      }
      for (; i<len; ++i) { char c=src[i]; if (c=='+') c='-'; else if (c=='/') c='_'; dst[i]=c; }
    }

    // SSE4.1 implementation
    [[gnu::target("sse4.1")]]
     void sse41_map_std_to_url(char* dst, const char* src, std::size_t len) {
      const __m128i plus  = _mm_set1_epi8('+');
      const __m128i slash = _mm_set1_epi8('/');
      const __m128i dash  = _mm_set1_epi8('-');
      const __m128i under = _mm_set1_epi8('_');
      std::size_t i=0;
      for (; i+16<=len; i+=16) {
        __m128i v  = _mm_loadu_si128((const __m128i*)(src+i));
        __m128i v1 = _mm_blendv_epi8(v,  dash,  _mm_cmpeq_epi8(v, plus));
        __m128i v2 = _mm_blendv_epi8(v1, under, _mm_cmpeq_epi8(v, slash));
        _mm_storeu_si128((__m128i*)(dst+i), v2);
      }
      for (; i<len; ++i) { char c=src[i]; if (c=='+') c='-'; else if (c=='/') c='_'; dst[i]=c; }
    }
#endif // XPS_B64X_ON_X86

  } // namespace detail

  // ----------------------------- Options / Analytics --------------------------
  struct Options {
    ProfileId   profile { ProfileId::Standard };
    bool        pad     { true };
    std::size_t line_len{ 0 };
    bool        use_crlf{ false };
    bool        analytics{ false };

    // New granular decode controls
    bool        ignore_whitespace { true };
    bool        url_relaxed       { true };
  };

  struct Analytics {
    std::size_t input_bytes{0};
    std::size_t output_chars{0}; // for decode this means output_bytes
    double      encode_ms{0};
    double      decode_ms{0};
    std::array<std::uint32_t,64> symbol_freq{};
  };

#if XPS_B64X_ENABLE_THREATS
  // ----------------------------- Threat Scanning ------------------------------
  enum class MimeKind : std::uint8_t {
    Unknown, TextLikely, BinaryLikely,
    HTML, JavaScript, PDF, ZIP, ELF, PE, PNG, JPEG
  };

  struct ThreatFinding {
    std::string category;     // e.g., "XSS", "RCE", "Suspicious MIME", "Banking", "API Key"
    std::string snippet;      // tiny excerpt or matched token
    int         severity{0};  // 1..100
  };

  struct ThreatReport {
    MimeKind                  mime{MimeKind::Unknown};
    bool                      potential_threat{false};
    int                       risk_score{0}; // cumulative 0..100
    std::vector<ThreatFinding> findings;
  };

  namespace sec {

    // ---- Banking/PII helpers ----
    inline bool luhn_valid_digits(const char* p, std::size_t n) {
      int sum = 0; bool alt = false;
      for (std::size_t i=0;i<n;i++) {
        char c = p[n-1-i];
        if (c<'0' || c>'9') return false;
        int d = c - '0';
        if (alt) { d *= 2; if (d > 9) d -= 9; }
        sum += d; alt = !alt;
      }
      return (sum % 10) == 0;
    }

    inline bool is_card_number(std::string_view s, std::size_t& from, std::size_t& to) {
      // scan for 13..19 digits allowing spaces/dashes
      const std::size_t N = s.size();
      for (std::size_t i=0;i<N;i++) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) continue;
        std::string tmp; tmp.reserve(25);
        std::size_t j = i;
        while (j<N && (std::isdigit(static_cast<unsigned char>(s[j])) || s[j]==' ' || s[j]=='-')) {
          if (std::isdigit(static_cast<unsigned char>(s[j]))) tmp.push_back(s[j]);
          j++;
          if (tmp.size()>19) break;
        }
        if (tmp.size()>=13 && tmp.size()<=19 && luhn_valid_digits(tmp.data(), tmp.size())) {
          from = i; to = j;
          return true;
        }
      }
      return false;
    }

    inline int char_to_iban_val(char c) {
      if (c>='0' && c<='9') return c - '0';
      if (c>='A' && c<='Z') return c - 'A' + 10;
      if (c>='a' && c<='z') return c - 'a' + 10;
      return -1;
    }

    inline bool iban_mod97_ok(std::string_view iban) {
      // remove spaces, move first 4 chars to end, compute mod 97
      std::string norm; norm.reserve(iban.size());
      for (char c : iban) if (c!=' ' && c!='-') norm.push_back(c);
      if (norm.size() < 15 || norm.size() > 34) return false;
      // country(2 letters) + check(2 digits)
      if (!std::isalpha(static_cast<unsigned char>(norm[0])) ||
          !std::isalpha(static_cast<unsigned char>(norm[1])) ||
          !std::isdigit(static_cast<unsigned char>(norm[2])) ||
          !std::isdigit(static_cast<unsigned char>(norm[3]))) return false;

      std::rotate(norm.begin(), norm.begin()+4, norm.end());
      // stream mod 97
      int mod = 0;
      for (char c : norm) {
        int v = char_to_iban_val(c);
        if (v < 0) return false;
        if (v >= 10) {
          mod = (mod*100 + v) % 97;
        } else {
          mod = (mod*10 + v) % 97;
        }
      }
      return mod == 1;
    }

    inline bool find_iban(std::string_view s, std::size_t& from, std::size_t& to, std::string& matched) {
      const std::size_t N = s.size();
      for (std::size_t i=0;i+3<N;i++) {
        if (!std::isalpha(static_cast<unsigned char>(s[i])) ||
            !std::isalpha(static_cast<unsigned char>(s[i+1])) ||
            !std::isdigit(static_cast<unsigned char>(s[i+2])) ||
            !std::isdigit(static_cast<unsigned char>(s[i+3]))) continue;

        // Collect up to 34 alnum with spaces/dashes allowed
        std::size_t j = i;
        std::string cand; cand.reserve(40);
        while (j<N && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j]==' ' || s[j]=='-')) {
          cand.push_back(s[j]); j++;
          if (cand.size() > 40) break;
        }
        if (iban_mod97_ok(cand)) {
          from = i; to = j; matched = cand;
          return true;
        }
      }
      return false;
    }

    inline bool is_bic_code(std::string_view s) {
      auto upper = [](char c){ return std::toupper(static_cast<unsigned char>(c)); };
      std::string t{s};
      for (char& c : t) c = upper(c);
      auto ok8  = t.size()==8;
      auto ok11 = t.size()==11;
      if (!ok8 && !ok11) return false;
      auto alpha = [](char c){ return c>='A' && c<='Z'; };
      auto alnum = [&](char c){ return alpha(c) || (c>='0' && c<='9'); };
      if (!(alpha(t[0])&&alpha(t[1])&&alpha(t[2])&&alpha(t[3]))) return false; // bank
      if (!(alpha(t[4])&&alpha(t[5]))) return false; // country
      if (!(alnum(t[6])&&alnum(t[7]))) return false; // location
      if (ok11) { if (!(alnum(t[8])&&alnum(t[9])&&alnum(t[10]))) return false; }
      return true;
    }

    inline bool detect_bic(std::string_view s, std::size_t& from, std::size_t& to, std::string& matched) {
      const std::size_t N = s.size();
      for (std::size_t i=0;i<N;i++) {
        if (!std::isalpha(static_cast<unsigned char>(s[i]))) continue;
        if (i+8 <= N) {
          std::string_view v8{s.data()+i, 8};
          if (is_bic_code(v8)) { from=i; to=i+8; matched = std::string(v8); return true; }
        }
        if (i+11 <= N) {
          std::string_view v11{s.data()+i, 11};
          if (is_bic_code(v11)) { from=i; to=i+11; matched = std::string(v11); return true; }
        }
      }
      return false;
    }

    // ---- JWT/API keys/Secrets/PEM/DB URIs ----
    inline bool is_b64url_token(std::string_view t) {
      if (t.empty()) return false;
      for (char c : t) {
        if (!detail::is_b64url_char(static_cast<unsigned char>(c))) return false;
      }
      return true;
    }

    inline bool detect_jwt(std::string_view s, std::size_t& from, std::size_t& to) {
      // look for header.payload.signature by spans of base64url characters separated by '.'
      const std::size_t N = s.size();
      for (std::size_t i=0;i<N;i++) {
        // find first '.'
        std::size_t dot1 = s.find('.', i);
        if (dot1 == std::string_view::npos) break;
        std::size_t dot2 = s.find('.', dot1+1);
        if (dot2 == std::string_view::npos) break;

        std::string_view a{s.data()+i,           dot1 - i};
        std::string_view b{s.data()+dot1+1,      dot2 - (dot1+1)};

        // signature token: extend while base64url chars
        std::size_t endSig = dot2+1;
        while (endSig < N && detail::is_b64url_char(static_cast<unsigned char>(s[endSig]))) ++endSig;
        std::string_view c{s.data()+dot2+1,      endSig - (dot2+1)};

        if (a.size()>=2 && b.size()>=2 && c.size()>=2 &&
            is_b64url_token(a) && is_b64url_token(b) && is_b64url_token(c)) {
          // Try decode header and check for "alg"
          auto dh = xps::intx::decode(a, xps::intx::DecodeOptions{
                    .variant=xps::intx::Variant::Url,
                    .accept_whitespace=false,.require_padding=false,.url_relaxed=true});
          if (dh && dh->size()>0) {
            // robust temporary string for scanning (avoid debug-mode UB on non-text)
            std::string hdr(reinterpret_cast<const char*>(dh->data()),
                            reinterpret_cast<const char*>(dh->data()) + dh->size());
            if (hdr.find("\"alg\"") != std::string::npos) { from=i; to=endSig; return true; }
          }
        }
        i = dot1; // continue after first dot
      }
      return false;
    }

    inline void push(ThreatReport& rep, std::string cat, std::string snip, int sev) {
      rep.findings.push_back({std::move(cat), std::move(snip), sev});
      rep.risk_score += sev;
      rep.potential_threat = true;
      if (rep.risk_score > 100) rep.risk_score = 100;
    }

    inline MimeKind sniff(BytesView b) {
      if (b.size() >= 2 && std::to_integer<unsigned char>(b[0])==0x4D && std::to_integer<unsigned char>(b[1])==0x5A) return MimeKind::PE;      // MZ
      if (b.size() >= 4 && std::to_integer<unsigned char>(b[0])==0x7F && std::to_integer<unsigned char>(b[1])==0x45 &&
                          std::to_integer<unsigned char>(b[2])==0x4C && std::to_integer<unsigned char>(b[3])==0x46)   return MimeKind::ELF;     // 0x7F 'E''L''F'
      if (b.size() >= 4 && std::to_integer<unsigned char>(b[0])==0x25 && std::to_integer<unsigned char>(b[1])==0x50 &&
                          std::to_integer<unsigned char>(b[2])==0x44 && std::to_integer<unsigned char>(b[3])==0x46)   return MimeKind::PDF;     // %PDF
      if (b.size() >= 4 && std::to_integer<unsigned char>(b[0])==0x50 && std::to_integer<unsigned char>(b[1])==0x4B &&
                          std::to_integer<unsigned char>(b[2])==0x03 && std::to_integer<unsigned char>(b[3])==0x04)   return MimeKind::ZIP;     // PK..
      if (b.size() >= 8 && std::to_integer<unsigned char>(b[0])==0x89 && std::to_integer<unsigned char>(b[1])==0x50 &&
                          std::to_integer<unsigned char>(b[2])==0x4E && std::to_integer<unsigned char>(b[3])==0x47)   return MimeKind::PNG;
      if (b.size() >= 3 && std::to_integer<unsigned char>(b[0])==0xFF && std::to_integer<unsigned char>(b[1])==0xD8 &&
                          std::to_integer<unsigned char>(b[2])==0xFF)                                                return MimeKind::JPEG;

      // quick text heuristic: count control bytes
      std::size_t ctrl=0, n=b.size();
      const std::size_t K = std::min<std::size_t>(n, 4096);
      for (std::size_t i=0;i<K;i++){
        unsigned char c = std::to_integer<unsigned char>(b[i]);
        if (c<9 || (c>13 && c<32)) ctrl++;
      }
      if (K>0 && (100*ctrl/K) <= 2) return MimeKind::TextLikely;
      return MimeKind::Unknown;
    }

    inline void scan_text_common(std::string_view s, ThreatReport& rep) {
      auto contains = [&](std::string_view needle){ return s.find(needle) != std::string_view::npos; };

      if (contains("<script"))      push(rep, "XSS", "<script", 12);
      if (contains("javascript:"))  push(rep, "XSS", "javascript:", 10);
      if (contains("onerror=") || contains("onload=")) push(rep, "XSS", "inline handler", 8);
      if (contains("eval(") || contains("Function("))  push(rep, "JS Eval", "eval/Function", 8);
      if (contains("XMLHttpRequest(") || contains("fetch(")) push(rep, "Network", "XHR/fetch", 4);
      if (contains("system(") || contains("exec("))    push(rep, "RCE", "system/exec", 15);
      if (contains("<?php"))         push(rep, "Server-Side", "<?php", 12);
      if (contains("<iframe"))       push(rep, "XSS", "<iframe", 6);
      if (contains("<img"))          push(rep, "XSS", "<img", 4);
      if (contains("document.cookie")) push(rep, "Data Exfil", "document.cookie", 9);

      if (s.find("<html")!=std::string_view::npos || s.find("<!DOCTYPE html")!=std::string_view::npos) rep.mime = MimeKind::HTML;
      if (s.find("function(")!=std::string_view::npos || s.find("=>")!=std::string_view::npos)         rep.mime = MimeKind::JavaScript;
    }

    inline void scan_text_sensitive(std::string_view s, ThreatReport& rep) {
      // PEM / keys
      if (s.find("-----BEGIN PRIVATE KEY-----") != std::string_view::npos ||
          s.find("-----BEGIN RSA PRIVATE KEY-----") != std::string_view::npos ||
          s.find("-----BEGIN EC PRIVATE KEY-----") != std::string_view::npos) {
        push(rep, "Secret", "PEM Private Key", 40);
      }
      if (s.find("-----BEGIN OPENSSH PRIVATE KEY-----") != std::string_view::npos) {
        push(rep, "Secret", "OpenSSH Private Key", 40);
      }

      // Authorization tokens
      if (s.find("Authorization: Bearer ") != std::string_view::npos ||
          s.find("authorization: Bearer ") != std::string_view::npos ||
          s.find("Bearer ") != std::string_view::npos) {
        push(rep, "Auth", "Bearer token", 12);
      }

      // JWT
      std::size_t f=0,t=0;
      if (detect_jwt(s, f, t)) {
        push(rep, "Auth", "JWT token", 14);
      }

      // AWS keys
      if (s.find("AWS_SECRET_ACCESS_KEY") != std::string_view::npos ||
          s.find("aws_secret_access_key") != std::string_view::npos) {
        push(rep, "Cloud", "AWS Secret Access Key ref", 16);
      }
      if (s.find("AWS_ACCESS_KEY_ID") != std::string_view::npos ||
          s.find("aws_access_key_id") != std::string_view::npos) {
        push(rep, "Cloud", "AWS Access Key ID ref", 8);
      }
      // AKIA pattern (heuristic)
      for (std::size_t i=0;i+20<=s.size();++i) {
        if (s[i]=='A'&&s[i+1]=='K'&&s[i+2]=='I'&&s[i+3]=='A') {
          bool ok=true;
          for (std::size_t k=4;k<20;k++){
            char c = s[i+k];
            if (!std::isalnum(static_cast<unsigned char>(c))) { ok=false; break; }
          }
          if (ok) { push(rep, "Cloud", "AKIA******** (AWS Access Key ID)", 14); break; }
        }
      }

      // Google API key AIza...
      for (std::size_t i=0;i+39<=s.size();++i) {
        if (s[i]=='A'&&s[i+1]=='I'&&s[i+2]=='z'&&s[i+3]=='a') {
          bool ok=true;
          for (std::size_t k=4;k<39;k++){
            char c = s[i+k];
            if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-')) { ok=false; break; }
          }
          if (ok) { push(rep, "API Key", "Google API Key (AIza...)", 12); break; }
        }
      }

      // Slack tokens
      if (s.find("xoxb-") != std::string_view::npos || s.find("xoxp-") != std::string_view::npos ||
          s.find("xoxa-") != std::string_view::npos || s.find("xoxs-") != std::string_view::npos) {
        push(rep, "API Key", "Slack token", 12);
      }

      // GitHub tokens
      if (s.find("ghp_") != std::string_view::npos || s.find("github_pat_") != std::string_view::npos) {
        push(rep, "API Key", "GitHub token", 12);
      }

      // DB URIs / conn strings
      if (s.find("postgres://") != std::string_view::npos ||
          s.find("postgresql://") != std::string_view::npos ||
          s.find("mysql://") != std::string_view::npos ||
          s.find("mongodb://") != std::string_view::npos ||
          s.find("redis://") != std::string_view::npos ||
          s.find("amqp://") != std::string_view::npos ||
          s.find("amqps://") != std::string_view::npos ||
          s.find("jdbc:") != std::string_view::npos ||
          s.find("sqlserver://") != std::string_view::npos) {
        push(rep, "Secrets", "DB/Queue connection URI", 10);
      }
      if (s.find("password=") != std::string_view::npos || s.find("pwd=") != std::string_view::npos) {
        push(rep, "Secrets", "Connection string with password=", 10);
      }

      // Banking: IBAN / BIC / cards
      std::size_t a=0,b=0; std::string iban;
      if (find_iban(s, a, b, iban)) {
        push(rep, "Banking", "IBAN detected", 10);
      }
      std::string bic;
      if (detect_bic(s, a, b, bic)) {
        push(rep, "Banking", "SWIFT/BIC detected", 6);
      }
      if (is_card_number(s, a, b)) {
        push(rep, "Banking", "PAN (card number) via Luhn", 18);
      }
    }

    inline void scan_text(std::string_view s, ThreatReport& rep) {
      scan_text_common(s, rep);
      scan_text_sensitive(s, rep);
    }

    inline void scan_binary(BytesView b, ThreatReport& rep) {
      auto m = sniff(b);
      if (m != MimeKind::Unknown) rep.mime = m;

      switch (m) {
        case MimeKind::PE:   push(rep, "Executable", "PE/MZ", 30); break;
        case MimeKind::ELF:  push(rep, "Executable", "ELF", 30);  break;
        case MimeKind::PDF:  push(rep, "Document",   "PDF", 6);   break;
        case MimeKind::ZIP:  push(rep, "Archive",    "ZIP", 4);   break;
        default: break;
      }

      // High-entropy heuristic (first 2KB)
      std::array<std::uint32_t,256> freq{};
      const std::size_t N = std::min<std::size_t>(b.size(), 2048);
      for (std::size_t i=0;i<N;i++) freq[ std::to_integer<unsigned char>(b[i]) ]++;
      double H = 0.0;
      for (auto c : freq) if (c) {
        double p = double(c)/double(N);
        H -= p * std::log2(p);
      }
      if (H > 7.5 && (rep.mime==MimeKind::Unknown || rep.mime==MimeKind::BinaryLikely)) {
        push(rep, "Entropy", "High entropy payload", 6);
      }

      // Try to extract ASCII window and run sensitive scan
      std::string ascii; ascii.reserve(std::min<std::size_t>(N, 4096));
      for (std::size_t i=0;i<N;i++) {
        unsigned char c = std::to_integer<unsigned char>(b[i]);
        if (c>=32 && c<127) ascii.push_back(static_cast<char>(c));
        else ascii.push_back(' ');
      }
      scan_text_sensitive(ascii, rep);
    }

    inline void analyze(BytesView b, ThreatReport& rep) {
      rep.mime = sniff(b);
      if (rep.mime==MimeKind::TextLikely || rep.mime==MimeKind::HTML || rep.mime==MimeKind::JavaScript) {
        std::string_view sv(reinterpret_cast<const char*>(b.data()), b.size());
        scan_text(sv, rep);
      } else {
        scan_binary(b, rep);
      }
      if (rep.risk_score > 100) rep.risk_score = 100;
    }

  } // namespace sec
#endif // XPS_B64X_ENABLE_THREATS

  // ----------------------------- Encode (with profile) ------------------------
  [[nodiscard]] Result<std::string>
  encode(BytesView src, const Options& opt, Analytics* stats = nullptr) {
    auto t0 = std::chrono::high_resolution_clock::now();

    xps::intx::EncodeOptions base_opt{
      .variant  = (opt.profile==ProfileId::Url ? xps::intx::Variant::Url
                                               : xps::intx::Variant::Standard),
      .pad      = opt.pad,
      .line_len = opt.line_len,
      .use_crlf = opt.use_crlf
    };

    auto base = xps::intx::encode(src, base_opt);
    if (!base) return xps::unexpected<std::string>(base.error());

    std::string out = std::move(*base);

    // Standard/URL are ready as-is
    if (opt.profile==ProfileId::Standard || opt.profile==ProfileId::Url) {
      if (stats) {
        auto t1 = std::chrono::high_resolution_clock::now();
        stats->input_bytes  = src.size();
        stats->output_chars = out.size();
        stats->encode_ms    = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (opt.analytics) {
          for (unsigned char ch : std::string_view{out}) {
            if (ch=='=' || detail::is_ws(ch)) continue;
            unsigned char idx = detail::logical_index(opt.profile, ch);
            if (idx<=63) stats->symbol_freq[idx]++;
          }
        }
      }
      return out;
    }

    // Experimental profiles: post-map Standard → custom alphabet
    const auto& prof = detail::get_profile(opt.profile);
    const auto& revS = detail::std_rev();
    for (char& ch : out) {
      if (ch=='=' || ch=='\n' || ch=='\r') continue;
      unsigned char idx = revS[static_cast<unsigned char>(ch)];
      if (idx<=63) ch = prof.map[idx];
      else return xps::unexpected<std::string>(std::string{"[b64x] unexpected char in base output"});
    }

    if (stats) {
      auto t1 = std::chrono::high_resolution_clock::now();
      stats->input_bytes  = src.size();
      stats->output_chars = out.size();
      stats->encode_ms    = std::chrono::duration<double, std::milli>(t1 - t0).count();
      if (opt.analytics) {
        for (unsigned char ch : std::string_view{out}) {
          if (ch=='=' || detail::is_ws(ch)) continue;
          unsigned char idx = detail::logical_index(opt.profile, ch);
          if (idx<=63) stats->symbol_freq[idx]++;
        }
      }
    }
    return out;
  }

  [[nodiscard]] Result<std::string>
  encode(std::string_view s, const Options& opt, Analytics* stats = nullptr) {
    return encode(BytesView{ reinterpret_cast<const std::byte*>(s.data()), s.size() }, opt, stats);
  }

  // ----------------------------- Decode (with profile) ------------------------
  [[nodiscard]] Result<Bytes>
  decode(std::string_view encoded, const Options& opt, Analytics* stats = nullptr) {
    auto t0 = std::chrono::high_resolution_clock::now();

    std::string mapped; mapped.reserve(encoded.size());
    if (opt.profile==ProfileId::Standard || opt.profile==ProfileId::Url) {
      mapped.assign(encoded.begin(), encoded.end());
    } else {
      const auto& prof = detail::get_profile(opt.profile);
      for (unsigned char c : std::string_view{encoded}) {
        if (c=='=' || detail::is_ws(c)) {
          mapped.push_back(static_cast<char>(c));
          continue;
        }
        unsigned char idx = prof.rev[c];
        if (idx<=63) mapped.push_back(detail::ALPH_STD[idx]);
        else return xps::unexpected<std::string>(std::string{"[b64x] invalid character for selected profile"});
      }
    }

    xps::intx::DecodeOptions base_opt{
      .variant           = (opt.profile==ProfileId::Url ? xps::intx::Variant::Url
                                                        : xps::intx::Variant::Standard),
      .accept_whitespace = opt.ignore_whitespace,
      .require_padding   = false,
      .url_relaxed       = opt.url_relaxed
    };

    auto dec = xps::intx::decode(std::string_view{mapped}, base_opt);
    if (!dec) return xps::unexpected<std::string>(dec.error());

    if (stats) {
      auto t1 = std::chrono::high_resolution_clock::now();
      stats->input_bytes  = encoded.size();
      stats->output_chars = dec->size(); // = output bytes
      stats->decode_ms    = std::chrono::duration<double, std::milli>(t1 - t0).count();
      if (opt.analytics) {
        for (unsigned char c : std::string_view{encoded}) {
          if (c=='=' || detail::is_ws(c)) continue;
          unsigned char idx = detail::logical_index(opt.profile, c);
          if (idx<=63) stats->symbol_freq[idx]++;
        }
      }
    }
    return *dec;
  }

  // ----------------------------- CRC helpers ---------------------------------
  struct EncodedWithCrc {
    std::string   encoded;
    std::uint32_t crc32{};
    std::string   crc32_hex() const { return detail::to_hex32(crc32); }
  };

  [[nodiscard]] Result<EncodedWithCrc>
  encode_with_crc(BytesView src, const Options& opt, Analytics* stats = nullptr) {
    auto enc = encode(src, opt, stats);
    if (!enc) return xps::unexpected<std::string>(enc.error());
    EncodedWithCrc out;
    out.encoded = std::move(*enc);
    out.crc32   = detail::crc32(src.data(), src.size());
    return out;
  }

  [[nodiscard]] Result<Bytes>
  decode_verify_crc(std::string_view encoded,
                    std::uint32_t expected_crc,
                    const Options& opt,
                    Analytics* stats = nullptr) {
    auto dec = decode(encoded, opt, stats);
    if (!dec) return xps::unexpected<std::string>(dec.error());
    auto got = detail::crc32(dec->data(), dec->size());
    if (got != expected_crc) {
      return xps::unexpected<std::string>(std::string{"[b64x] CRC32 mismatch"});
    }
    return *dec;
  }

  // ----------------------------- Steganography (simple) ----------------------
  [[nodiscard]] Result<std::string>
  encode_stego(BytesView data, BytesView cover,
               const Options& opt, Analytics* stats = nullptr) {
    Bytes combined;
    combined.reserve(data.size() + cover.size());
    std::size_t i=0, j=0;
    while (i<data.size() || j<cover.size()) {
      if (j<cover.size()) combined.push_back(cover[j++]);
      if (i<data.size())  combined.push_back(data[i++]);
    }
    return encode(BytesView{combined.data(), combined.size()}, opt, stats);
  }

  // ----------------------------- SIMD hook (runtime map to URL) --------------
  // Optimizes only the URL profile by encoding Standard first then mapping
  // '+'/'/' to '-'/'_' using AVX2 or SSE4.1 if available; otherwise fallback.
  [[nodiscard]] Result<std::string>
  encode_simd_if_available(BytesView src, const Options& opt,
                           Analytics* stats = nullptr) {
    if (opt.profile != ProfileId::Url) {
      return encode(src, opt, stats);
    }

    xps::intx::EncodeOptions base_opt{
      .variant  = xps::intx::Variant::Standard,
      .pad      = opt.pad,
      .line_len = opt.line_len,
      .use_crlf = opt.use_crlf
    };
    auto base = xps::intx::encode(src, base_opt);
    if (!base) return xps::unexpected<std::string>(base.error());

#if XPS_B64X_ON_X86
    if (detail::has_avx2()) {
      std::string out; out.resize(base->size());
      detail::avx2_map_std_to_url(out.data(), base->data(), base->size());
      if (stats) { stats->input_bytes  = src.size(); stats->output_chars = out.size(); }
      return out;
    }
    if (detail::has_sse41()) {
      std::string out; out.resize(base->size());
      detail::sse41_map_std_to_url(out.data(), base->data(), base->size());
      if (stats) { stats->input_bytes  = src.size(); stats->output_chars = out.size(); }
      return out;
    }
#endif
    // Scalar fallback mapping (small tail loop is already cheap)
    std::string out; out.resize(base->size());
    for (std::size_t i=0;i<base->size();++i) {
      char c = (*base)[i];
      if (c=='+') c='-'; else if (c=='/') c='_';
      out[i]=c;
    }
    if (stats) { stats->input_bytes  = src.size(); stats->output_chars = out.size(); }
    return out;
  }

  // ----------------------------- Threat-aware decode -------------------------
  [[nodiscard]] Result<Bytes>
  decode_and_scan(std::string_view encoded, const Options& opt,
#if XPS_B64X_ENABLE_THREATS
                  ThreatReport* report_out = nullptr,
#else
                  void* /*report_out*/ = nullptr,
#endif
                  Analytics* stats = nullptr) {
    auto dec = decode(encoded, opt, stats);
    if (!dec) return xps::unexpected<std::string>(dec.error());
#if XPS_B64X_ENABLE_THREATS
    if (report_out) {
      sec::analyze(BytesView{dec->data(), dec->size()}, *report_out);
    }
#endif
    return *dec;
  }

  // ----------------------------- Quick self-test -----------------------------
  [[nodiscard]] xps::expected<void, std::string>
  selftest() {
    Options std_opt{ .profile=ProfileId::Standard, .pad=true };
    Options url_opt{ .profile=ProfileId::Url, .pad=false };

    struct V { const char* plain; const char* std_b64; const char* url_b64; };
    static constexpr V TV[] = {
      {"", "", ""},
      {"f", "Zg==", "Zg"},
      {"fo", "Zm8=", "Zm8"},
      {"foo", "Zm9v", "Zm9v"},
      {"foob", "Zm9vYg==", "Zm9vYg"},
      {"fooba", "Zm9vYmE=", "Zm9vYmE"},
      {"foobar", "Zm9vYmFy", "Zm9vYmFy"}
    };

    for (auto& v : TV) {
      auto e1 = encode(std::string_view{v.plain}, std_opt);
      if (!e1) return xps::unexpected<std::string>(e1.error());
      if (*e1 != std::string(v.std_b64)) return xps::unexpected<std::string>(std::string{"std encode mismatch"});

      auto d1 = decode(*e1, std_opt);
      if (!d1) return xps::unexpected<std::string>(d1.error());
      if (std::string(reinterpret_cast<const char*>(d1->data()), d1->size()) != std::string(v.plain))
        return xps::unexpected<std::string>(std::string{"std decode mismatch"});

      auto e2 = encode(std::string_view{v.plain}, url_opt);
      if (!e2) return xps::unexpected<std::string>(e2.error());
      if (*e2 != std::string(v.url_b64)) return xps::unexpected<std::string>(std::string{"url encode mismatch"});

      auto d2 = decode(*e2, url_opt);
      if (!d2) return xps::unexpected<std::string>(d2.error());
      if (std::string(reinterpret_cast<const char*>(d2->data()), d2->size()) != std::string(v.plain))
        return xps::unexpected<std::string>(std::string{"url decode mismatch"});
    }

#if XPS_B64X_ENABLE_THREATS
    // Threat check sanity (HTML/JS)
    ThreatReport rep{};
    auto d = decode_and_scan("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", std_opt, &rep);
    if (!d) return xps::unexpected<std::string>(d.error());
    if (rep.findings.empty() || !rep.potential_threat) {
      return xps::unexpected<std::string>(std::string{"threat scan failed to flag <script>"});
    }

    // Banking/Keys quick heuristics (best-effort)
    ThreatReport rep2{};
    (void)decode_and_scan("QVVUSDowMGFrIEJBUkVFUjogZ2hwX3Rlc3QhIElCQU46REU5OSAxMjM0IDU2NzggOTAxIg==",
                          std_opt, &rep2);
#endif
    return {};
  }

} // namespace xps::b64x
