// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <extwallet/extkey.h>

#include <base58.h>
#include <chainparams.h>
#include <key.h>
#include <util.h>

#include <cstdio>
#include <sstream>

const std::string DEFAULT_ACCOUNT_PATH("m/44'/8192'/0'");

constexpr char ERR_PATH_STR_EMPTY[] = "Path string empty";
constexpr char ERR_INT_INVALID_CHAR[] = "Integer conversion invalid character";
constexpr char ERR_MALFORMED_PATH[] = "Malformed path";
constexpr char ERR_OFFSET_HARDENED[] = "Offset is hardened already";

bool ParseExtKeyPath(const std::string &s, std::vector<uint32_t> &path, std::string &error) {
  path.clear();

  if (s.length() < 1) {
    error = ERR_PATH_STR_EMPTY;
    return false;
  }

  const auto npos = std::string::npos;
  for (size_t start = 0, end = 0; end != npos; start = end + 1) {
    end = s.find('/', start);
    size_t token_length = (end == npos) ? npos : (end - start);
    std::string token = s.substr(start, token_length);

    if (token.size() == 0) {
      error = ERR_MALFORMED_PATH;
      return false;
    }

    if (token == "m") {
      if (path.size() > 0 || start > 0) {
        error = ERR_MALFORMED_PATH;
        return false;
      }
      // Ignore initial 'm'
      continue;
    }

    std::istringstream is(std::move(token));

    uint32_t child;
    is >> child;
    if (is.fail()) {
      error = ERR_INT_INVALID_CHAR;
      return false;
    }

    char hardened = is.get();
    if (!is.eof()) {
      if (hardened != '\'' && hardened != 'h') {
        error = ERR_INT_INVALID_CHAR;
        return false;
      }
      if (child >= BIP32_HARDENED_KEY_LIMIT) {
        error = ERR_OFFSET_HARDENED;
        return false;
      }
      child |= BIP32_HARDENED_KEY_LIMIT;
    }

    // must consume the whole token
    if (is.peek() != EOF) {
      error = ERR_MALFORMED_PATH;
      return false;
    }

    path.emplace_back(child);
  }

  return true;
}

std::string FormatExtKeyPath(const std::vector<uint32_t> &path) {
  std::ostringstream s;
  s << "m";
  for (auto i : path) {
    s << '/' << (i & ~BIP32_HARDENED_KEY_LIMIT);
    if (i & BIP32_HARDENED_KEY_LIMIT) {
      s << '\'';
    }
  }
  return s.str();
}

std::string ExtKeyToString(const CExtPubKey &epk) {
  unsigned char code[BIP32_EXTKEY_SIZE];
  epk.Encode(code);
  return HexStr(code, code + sizeof(code));
}

inline void AppendPathLink(std::string &s, uint32_t n, char cH)
{
    s += "/";
    bool fHardened = false;
    if ((n >> 31) == 1) {
        n &= ~(1U << 31);
        fHardened = true;
    }
    s += strprintf("%u", n);
    if (fHardened) {
        s += cH;
    }
};

int ConvertPath(const std::vector<uint8_t> &path_in, std::vector<uint32_t> &path_out)
{
    path_out.clear();
    if (path_in.size() % 4 != 0) {
        return 1;
    }
    for (size_t o = 0; o < path_in.size(); o+=4) {
        uint32_t n;
        memcpy(&n, &path_in[o], 4);
        path_out.push_back(n);
    }
    return 0;
};

int PathToString(const std::vector<uint8_t> &vPath, std::string &sPath, char cH, size_t nStart)
{
    sPath = "";
    if (vPath.size() % 4 != 0) {
        return 1;
    }

    sPath = "m";
    for (size_t o = nStart; o < vPath.size(); o+=4) {
        uint32_t n;
        memcpy(&n, &vPath[o], 4);
        AppendPathLink(sPath, n, cH);
    }

    return 0;
};

int PathToString(const std::vector<uint32_t> &vPath, std::string &sPath, char cH, size_t nStart)
{
    sPath = "m";
    for (size_t o = nStart; o < vPath.size(); ++o) {
        AppendPathLink(sPath, vPath[o], cH);
    }
    return 0;
};

std::string GetDefaultAccountPath()
{
    return DEFAULT_ACCOUNT_PATH;
}

#define _UINT32_MAX (0xffffffff)
static uint32_t strtou32max(const char *nptr, int base)
{
    const char *s;
    uintmax_t acc;
    char c;
    uintmax_t cutoff;
    int neg, any, cutlim;

    s = nptr;
    do {
        c = *s++;
    } while (isspace((unsigned char)c));

    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X') &&
        ((s[1] >= '0' && s[1] <= '9') ||
        (s[1] >= 'A' && s[1] <= 'F') ||
        (s[1] >= 'a' && s[1] <= 'f'))) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;
    acc = any = 0;
    if (base < 2 || base > 36)
        goto noconv;

    cutoff = _UINT32_MAX / base;
    cutlim = _UINT32_MAX % base;
    for ( ; ; c = *s++) {
        if (c >= '0' && c <= '9')
            c -= '0';
        else if (c >= 'A' && c <= 'Z')
            c -= 'A' - 10;
        else if (c >= 'a' && c <= 'z')
            c -= 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = _UINT32_MAX;
        errno = ERANGE;
    } else if (!any) {
noconv:
        errno = EINVAL;
    } else if (neg)
        acc = -acc;
    return (acc);
}

static inline int validDigit(char c, int base)
{
    switch(base) {
        case 2:  return c == '0' || c == '1';
        case 10: return c >= '0' && c <= '9';
        case 16: return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        default: errno = EINVAL;
    }
    return 0;
}

int ExtractExtKeyPath(const std::string &sPath, std::vector<uint32_t> &vPath)
{
    char data[512];

    vPath.clear();

    if (sPath.length() > sizeof(data) -2) {
        return 2;
    }
    if (sPath.length() < 1) {
        return 3;
    }

    size_t nStart = 0;
    size_t nLen = sPath.length();
    if (tolower(sPath[0]) == 'm') {
        nStart+=2;
        nLen-=2;
    }
    if (nLen < 1) {
        return 3;
    }

    memcpy(data, sPath.data()+nStart, nLen);
    data[nLen] = '\0';

    int nSlashes = 0;
    for (size_t k = 0; k < nLen; ++k) {
        if (data[k] == '/') {
            nSlashes++;

            // Catch start or end '/', and '//'
            if (k == 0
                || k == nLen-1
                || (k < nLen-1 && data[k+1] == '/')) {
                return 7;
            }
        }
    }

    vPath.reserve(nSlashes + 1);

    char *token, *p = strtok_r(data, "/", &token);

    while (p) {
        uint32_t nChild;
        bool fHarden = false;

        // Don't allow octal, only hex and binary
        int nBase = *p == '0' && (*(p+1) == 'b' || *(p+1) == 'B') ? 2
            : *p == '0' && (*(p+1) == 'x' || *(p+1) == 'X') ? 16 : 10;
        if (nBase != 10)
            p += 2; // step over 0b / 0x
        char *ps = p;
        for (; *p; ++p) {
            // Last char can be (h, H ,')
            if (!*(p+1) && (tolower(*p) == 'h' || *p == '\'')) {
                fHarden = true;
                *p = '\0';
            } else
            if (!validDigit(*p, nBase)) {
                return 4;
            }
        }

        errno = 0;
        nChild = strtou32max(ps, nBase);
        if (errno != 0)
            return 5;

        if (fHarden) {
            if ((nChild >> 31) == 0) {
                nChild |= 1U << 31;
            } else {
                return 8;
            }
        }

        vPath.push_back(nChild);

        p = strtok_r(nullptr, "/", &token);
    }

    if (vPath.size() < 1) {
        return 3;
    }

    return 0;
}
