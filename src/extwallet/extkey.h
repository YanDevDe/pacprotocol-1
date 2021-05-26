// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PACPROTOCOL_EXTKEY_H
#define PACPROTOCOL_EXTKEY_H

#include <key.h>
#include <utilstrencodings.h>

#include <cstdint>
#include <string>
#include <vector>

#include <univalue.h>

inline bool IsHardened(uint32_t n)              { return (n & (1 << 31));};
inline uint32_t &SetHardenedBit(uint32_t &n)    { return (n |= (1 << 31));};
inline uint32_t &ClearHardenedBit(uint32_t &n)  { return (n &= ~(1 << 31));};
inline uint32_t WithHardenedBit(uint32_t n)     { return (n |= (1 << 31));};

const int MAX_BIP32_PATH = 10;
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;
const uint32_t BIP32_PURPOSE = 0x8000002C;

//! The default BIP44 account path for this coin
extern const std::string DEFAULT_ACCOUNT_PATH;

//! Transform a BIP32 path string into a vector of child offsets
bool ParseExtKeyPath(const std::string &path_string, std::vector<uint32_t> &path, std::string &error);

//! Transform a vector of BIP32 child offsets into a path string
std::string FormatExtKeyPath(const std::vector<uint32_t> &path);

//! Display an extended pubkey as a hex string
std::string ExtKeyToString(const CExtPubKey &epk);

int ExtractExtKeyPath(const std::string &sPath, std::vector<uint32_t> &vPath);

int ConvertPath(const std::vector<uint8_t> &path_in, std::vector<uint32_t> &path_out);

int PathToString(const std::vector<uint8_t> &vPath, std::string &sPath, char cH='\'', size_t nStart = 0);
int PathToString(const std::vector<uint32_t> &vPath, std::string &sPath, char cH='\'', size_t nStart = 0);

bool IsBIP32(const char *base58);

std::string HDAccIDToString(const CKeyID &id);
std::string HDKeyIDToString(const CKeyID &id);

std::string GetDefaultAccountPath();

#endif // PACPROTOCOL_EXTKEY_H
