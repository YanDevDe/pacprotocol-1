// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef USBDEVICE_USBUTIL_H
#define USBDEVICE_USBUTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <tinyformat.h>
#include <univalue.h>

#include <cstring>
#include <vector>

void SetAmountToVect(std::vector<uint8_t>& v, int64_t amount);
void SetVectToAmount(std::vector<uint8_t> v, int64_t& amount);
std::vector<uint8_t> UseAmountAsVect(int64_t amount);
int64_t UseVectAsAmount(std::vector<uint8_t> v);
int PutVarInt(std::vector<uint8_t>& v, uint64_t i);
int PutVarInt(uint8_t* p, uint64_t i);
unsigned char* writeUint32BE(unsigned char* buffer, uint32_t value);
bool error(std::string& errorMsg);
UniValue json_read_doc(const std::string& jsondata);
std::string json_get_key_string(const UniValue& jsondata, std::string key);

#endif // USBDEVICE_USBUTIL_H
