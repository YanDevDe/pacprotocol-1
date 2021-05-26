// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <extwallet/util.h>
#include <util.h>

void SetAmountToVect(std::vector<uint8_t>& v, int64_t amount)
{
    v.resize(8);
    amount = (int64_t)htole64((uint64_t)amount);
    memcpy(v.data(), &amount, 8);
}

void SetVectToAmount(std::vector<uint8_t> v, int64_t& amount)
{
    v.resize(8);
    memcpy(&amount, v.data(), 8);
    amount = (int64_t)htole64((uint64_t)amount);
}

std::vector<uint8_t> UseAmountAsVect(int64_t amount)
{
    std::vector<uint8_t> vchAmount(8);
    SetAmountToVect(vchAmount, amount);
    return vchAmount;
}

int64_t UseVectAsAmount(std::vector<uint8_t> v)
{
    int64_t amount = 0;
    SetVectToAmount(v, amount);
    return amount;
}

int PutVarInt(std::vector<uint8_t>& v, uint64_t i)
{
    uint8_t b = i & 0x7F;
    while ((i = i >> 7) > 0) {
        v.push_back(b | 0x80);
        b = i & 0x7F;
    }
    v.push_back(b);
    return i; // 0 == success
}

int PutVarInt(uint8_t* p, uint64_t i)
{
    int nBytes = 0;
    uint8_t b = i & 0x7F;
    while ((i = i >> 7) > 0) {
        *p++ = b | 0x80;
        b = i & 0x7F;
        nBytes++;
    }
    *p++ = b;
    nBytes++;
    return nBytes;
}

template <typename I>
inline unsigned int GetSizeOfVarInt(I n)
{
    int nRet = 0;
    while (true) {
        nRet++;
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
    }
    return nRet;
}

unsigned char* writeUint32BE(unsigned char* buffer, uint32_t value)
{
    *buffer = ((value >> 24) & 0xff);
    *(buffer + 1) = ((value >> 16) & 0xff);
    *(buffer + 2) = ((value >> 8) & 0xff);
    *(buffer + 3) = (value & 0xff);
    return (buffer + 4);
}

bool error(std::string& errorMsg)
{
    LogPrintf("%s - error:\n%s\n", __func__, errorMsg);
    return false;
}

UniValue json_read_doc(const std::string& jsondata)
{
    UniValue v;
    v.read(jsondata);
    return v;
}

std::string json_get_key_string(const UniValue& jsondata, std::string key)
{
    UniValue v(UniValue::VSTR);
    if(jsondata.exists(key)) {
        UniValue data = jsondata[key];
        if(data.isStr())
            v = data;
    }
    return v.get_str();
}
