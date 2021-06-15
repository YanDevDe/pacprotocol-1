// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <keystore.h>
#include <pubkey.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

// Converts a hex string to a public key if possible
CPubKey HexToPubKey(const std::string& hex_in)
{
    if (!IsHex(hex_in)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    CPubKey vchPubKey(ParseHex(hex_in));
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    return vchPubKey;
}

// Retrieves a public key for an address from the given CKeyStore
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in)
{
    CTxDestination dest = DecodeDestination(addr_in);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_in);
    }
    const CKeyID *keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s does not refer to a key", addr_in));
    }
    CPubKey vchPubKey;
    if (!keystore->GetPubKey(*keyID, vchPubKey)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("no full public key for address %s", addr_in));
    }
    if (!vchPubKey.IsFullyValid()) {
       throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet contains an invalid public key");
    }
    return vchPubKey;
}

// Creates a multisig redeemscript from a given list of public keys and number required.
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys)
{
    // Gather public keys
    if (required < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a multisignature address must require at least one key to redeem");
    }
    if ((int)pubkeys.size() < required) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("not enough keys supplied (got %u keys, but need at least %d to redeem)", pubkeys.size(), required));
    }
    if (pubkeys.size() > 16) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Number of keys involved in the multisignature address creation > 16\nReduce the number");
    }

    CScript result = GetScriptForMultisig(required, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, (strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE)));
    }

    return result;
}

static std::pair<int64_t, int64_t> ParseRange(const UniValue& value)
{
    if (value.isNum()) {
        return {0, value.get_int64()};
    }
    if (value.isArray() && value.size() == 2 && value[0].isNum() && value[1].isNum()) {
        int64_t low = value[0].get_int64();
        int64_t high = value[1].get_int64();
        if (low > high) throw JSONRPCError(RPC_INVALID_PARAMETER, "Range specified as [begin,end] must not have begin after end");
        return {low, high};
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Range must be specified as end or as [begin,end]");
}

std::pair<int64_t, int64_t> ParseDescriptorRange(const UniValue& value)
{
    int64_t low, high;
    std::tie(low, high) = ParseRange(value);
    if (low < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should be greater or equal than 0");
    }
    if ((high >> 31) != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "End of range is too high");
    }
    if (high >= low + 1000000) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range is too large");
    }
    return {low, high};
}

std::vector<CScript> EvalDescriptorStringOrObject(const UniValue& scanobject, FlatSigningProvider& provider)
{
    std::string desc_str;
    std::pair<int64_t, int64_t> range = {0, 1000};
    if (scanobject.isStr()) {
        desc_str = scanobject.get_str();
    } else if (scanobject.isObject()) {
        UniValue desc_uni = find_value(scanobject, "desc");
        if (desc_uni.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor needs to be provided in scan object");
        desc_str = desc_uni.get_str();
        UniValue range_uni = find_value(scanobject, "range");
        if (!range_uni.isNull()) {
            range = ParseDescriptorRange(range_uni);
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan object needs to be either a string or an object");
    }

    std::string error;
    auto desc = Parse(desc_str, provider);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    if (!desc->IsRange()) {
        range.first = 0;
        range.second = 0;
    }
    std::vector<CScript> ret;
    for (int i = range.first; i <= range.second; ++i) {
        std::vector<CScript> scripts;
        if (!desc->Expand(i, provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys: '%s'", desc_str));
        }
        std::move(scripts.begin(), scripts.end(), std::back_inserter(ret));
    }
    return ret;
}

class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:

    explicit DescribeAddressVisitor() {}

    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        return obj;
    }
};

UniValue DescribeAddress(const CTxDestination& dest)
{
    return boost::apply_visitor(DescribeAddressVisitor(), dest);
}
