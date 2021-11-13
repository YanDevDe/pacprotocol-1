// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2021 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <init.h>
#include <keystore.h>
#include <validation.h>
#include <validationinterface.h>
#include <key_io.h>
#include <merkleblock.h>
#include <net.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/rawtransaction.h>
#include <rpc/server.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/standard.h>
#include <txmempool.h>
#include <uint256.h>
#include <utilstrencodings.h>
#ifdef ENABLE_WALLET
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#endif

#include <future>
#include <stdint.h>

#include <univalue.h>

#include <boost/assign/list_of.hpp>

class CWallet;
typedef std::vector<uint8_t> valtype;

static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("txid", txin.prevout.hash.ToString());
    entry.pushKV("vout", (uint64_t)txin.prevout.n);
    entry.pushKV("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
    entry.pushKV("sequence", (uint64_t)txin.nSequence);
    entry.pushKV("error", strMessage);
    vErrorsRet.push_back(entry);
}

std::set<CTxDestination> GetAccountAddress(const std::string& account, CWallet* pwallet)
{
    std::set<CTxDestination> ret;
    for (const std::pair<CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CTxDestination& dest = item.first;
        const std::string& strName = item.second.name;
        if (strName == account)
            ret.insert(dest);
    }
    return ret;
}

UniValue GetAccountInfo(const std::string& account, CWallet* pwallet)
{
    LOCK2(cs_main, pwallet->cs_wallet);
    assert(pwallet != nullptr);

    UniValue result(UniValue::VOBJ);
    result.pushKV("account", account);

    std::set<CTxDestination> destinations = GetAccountAddress(account, pwallet);
    UniValue addresses(UniValue::VARR);
    for (const auto& dest : destinations)
        addresses.push_back(EncodeDestination(dest));
    result.pushKV("addresses", addresses);

    if (destinations.size() == 0)
        return result;

    UniValue unspentPAC(UniValue::VARR);
    UniValue unspentToken(UniValue::VARR);
    CAmount nPACAmount = 0;
    CAmount nTokenPACAmount = 0;
    std::map<std::string, CAmount> mTokenAmount;
    std::vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs, false, nullptr, true);
    for (const COutput& out : vecOutputs)
    {
        CTxDestination address;
        if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address))
            continue;
        if (!destinations.count(address))
            continue;

        CAmount nValue = out.tx->tx->vout[out.i].nValue;
        const CScript& pk = out.tx->tx->vout[out.i].scriptPubKey;

        bool fToken = false;
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    if (redeemScript.IsPayToToken()) {
                        fToken = true;
                        UniValue entry(UniValue::VOBJ);
                        entry.pushKV("txid", out.tx->tx->GetHash().GetHex());
                        entry.pushKV("vout", out.i);

                        CTxDestination address;
                        if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
                            entry.pushKV("address", EncodeDestination(address));
                            if (pwallet->mapAddressBook.count(address))
                                entry.pushKV("account", pwallet->mapAddressBook[address].name);
                        }

                        entry.pushKV("scriptPubKey", HexStr(pk.begin(), pk.end()));
                        entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
                        entry.pushKV("amount", ValueFromAmount(nValue));
                        entry.pushKV("spendable", out.fSpendable);

                        int namesize = redeemScript[1];
                        int amountsize = redeemScript[2 + namesize];
                        std::vector<unsigned char> vecName(redeemScript.begin() + 2, redeemScript.begin() + 2 + namesize);
                        std::vector<unsigned char> vecAmount(redeemScript.begin() + 3 + namesize, redeemScript.begin() + 3 + namesize + amountsize);
                        std::string tokenName(vecName.begin(), vecName.end());
                        CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

                        entry.pushKV("token", tokenName);
                        entry.pushKV("tokenAmount", tokenAmount);
                        unspentToken.push_back(entry);
                        mTokenAmount[tokenName] += tokenAmount;
                        nTokenPACAmount += nValue;
                    }
                }
            }
        } else if (pk.IsPayToToken()) {
            fToken = true;
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", out.tx->tx->GetHash().GetHex());
            entry.pushKV("vout", out.i);

            CTxDestination address;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
                entry.pushKV("address", EncodeDestination(address));
                if (pwallet->mapAddressBook.count(address))
                    entry.pushKV("account", pwallet->mapAddressBook[address].name);
            }

            entry.pushKV("scriptPubKey", HexStr(pk.begin(), pk.end()));
            entry.pushKV("amount", ValueFromAmount(nValue));
            entry.pushKV("spendable", out.fSpendable);

            int namesize = pk[1];
            int amountsize = pk[2 + namesize];
            std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
            std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
            std::string tokenName(vecName.begin(), vecName.end());
            CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

            entry.pushKV("token", tokenName);
            entry.pushKV("tokenAmount", tokenAmount);
            unspentToken.push_back(entry);
            mTokenAmount[tokenName] += tokenAmount;
            nTokenPACAmount += nValue;
        }

        if (fToken)
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.tx->tx->GetHash().GetHex());
        entry.pushKV("vout", out.i);
        if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
            entry.pushKV("address", EncodeDestination(address));
            if (pwallet->mapAddressBook.count(address))
                entry.pushKV("account", pwallet->mapAddressBook[address].name);
        }
        entry.pushKV("scriptPubKey", HexStr(pk.begin(), pk.end()));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript))
                    entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
            }
        }
        entry.pushKV("amount", ValueFromAmount(nValue));
        entry.pushKV("spendable", out.fSpendable);
        unspentPAC.push_back(entry);
        nPACAmount += nValue;
    }

    result.pushKV("PAC", ValueFromAmount(nPACAmount));
    result.pushKV("PACInToken", ValueFromAmount(nTokenPACAmount));

    UniValue tokenlist(UniValue::VARR);
    for (auto& it : mTokenAmount) {
        UniValue u(UniValue::VOBJ);
        u.pushKV("token", it.first);
        u.pushKV("amount", it.second);
        tokenlist.push_back(u);
    }
    result.pushKV("tokenList", tokenlist);
    result.pushKV("unspentPAC", unspentPAC);
    result.pushKV("unspentToken", unspentToken);
    return result;
}

UniValue getaccountinfo(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error("getaccountinfo \"account\" \n");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR), true);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = request.params[0].get_str();
    return GetAccountInfo(account, pwallet);
}

bool SignTokenTx(CMutableTransaction& rawTx, CWallet* pwallet)
{
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache& viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : rawTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwallet)
        EnsureWalletIsUnlocked(pwallet);
#endif

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = (!pwallet ? tempKeystore : *pwallet);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY)) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(rawTx);

    // Sign what we can:
    for (unsigned int i = 0; i < rawTx.vin.size(); i++) {
        CTxIn& txin = rawTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < rawTx.vout.size()))
            SignSignature(keystore, prevPubKey, rawTx, i, amount, nHashType);

        // ... and merge in other signatures:
        SignatureData sigdata;
        sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(rawTx, i));
        ScriptError serror = SCRIPT_ERR_OK;

        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&rawTx, i, amount), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }

    if (!vErrors.empty())
        return false;
    return true;
}

void SendTokenTx(const CMutableTransaction& rawTx, CWallet* pwallet)
{
    uint256 hashTx = rawTx.GetHash();
    bool fOverrideFees = false;

    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, MakeTransactionRef(rawTx), &fMissingInputs, false, !fOverrideFees)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(
                    RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            pwallet->_SyncTransaction(MakeTransactionRef(rawTx));
#endif
    }

    g_connman->RelayTransaction(rawTx);
}

UniValue tokenmint(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "tokenmint \"account\" \"token\" \"supply\"\n"
            "\nIssue a new token, token id is one of your UTXO's txid.\n"
            "The total amount of token must be less than 10**18.\n"
            "You need at least 0.1001PAC to issue token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"account\":   (string, required) token issuer\n"
            "2. \"token\":     (string, required) token name\n"
            "3. \"supply\":    (string, required) token supply\n"

            "\nResult:\n"
            "\"txid\"          (string) The transaction hash in hex\n");

#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
#else
    CWallet* const pwallet = nullptr;
#endif

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR), true);
    for (unsigned int i = 0; i < request.params.size(); ++i)
        if (request.params[i].isNull())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = request.params[0].get_str();
    std::string tokenname = request.params[1].get_str();

    // check supply is valid
    std::string supply = request.params[2].get_str();
    CAmount nSupply = std::atoll(supply.c_str());
    if (nSupply <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply must be positive");
    if (nSupply > MAX_TOKEN_SUPPLY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply is out of range");

    // default fee
    CAmount defaultSupplyAmount = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;
    UniValue result(UniValue::VOBJ);

    // get account info
    UniValue accountInfo = GetAccountInfo(account, pwallet);
    UniValue addresses = accountInfo["addresses"].get_array();
    if (addresses.size() == 0) {
        result.pushKV("error", "account does not exist");
        return result;
    }

    // create tx vin
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();

    UniValue utxoPAC = accountInfo["unspentPAC"].get_array();
    CAmount nVinAmount = 0;
    for (size_t i = 0; i < utxoPAC.size(); ++i) {
        UniValue utxo = utxoPAC[i];
        CAmount tmp = AmountFromValue(utxo["amount"]);
        uint256 txid;
        txid.SetHex(utxo["txid"].get_str());
        CTxIn in(COutPoint(txid, utxo["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in);
        nVinAmount += tmp;
        if (nVinAmount >= (defaultSupplyAmount + defaultSupplyFee))
            break;
    }

    // check PAC balance is enough
    if (nVinAmount < (defaultSupplyAmount + defaultSupplyFee)) {
        result.pushKV("error", "insufficient balance");
        return result;
    }

    // build token script
    CTxDestination destination = DecodeDestination(addresses[0].get_str());
    CScript scriptPubKey = GetScriptForDestination(destination);
    CScript script = CScript() << OP_TOKEN << ToByteVector(tokenname) << CScriptNum(nSupply);
    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    result.pushKV("account", account);
    result.pushKV("token", tokenname);
    result.pushKV("address", address);

    pwallet->AddCScript(script);
    pwallet->SetAddressBook(innerID, "", account);

    // token vout
    CTxOut supplyOut(defaultSupplyAmount, script);
    rawTx.vout.push_back(supplyOut);

    // charge vout
    CAmount chargeAmount = nVinAmount - defaultSupplyAmount - defaultSupplyFee;
    if (chargeAmount) {
        CTxOut chargeOut(chargeAmount, scriptPubKey);
        rawTx.vout.push_back(chargeOut);
    }

    // sign tx
    if (!SignTokenTx(rawTx, pwallet)) {
        result.pushKV("error", "error signing token transaction");
        return result;
    }

    // send tx
    SendTokenTx(rawTx, pwallet);

    result.pushKV("txid", rawTx.GetHash().ToString());
    result.pushKV("fee", "0.0001");
    result.pushKV("hex", EncodeHexTx(rawTx));
    return result;
}

UniValue tokentransfer(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "tokentransfer \"token\" \"account\" [{\"address\":\"xxxx\", \"amount\":n},...] \n"
            "\nCreate a transaction to transfer token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"token\":        (string, required) token name\n"
            "2. \"account\":      (string, required) sender account\n"
            "3. \"receivers\":    (string, required) A json array of receivers\n"
            "     [\n"
            "       {\n"
            "         \"address\":\"xxxx\",  (string, required) reveiver address\n"
            "         \"amount\":n           (numeric, required) token amount\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "\"txid\"             (string) The transaction hash in hex\n");

#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
#else
    CWallet* const pwallet = nullptr;
#endif

    if (!pwallet)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "This function requires a wallet-enabled build.");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VARR), true);
    for (unsigned int i = 0; i < request.params.size(); ++i)
        if (request.params[i].isNull())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string token = request.params[0].get_str();
    std::string account = request.params[1].get_str();
    UniValue receivers = request.params[2].get_array();
    UniValue result(UniValue::VOBJ);

    // get account info
    UniValue accountInfo = GetAccountInfo(account, pwallet);
    UniValue addresses = accountInfo["addresses"].get_array();
    if (addresses.size() == 0) {
        result.pushKV("error", "account does not exist");
        return result;
    }

    CAmount defaultTransferFee = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;
    CAmount nVinToken = 0;
    CAmount nVoutToken = 0;
    CAmount nVinPAC = 0;
    CAmount nVoutPAC = defaultSupplyFee + defaultTransferFee * receivers.size();

    // calculate vout token amount
    for (unsigned int idx = 0; idx < receivers.size(); ++idx) {
        const UniValue& obj = receivers[idx].get_obj();
        std::string address = obj["address"].get_str();
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            result.pushKV("error", "invalid address");
            return result;
        }
        CAmount n = atoll(obj["amount"].get_str().c_str());
        nVoutToken += n;
    }

    // create tx
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();

    // search enough token vin
    UniValue utxoToken = accountInfo["unspentToken"].get_array();
    for (size_t i = 0; i < utxoToken.size(); ++i) {
        UniValue u = utxoToken[i];
        uint256 txid;
        txid.SetHex(u["txid"].get_str());
        CTxIn in(COutPoint(txid, u["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in);

        nVinToken += u["tokenAmount"].get_int64();
        if (nVinToken >= nVoutToken)
            break;
    }

    if (nVinToken < nVoutToken) {
        result.pushKV("error", "insufficient token balance");
        return result;
    }

    // if has token charge, raise PAC fee
    if (nVinToken > nVoutToken)
        nVoutPAC += defaultTransferFee;

    nVinPAC = rawTx.vin.size() * defaultTransferFee;

    // search PAC vin to pay fee
    UniValue utxoPAC = accountInfo["unspentPAC"].get_array();
    for (size_t i = 0; i < utxoPAC.size(); ++i) {
        UniValue u = utxoPAC[i];
        uint256 txid;
        txid.SetHex(u["txid"].get_str());
        CTxIn in(COutPoint(txid, u["vout"].get_int()), CScript(), nSequence);
        rawTx.vin.push_back(in);

        nVinPAC += AmountFromValue(u["amount"]);
        if (nVinPAC >= nVoutPAC)
            break;
    }

    if (nVinPAC < nVoutPAC) {
        result.pushKV("error", "insufficient balance");
        return result;
    }

    // create token vout
    for (unsigned int idx = 0; idx < receivers.size(); idx++) {
        const UniValue& output = receivers[idx];
        std::string address = output["address"].get_str();
        CAmount n = atoll(output["amount"].get_str().c_str());
        CTxDestination destination = DecodeDestination(address);
        CScript scriptPubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(n) << OP_DROP << OP_DROP;
        scriptPubKey += GetScriptForDestination(destination);
        CTxOut out(defaultTransferFee, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    CTxDestination chargeDest = DecodeDestination(addresses[0].get_str());

    // token charge
    if (nVinToken > nVoutToken) {
        CScript chargePubKey = CScript() << OP_TOKEN << ToByteVector(token) << CScriptNum(nVinToken - nVoutToken) << OP_DROP << OP_DROP;
        chargePubKey += GetScriptForDestination(chargeDest);
        CTxOut out(defaultTransferFee, chargePubKey);
        rawTx.vout.push_back(out);
    }

    // PAC charge
    if (nVinPAC > nVoutPAC) {
        CScript chargePubKey = GetScriptForDestination(chargeDest);
        CTxOut out(nVinPAC - nVoutPAC, chargePubKey);
        rawTx.vout.push_back(out);
    }

    // sign tx
    if (!SignTokenTx(rawTx, pwallet)) {
        result.pushKV("error", "error signing token transaction");
        return result;
    }

    // send tx
    SendTokenTx(rawTx, pwallet);

    result.pushKV("txid", rawTx.GetHash().ToString());
    result.pushKV("fee", "0.0001");
    result.pushKV("hex", EncodeHexTx(rawTx));
    return result;
}


UniValue tokenlist(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "tokenlist \n"
            "\nList the information about all the issued token.\n"
            "Returns token list.\n");

    UniValue result(UniValue::VARR);
    std::set<std::string> sToken;

    for (auto it : pwallet->mapWallet) {
        const CWalletTx& wtx = it.second;
        if (wtx.IsCoinBase())
            continue;

        for (const auto& out : wtx.tx->vout) {
            const CScript& pk = out.scriptPubKey;
            if (pk.IsPayToToken()) {
                int namesize = pk[1];
                int amountsize = pk[2 + namesize];
                std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

                if (sToken.count(tokenName))
                    continue;
                else
                    sToken.insert(tokenName);

                UniValue entry(UniValue::VOBJ);
                CTxDestination address;
                if (ExtractDestination(pk, address)) {
                    // entry.pushKV("address", EncodeDestination(address));
                    if (pwallet->mapAddressBook.count(address))
                        entry.pushKV("account", pwallet->mapAddressBook[address].name);
                }
                entry.pushKV("token", tokenName);
                entry.pushKV("supply", tokenAmount);
                result.push_back(entry);
            }
        }
    }
    return result;
}

UniValue tokensearch(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "tokensearch \"account\" \"token\" \n"
            "\nSearch token by account or token name.\n"
            "Returns token information.\n");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR), true);
    std::string account = request.params[0].get_str();
    std::string token = request.params[1].get_str();
    if (account.empty() && token.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments only one can be null");

    UniValue result(UniValue::VARR);

    for (auto it : pwallet->mapWallet) {
        const CWalletTx& wtx = it.second;
        if (wtx.IsCoinBase())
            continue;

        for (const auto& out : wtx.tx->vout) {
            const CScript& pk = out.scriptPubKey;
            if (pk.IsPayToToken()) {
                int namesize = pk[1];
                int amountsize = pk[2 + namesize];
                std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

                CTxDestination address;
                std::string issuer = "";
                if (ExtractDestination(pk, address)) {
                    if (pwallet->mapAddressBook.count(address))
                        issuer = pwallet->mapAddressBook[address].name;
                }

                if (!token.empty()) {
                    if (token == tokenName && (account.empty() || account == issuer)) {
                        UniValue entry(UniValue::VOBJ);
                        // entry.pushKV("txid", it.first.ToString()));
                        entry.pushKV("account", issuer);
                        entry.pushKV("token", tokenName);
                        entry.pushKV("supply", tokenAmount);
                        // entry.pushKV("address", EncodeDestination(address));
                        result.push_back(entry);
                        return result;
                    }
                } else if (!account.empty() && account == issuer) {
                    UniValue entry(UniValue::VOBJ);
                    // entry.pushKV("txid", it.first.ToString());
                    entry.pushKV("account", issuer);
                    entry.pushKV("token", tokenName);
                    entry.pushKV("supply", tokenAmount);
                    // entry.pushKV("address", EncodeDestination(address));
                    result.push_back(entry);
                    return result;
                }
            }
        }
    }
    return result;
}

UniValue GetAccountTokenAddress(const std::string& account, CWallet* pwallet)
{
    LOCK2(cs_main, pwallet->cs_wallet);
    assert(pwallet != nullptr);

    UniValue result(UniValue::VARR);

    std::set<CTxDestination> destinations = GetAccountAddress(account, pwallet);
    if (destinations.size() == 0)
        return result;

    std::vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs, false, nullptr, true);
    for (const COutput& out : vecOutputs) {
        CTxDestination address;
        if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address))
            continue;

        if (!destinations.count(address))
            continue;

        const CScript& pk = out.tx->tx->vout[out.i].scriptPubKey;
        if (pk.IsPayToToken()) {
            UniValue entry(UniValue::VOBJ);
            CTxDestination address;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
                entry.pushKV("address", EncodeDestination(address));
            }
            int namesize = pk[1];
            int amountsize = pk[2 + namesize];
            std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
            std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
            std::string tokenName(vecName.begin(), vecName.end());
            CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

            entry.pushKV("token", tokenName);
            entry.pushKV("amount", tokenAmount);
            result.push_back(entry);
        }
    }
    return result;
}

UniValue tokenaddress(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokenaddress \"account\" \n"
            "\nList the addresses that contains token.\n"
            "Returns address list.\n");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR), true);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, argument must be non-null");

    std::string account = request.params[0].get_str();
    return GetAccountTokenAddress(account, pwallet);
}

UniValue tokenhistory(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 4)
        throw std::runtime_error(
            "tokenhistory \"account\" \"token\" \"index\" \"limit\" \n"
            "\nList the token transaction history.\n"
            "Returns token transaction list.\n");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VNUM)(UniValue::VNUM), true);
    for (size_t i = 0; i < request.params.size(); ++i)
        if (request.params[i].isNull())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    std::string account = request.params[0].get_str();
    std::string token = request.params[1].get_str();
    int index = request.params[2].get_int();
    int limit = request.params[3].get_int();

    UniValue result(UniValue::VARR);
    if (index < 0 || limit < 0)
        return result;

    if (limit == 0)
        return result;

    unsigned int end = index + limit - 1;

    for (auto it : pwallet->mapWallet) {
        const CWalletTx& wtx = it.second;
        if (wtx.IsCoinBase())
            continue;

        for (const auto& out : wtx.tx->vout) {
            const CScript& pk = out.scriptPubKey;
            if (pk.IsPayToToken()) {
                int namesize = pk[1];
                int amountsize = pk[2 + namesize];
                std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount amount = CScriptNum(vecAmount, true).getamount();

                if (tokenName != token)
                    continue;

                CTxDestination address;
                std::string receiver = "";
                if (ExtractDestination(pk, address)) {
                    if (pwallet->mapAddressBook.count(address))
                        receiver = pwallet->mapAddressBook[address].name;
                }

                if (account != receiver)
                    continue;

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("txid", it.first.ToString());
                entry.pushKV("address", EncodeDestination(address));
                entry.pushKV("amount", amount);
                entry.pushKV("category", "receive");
                entry.pushKV("timestamp", wtx.GetTxTime());
                result.push_back(entry);

                if (result.size() > end) {
                    UniValue ret(UniValue::VARR);
                    for (size_t i = index; i < end + 1; ++i)
                        ret.push_back(result[i]);
                    return ret;
                }
            }
        }

        for (const auto& in : wtx.tx->vin) {
            const CWalletTx& wtx = pwallet->mapWallet[in.prevout.hash];
            CScript pk = wtx.tx->vout[in.prevout.n].scriptPubKey;
            if (pk.IsPayToToken()) {
                int namesize = pk[1];
                int amountsize = pk[2 + namesize];
                std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount amount = CScriptNum(vecAmount, true).getamount();

                if (tokenName != token)
                    continue;

                CTxDestination address;
                std::string receiver = "";
                if (ExtractDestination(pk, address)) {
                    if (pwallet->mapAddressBook.count(address))
                        receiver = pwallet->mapAddressBook[address].name;
                }

                if (account != receiver)
                    continue;

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("txid", it.first.ToString());
                entry.pushKV("address", EncodeDestination(address));
                entry.pushKV("amount", amount);
                entry.pushKV("category", "send");
                entry.pushKV("timestamp", wtx.GetTxTime());
                result.push_back(entry);
                if (result.size() > end) {
                    UniValue ret(UniValue::VARR);
                    for (size_t i = index; i < end + 1; ++i)
                        ret.push_back(result[i]);
                    return ret;
                }
            }
        }
    }

    UniValue ret(UniValue::VARR);
    if (result.size() < (unsigned int)(index + 1))
        return ret;

    for (size_t i = index; i < result.size(); ++i)
        ret.push_back(result[i]);
    return ret;
}

UniValue tokendetail(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokendetail \"txid\" \n"
            "\nReturns the transaction details\n");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR), true);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    LOCK2(cs_main, pwallet->cs_wallet);
    std::string txid = request.params[0].get_str();
    uint256 hash;
    hash.SetHex(txid);
    isminefilter filter = ISMINE_SPENDABLE;

    UniValue result(UniValue::VOBJ);
    if (!pwallet->mapWallet.count(hash))
        return result;

    const CWalletTx& wtx = pwallet->mapWallet[hash];
    result.pushKV("txid", txid);

    int confirms = wtx.GetDepthInMainChain();
    int height = chainActive.Height() + 1 - confirms;
    result.pushKV("height", height);

    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nFee = wtx.tx->GetValueOut() > nDebit ? wtx.tx->GetValueOut() - nDebit : nDebit - wtx.tx->GetValueOut();
    result.pushKV("fee", ValueFromAmount(nFee));
    result.pushKV("time", wtx.GetTxTime());

    UniValue details(UniValue::VARR);
    std::string token = "";
    CAmount nTokenAmount = 0;
    for (const auto& out : wtx.tx->vout) {
        const CScript& pk = out.scriptPubKey;
        if (pk.IsPayToToken()) {
            int namesize = pk[1];
            int amountsize = pk[2 + namesize];
            std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
            std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
            std::string name(vecName.begin(), vecName.end());
            CAmount amount = CScriptNum(vecAmount, true).getamount();

            UniValue entry(UniValue::VOBJ);
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                if (pwallet->mapAddressBook.count(address))
                    entry.pushKV("account", pwallet->mapAddressBook[address].name);
                entry.pushKV("address", EncodeDestination(address));
            }
            entry.pushKV("amount", amount);
            entry.pushKV("category", "receive");
            details.push_back(entry);

            if (token.empty())
                token = name;
            nTokenAmount += amount;
        }
    }

    for (const auto& in : wtx.tx->vin) {
        const CWalletTx& wtx = pwallet->mapWallet[in.prevout.hash];
        CScript pk = wtx.tx->vout[in.prevout.n].scriptPubKey;
        if (pk.IsPayToToken()) {
            int namesize = pk[1];
            int amountsize = pk[2 + namesize];
            std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vecAmount, true).getamount();

            UniValue entry(UniValue::VOBJ);
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                if (pwallet->mapAddressBook.count(address))
                    entry.pushKV("account", pwallet->mapAddressBook[address].name);

                entry.pushKV("address", EncodeDestination(address));
            }
            entry.pushKV("amount", amount);
            entry.pushKV("category", "send");
            details.push_back(entry);
        }
    }

    result.pushKV("token", token);
    result.pushKV("amount", nTokenAmount);
    result.pushKV("details", details);

    return result;
}

UniValue tokenissue(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "tokenissue \"supply\" \n"
            "\nIssue a new token, token id is one of your UTXO's txid.\n"
            "The total amount of token must be less than 10**18.\n"
            "You need at least 0.0101BCH to issue token.\n"
            "Returns hex-encoded raw transaction.\n"

            "\nArguments:\n"
            "1. \"supply\":    (string, required) token supply\n"
            "\nResult:\n"
            "\"transaction\"   (string) hex string of the transaction\n");

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR), true);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    // check supply is valid
    std::string supply = request.params[0].get_str();
    CAmount nSupply = atoll(supply.c_str());
    if (nSupply <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply must be positive");
    if (nSupply > MAX_TOKEN_SUPPLY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, supply is out of range");

    // calaulate enough utxo
    CAmount defaultSupplyAmount = 0.01 * COIN;
    CAmount defaultSupplyFee = 0.0001 * COIN;

    std::vector<COutput> utxo;
    CAmount utxoAmount = 0;

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs, false, nullptr, true);
    for (const COutput& out : vecOutputs) {
        const CScript& pk = out.tx->tx->vout[out.i].scriptPubKey;
        if (pk.IsPayToScriptHash()) {
            std::vector<unsigned char> vec(pk.begin() + 2, pk.begin() + 22);
            CScriptID hash = CScriptID(uint160(vec));
            CScript redeemScript;
            if (pwallet->GetCScript(hash, redeemScript)) {
                if (redeemScript.IsPayToToken())
                    continue;
            }
        } else if (pk.IsPayToToken()) {
            continue;
        }

        CAmount nValue = out.tx->tx->vout[out.i].nValue;
        utxoAmount += nValue;
        if (utxoAmount > (defaultSupplyAmount + defaultSupplyFee)) {
            utxo.push_back(out);
            break;
        }
    }

    // check balance is enough
    if (utxoAmount < (defaultSupplyAmount + defaultSupplyFee))
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "balance is not enough for token issue, at least 0.0101BCH");

    // create tx
    CMutableTransaction rawTx;
    uint32_t nSequence = std::numeric_limits<uint32_t>::max();
    for (COutput out : utxo) {
        CTxIn in(COutPoint(out.tx->GetHash(), out.i), CScript(), nSequence);
        rawTx.vin.push_back(in);
    }

    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();
    CScript scriptPubKey = GetScriptForDestination(keyID);

    // TODO utxo[0].tx->GetHash().GetHex()
    // TODO put hex into script directly
    std::string tokenid = utxo[0].tx->GetHash().ToString();
    CScript script = CScript() << OP_TOKEN << ToByteVector(tokenid) << CScriptNum(nSupply);
    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    UniValue result(UniValue::VOBJ);
    result.pushKV("tokenid", tokenid);
    result.pushKV("tokenAddress", address);
    result.pushKV("tokenScript", HexStr(script.begin(), script.end()));

    pwallet->AddCScript(script);
    pwallet->SetAddressBook(innerID, "", "token");

    CTxOut supplyOut(defaultSupplyAmount, script);
    rawTx.vout.push_back(supplyOut);

    CAmount chargeAmount = utxoAmount - defaultSupplyAmount - defaultSupplyFee;
    CTxOut chargeOut(chargeAmount, scriptPubKey);
    rawTx.vout.push_back(chargeOut);

    // sign tx
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache& viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : rawTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwallet)
        EnsureWalletIsUnlocked(pwallet);
#endif

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = (!pwallet ? tempKeystore : *pwallet);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY)) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(rawTx);

    // Sign what we can:
    for (unsigned int i = 0; i < rawTx.vin.size(); i++) {
        CTxIn& txin = rawTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < rawTx.vout.size()))
            SignSignature(keystore, prevPubKey, rawTx, i, amount, nHashType);

        // ... and merge in other signatures:
        SignatureData sigdata;
        sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(rawTx, i));
        ScriptError serror = SCRIPT_ERR_OK;

        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&rawTx, i, amount), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }

    if (!vErrors.empty()) {
        result.pushKV("signErrors", vErrors);
        return result;
    }

    // send tx
    uint256 hashTx = rawTx.GetHash();

    bool fOverrideFees = false;

    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, MakeTransactionRef(rawTx), &fMissingInputs, false, !fOverrideFees)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(
                    RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            pwallet->_SyncTransaction(MakeTransactionRef(rawTx), nullptr, -1);
#endif
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }

    g_connman->RelayTransaction(rawTx);

    result.pushKV("txid", hashTx.GetHex());
    return result;
}

UniValue createtokenscript(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error("createtokenscript \"tokename\" \"tokensupply\" \n");

    LOCK(cs_main);
    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR), true);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    std::string name = request.params[0].get_str();

    CAmount supply = atoll(request.params[1].get_str().c_str());
    if (supply > MAX_TOKEN_SUPPLY)
        throw std::runtime_error("tokensupply is out of range");

    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();
    CScript scriptPubKey = GetScriptForDestination(keyID);

    CScript script = CScript() << OP_TOKEN << ToByteVector(name) << CScriptNum(supply);
    script << OP_DROP << OP_DROP;
    script += scriptPubKey;

    CScriptID innerID(script);
    std::string address = EncodeDestination(innerID);
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address);
    result.pushKV("token", HexStr(script.begin(), script.end()));

    pwallet->AddCScript(script);
    pwallet->SetAddressBook(innerID, "", "token");

    return result;
}

UniValue sendtoken(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
            "sendtoken [{\"txid\":\"id\",\"vout\":n},...] [{\"address\":\"xxx\", \"amount\":x.xxx, "
            "\"tokenname\":\"xxx\", \"tokenamount\":xxx, \"data\":\"hex\"},...] \"melt\" \n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's is signed, and broadcast to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",  (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"             (string, required) a json object with outputs\n"
            "     [\n"
            "       {\n"
            "         \"address\":\"xxx\",    (string) The bitcoin address\n"
            "         \"amount\":x.xxx,       (numeric or string) the numeric value (can be string) is the amount\n"
            "         \"tokenname\":\"xxx\",  (string) The token name\n"
            "         \"tokenamount\":xxx,    (string) The token amount\n"
            "         \"data\":\"hex\",       (string) the value is hex encoded data\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "3. melt                    (boolean, optional, default = false) allow melt token \n"

            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n");

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VARR)(UniValue::VARR), true);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments must be non-null");

    UniValue inputs = request.params[0].get_array();
    UniValue outputs = request.params[1].get_array();

    // create token tx
    CMutableTransaction rawTx;
    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());
        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    for (unsigned int idx = 0; idx < outputs.size(); idx++) {
        const UniValue& output = outputs[idx];
        const UniValue& o = output.get_obj();

        if (!find_value(o, "address").isNull() && !find_value(o, "amount").isNull() && find_value(o, "data").isNull()) {
            std::string address = find_value(o, "address").get_str();
            CTxDestination destination = DecodeDestination(address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + address);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + address);
            }

            CScript scriptPubKey;
            if (!find_value(o, "tokenamount").isNull() && !find_value(o, "tokenname").isNull()) {
                std::string name = find_value(o, "tokenname").get_str();
                std::string amount = find_value(o, "tokenamount").get_str();
                CAmount nAmount = atoll(amount.c_str());
                scriptPubKey << OP_TOKEN << ToByteVector(name) << CScriptNum(nAmount) << OP_DROP << OP_DROP;
            }
            scriptPubKey += GetScriptForDestination(destination);

            std::string amount = find_value(o, "amount").get_str();
            CAmount nAmount = AmountFromValue(amount);
            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        } else if (!find_value(o, "data").isNull() && find_value(o, "address").isNull()) {
            std::string hex = find_value(o, "data").get_str();
            if (!IsHex(hex))
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex must be hexadecimal string");

            CTxOut out(0, CScript() << OP_RETURN << ToByteVector(hex));
            rawTx.vout.push_back(out);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output error");
        }
    }

    // sign token tx
    std::vector<CMutableTransaction> txVariants;
    txVariants.push_back(rawTx);

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(rawTx);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache& viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : rawTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    CBasicKeyStore tempKeystore;

#ifdef ENABLE_WALLET
    if (pwallet)
        EnsureWalletIsUnlocked(pwallet);
#endif

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = (!pwallet ? tempKeystore : *pwallet);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY)) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);

    std::map<std::string, CAmount> mVinAmount;
    std::map<std::string, CAmount> mVoutAmount;

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        if (prevPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(prevPubKey.begin() + 2, prevPubKey.begin() + 22);
            CTransaction txToConst(mergedTx);
            TransactionSignatureCreator creator(&keystore, &txToConst, i, amount, nHashType);
            CScript scriptSigRet;
            creator.Provider().GetCScript(uint160(hashBytes), scriptSigRet);

            if (scriptSigRet.IsPayToToken()) {
                int namesize = scriptSigRet[1];
                int amountsize = scriptSigRet[2 + namesize];

                valtype vecName(scriptSigRet.begin() + 2, scriptSigRet.begin() + 2 + namesize);
                std::string name(vecName.begin(), vecName.end());

                valtype vec(scriptSigRet.begin() + 3 + namesize, scriptSigRet.begin() + 3 + namesize + amountsize);
                CAmount amount = CScriptNum(vec, true).getamount();
                if (amount > MAX_TOKEN_SUPPLY)
                    throw std::runtime_error("token amount out of range");

                CAmount temp = mVinAmount[name];
                temp += amount;
                if (temp > MAX_TOKEN_SUPPLY)
                    throw std::runtime_error("vin amount out of range");
                mVinAmount[name] = temp;
            }
        } else if (prevPubKey.IsPayToToken()) {
            int namesize = prevPubKey[1];
            int amountsize = prevPubKey[2 + namesize];

            valtype vecName(prevPubKey.begin() + 2, prevPubKey.begin() + 2 + namesize);
            std::string name(vecName.begin(), vecName.end());

            valtype vec(prevPubKey.begin() + 3 + namesize, prevPubKey.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vec, true).getamount();
            if (amount > MAX_TOKEN_SUPPLY)
                throw std::runtime_error("token amount out of range");

            CAmount temp = mVinAmount[name];
            temp += amount;
            if (temp > MAX_TOKEN_SUPPLY)
                throw std::runtime_error("vin amount out of range");
            mVinAmount[name] = temp;
        }

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, amount, nHashType);

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            SignatureData sigdata;
            sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(txv, i));
            ScriptError serror = SCRIPT_ERR_OK;
        }
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
            MutableTransactionSignatureChecker(&mergedTx, i, amount), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }

    UniValue result(UniValue::VOBJ);
    if (!vErrors.empty()) {
        result.pushKV("hex", EncodeHexTx(mergedTx));
        result.pushKV("signerrors", vErrors);
        return result;
    }

    for (unsigned int i = 0; i < mergedTx.vout.size(); i++) {
        CTxOut& txout = mergedTx.vout[i];
        CScript outScript = txout.scriptPubKey;
        if (outScript.IsPayToToken()) {
            int namesize = outScript[1];
            int amountsize = outScript[2 + namesize];

            valtype vecName(outScript.begin() + 2, outScript.begin() + 2 + namesize);
            std::string name(vecName.begin(), vecName.end());
            valtype vec(outScript.begin() + 3 + namesize, outScript.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vec, true).getamount();
            if (amount > MAX_TOKEN_SUPPLY)
                throw std::runtime_error("amount out of range");

            CAmount temp = mVoutAmount[name];
            temp += amount;
            if (temp > MAX_TOKEN_SUPPLY)
                throw std::runtime_error("vout amount out of range");
            mVoutAmount[name] = temp;
        }
    }

    bool melt = false;
    if (request.params.size() > 2)
        melt = request.params[2].get_bool();

    for (auto& it : mVinAmount) {
        if (it.second < mVoutAmount[it.first]) {
            throw std::runtime_error("vin token amount < vout token amount");
        } else if (!melt && it.second > mVoutAmount[it.first]) {
            throw std::runtime_error("vin token amount > vout token amount, " + std::to_string(it.second - mVoutAmount[it.first]) + " token will be melted");
        }
    }

    // send tx
    uint256 hashTx = mergedTx.GetHash();

    bool fOverrideFees = false;
    bool fHaveChain = false;
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, MakeTransactionRef(mergedTx), &fMissingInputs, false, !fOverrideFees)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(
                    RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
#ifdef ENABLE_WALLET
        else
            pwallet->_SyncTransaction(MakeTransactionRef(mergedTx), nullptr, -1);
#endif
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    g_connman->RelayTransaction(rawTx);

    return hashTx.GetHex();
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)            argNames
  //  --------------------- ------------------------        -----------------------     ----------
    { "token",              "tokenmint",                    &tokenmint,                 {"account","token","supply"} },
    { "token",              "tokentransfer",                &tokentransfer,             {"token", "account","receivers"} },
    { "token",              "tokenlist",                    &tokenlist,                 { } },
    { "token",              "tokensearch",                  &tokensearch,               {"account","token"} },
    { "token",              "tokenaddress",                 &tokenaddress,              {"account"} },
    { "token",              "tokenhistory",                 &tokenhistory,              {"account","token","index","limit"} },
    { "token",              "tokendetail",                  &tokendetail,               {"txid"} },
    { "token",              "sendtoken",                    &sendtoken,                 {"transactions","outputs","melt"} },
};

void RegisterTokenTransactionRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
