// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2021 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <chain.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <httpserver.h>
#include <keepass.h>
#include <key_io.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <rpc/mining.h>
#include <rpc/rawtransaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <timedata.h>
#include <txmempool.h>
#include <util.h>
#include <utilmoneystr.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <init.h> // For StartShutdown
#include <stdint.h>

#include <univalue.h>

#include <functional>

UniValue listtokenunspent(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listtokenunspent \n"
            "\nReturns array of unspent transaction outputs\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}\n"

            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",        (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",  (string) the bitcoin address\n"
            "    \"scriptPubKey\" : \"key\", (string) the script key\n"
            "    \"redeemScript\" : \"script\", (string) the redeem script\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction amount in "
            + CURRENCY_UNIT + "\n"
                              "    \"confirmations\" : n       (numeric) The number of confirmations\n"
                              "    \"token\" : \"token name\", (string) the token name\n"
                              "    \"tokenAmount\" : \"token amount\", (numeric) the token amount\n"
                              "  }\n"
                              "  ,...\n"
                              "]\n");

    int nMinDepth = 1;
    int nMaxDepth = 9999999;

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    assert(pwallet != nullptr);
    LOCK2(cs_main, pwallet->cs_wallet);
    pwallet->AvailableCoins(vecOutputs, false, NULL, true);
    for (const COutput& out : vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CAmount nValue = out.tx->tx->vout[out.i].nValue;
        const CScript& pk = out.tx->tx->vout[out.i].scriptPubKey;

        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    if (!redeemScript.IsPayToToken())
                        continue;

                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("txid", out.tx->GetHash().GetHex());
                    entry.pushKV("vout", out.i);
                    CTxDestination address;
                    if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address))
                        entry.pushKV("address", EncodeDestination(address));

                    entry.pushKV("scriptPubKey", HexStr(pk.begin(), pk.end()));
                    entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
                    entry.pushKV("satoshi", UniValue(nValue));
                    entry.pushKV("amount", ValueFromAmount(nValue));
                    entry.pushKV("confirmations", out.nDepth);
                    entry.pushKV("spendable", out.fSpendable);

                    int namesize = redeemScript[1];
                    int amountsize = redeemScript[2 + namesize];
                    std::vector<unsigned char> vecName(redeemScript.begin() + 2, redeemScript.begin() + 2 + namesize);
                    std::vector<unsigned char> vecAmount(redeemScript.begin() + 3 + namesize, redeemScript.begin() + 3 + namesize + amountsize);
                    std::string tokenName(vecName.begin(), vecName.end());
                    CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

                    entry.pushKV("token", tokenName);
                    entry.pushKV("tokenAmount", tokenAmount);
                    results.push_back(entry);
                }
            }
        } else if (pk.IsPayToToken()) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("txid", out.tx->GetHash().GetHex());
            entry.pushKV("vout", out.i);
            CTxDestination address;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address)) {
                entry.pushKV("address", EncodeDestination(address));
                entry.pushKV("scriptPubKey", HexStr(pk.begin(), pk.end()));
                entry.pushKV("satoshi", UniValue(nValue));
                entry.pushKV("amount", ValueFromAmount(nValue));
                entry.pushKV("confirmations", out.nDepth);
                entry.pushKV("spendable", out.fSpendable);

                int namesize = pk[1];
                int amountsize = pk[2 + namesize];
                std::vector<unsigned char> vecName(pk.begin() + 2, pk.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(pk.begin() + 3 + namesize, pk.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();

                entry.pushKV("token", tokenName);
                entry.pushKV("tokenAmount", tokenAmount);
                results.push_back(entry);
            }
        }
    }
    return results;
}

UniValue gettokenbalance(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error("gettokenbalance \n"
                                 "\nreturns the token balance in the account.\n");

    LOCK2(cs_main, pwallet->cs_wallet);
    return pwallet->GetTokenBalance();
}

static const CRPCCommand commands[] = {
    //  category              name                        actor (function)           argNames
    //  --------------------- ------------------------    -----------------------    ----------
      { "token",              "listtokenunspent",         &listtokenunspent,         {} },
      { "token",              "gettokenbalance",          &gettokenbalance,          {} },
};

void RegisterTokenRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
