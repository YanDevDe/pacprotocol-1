// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <banned.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <consensus/validation.h>
#include <util.h>
#include <validation.h>
#include <wallet/wallet.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <utilmoneystr.h>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                         && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

unsigned int GetTransactionSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    unsigned int nSigOps = GetLegacySigOpCount(tx);

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs);
    }

    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state)
{
    bool allowEmptyTxInOut = false;
    if (tx.nType == TRANSACTION_QUORUM_COMMITMENT) {
        allowEmptyTxInOut = true;
    }

    // Basic checks that don't depend on any context
    if (!allowEmptyTxInOut && tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (!allowEmptyTxInOut && tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_LEGACY_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");
    if (tx.vExtraPayload.size() > MAX_TX_EXTRA_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-payload-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin)
    {
        if (areBannedInputs(txin.prevout.hash, txin.prevout.n))
            return state.DoS(100, false, REJECT_INVALID, "banned-inputs-spent");
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        size_t minCbSize = 2;
        if (tx.nType == TRANSACTION_COINBASE) {
            // With the introduction of CbTx, coinbase scripts are not required anymore to hold a valid block height
            minCbSize = 1;
        }
        if (tx.vin[0].scriptSig.size() < minCbSize || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    const auto pwallet = GetWallets()[0];

    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", false,
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    std::map<std::string, CAmount> mVinToken;
    std::map<std::string, CAmount> mVoutToken;
    std::vector<std::string> vTxid;
    std::vector<std::string> vTokenid;

    for (unsigned int i = 0; i < tx.vin.size(); ++i)
    {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }

        // Verify use of OP_TOKEN
        CScript prevPubkey = coin.out.scriptPubKey;
        if (prevPubkey.IsPayToScriptHash())
        {
            std::vector<unsigned char> vec(prevPubkey.begin() + 2, prevPubkey.begin() + 22);
            CScriptID hash = CScriptID(uint160(vec));
            CScript redeemScript;
            if (pwallet->GetCScript(hash, redeemScript))
            {
                if (!redeemScript.IsPayToToken())
                    continue;
                int namesize = redeemScript[1];
                int amountsize = redeemScript[2 + namesize];
                std::vector<unsigned char> vecName(redeemScript.begin() + 2, redeemScript.begin() + 2 + namesize);
                std::vector<unsigned char> vecAmount(redeemScript.begin() + 3 + namesize, redeemScript.begin() + 3 + namesize + amountsize);
                std::string tokenName(vecName.begin(), vecName.end());
                CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();
                if (tokenAmount > MAX_TOKEN_SUPPLY)
                    return state.DoS(100, false, REJECT_INVALID, "token amount out of range");
                CAmount temp = mVinToken[tokenName];
                temp += tokenAmount;
                if (temp > MAX_TOKEN_SUPPLY)
                    return state.DoS(100, false, REJECT_INVALID, "vin amount out of range");
                mVinToken[tokenName] = temp;
            }
        }
        else if (prevPubkey.IsPayToToken())
        {
            int namesize = prevPubkey[1];
            int amountsize = prevPubkey[2 + namesize];
            std::vector<unsigned char> vecName(prevPubkey.begin() + 2, prevPubkey.begin() + 2 + namesize);
            std::vector<unsigned char> vecAmount(prevPubkey.begin() + 3 + namesize, prevPubkey.begin() + 3 + namesize + amountsize);
            std::string tokenName(vecName.begin(), vecName.end());
            CAmount tokenAmount = CScriptNum(vecAmount, true).getamount();
            mVinToken[tokenName] = tokenAmount;
            if (tokenAmount > MAX_TOKEN_SUPPLY)
                return state.DoS(100, false, REJECT_INVALID, "token amount out of range");
            CAmount temp = mVinToken[tokenName];
            temp += tokenAmount;
            if (temp > MAX_TOKEN_SUPPLY)
                return state.DoS(100, false, REJECT_INVALID, "vin amount out of range");
            mVinToken[tokenName] = temp;
        }
        vTxid.push_back(prevout.hash.ToString());
    }

    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        CTxOut txout = tx.vout[i];
        CScript outScript = txout.scriptPubKey;
        if (outScript.IsPayToToken())
        {
            int namesize = outScript[1];
            int amountsize = outScript[2 + namesize];
            std::vector<unsigned char> vecName(outScript.begin() + 2, outScript.begin() + 2 + namesize);
            std::string name(vecName.begin(), vecName.end());
            std::vector<unsigned char> vec(outScript.begin() + 3 + namesize, outScript.begin() + 3 + namesize + amountsize);
            CAmount amount = CScriptNum(vec, true).getamount();
            if (amount > MAX_TOKEN_SUPPLY)
                return state.DoS(100, false, REJECT_INVALID, "token amount out of range");
            CAmount temp = mVoutToken[name];
            temp += amount;
            if (temp > MAX_TOKEN_SUPPLY)
                return state.DoS(100, false, REJECT_INVALID, "vout amount out of range");
            mVoutToken[name] = temp;
            vTokenid.push_back(name);
        }
    }

    for (auto &it: mVinToken)
    {
        if (it.second < mVoutToken[it.first])
            return state.DoS(100, false, REJECT_INVALID, it.first + ": vin token amount < vout token amount");
    }

    const CAmount nValueOut = tx.GetValueOut();

    if (!tx.IsCoinStake()) {
        if (nValueIn < nValueOut) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));
        }

        // Tally transaction fees
        const CAmount txfee_aux = nValueIn - nValueOut;
        if (!MoneyRange(txfee_aux)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
        }

        txfee = txfee_aux;
    }

    return true;
}
