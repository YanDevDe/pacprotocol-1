// Copyright (c) 2022 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stake.h"

#include <checkpoints.h>
#include <chain.h>
#include <wallet/coinselection.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <fs.h>
#include <init.h>
#include <key.h>
#include <key_io.h>
#include <keystore.h>
#include <validation.h>
#include <net.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <timedata.h>
#include <txmempool.h>
#include <utilmoneystr.h>
#include <wallet/fees.h>

#include <coinjoin/coinjoin-client.h>
#include <coinjoin/coinjoin-client-options.h>
#include <governance/governance.h>
#include <keepass.h>

#include <evo/providertx.h>

#include <llmq/quorums_instantsend.h>
#include <llmq/quorums_chainlocks.h>

#include <pos/kernel.h>

typedef std::vector<unsigned char> valtype;

//! wallet ptr
CWallet* stakingWallet = nullptr;
void SetStakingWallet(CWallet* inWallet) {
    stakingWallet = inWallet;
}

//! staking params;
unsigned int nHashDrift{45};
unsigned int nHashInterval{22};
uint64_t nStakeSplitThreshold{2000};
int nStakeSetUpdateTime{300};

bool MintableCoins()
{
    LOCK(stakingWallet->cs_wallet);
    std::vector<COutput> vCoins;
    stakingWallet->AvailableCoins(vCoins, true);
    if (!vCoins.size()) {
        return false;
    }
    for (const COutput& out : vCoins) {
        if (GetTime() - out.tx->GetTxTime() > Params().GetConsensus().nStakeMinAge &&
            out.tx->tx->vout[out.i].nValue > Params().GetConsensus().nMinimumStakeValue) {
            return true;
        }
    }

    return false;
}

bool SelectStakeCoins(StakeCoinsSet& setCoins, CAmount nTargetAmount, const CScript& scriptFilterPubKey)
{
    CCoinControl coinControl;
    std::vector<COutput> vCoins;
    coinControl.fAllowWatchOnly = !scriptFilterPubKey.empty();
    {
        LOCK2(cs_main, stakingWallet->cs_wallet);
        stakingWallet->AvailableCoins(vCoins, !scriptFilterPubKey.empty(), &coinControl);
    }

    CAmount nAmountSelected = 0;
    std::set<CScript> rejectCache;
    for (const auto& out : vCoins) {
        CTxDestination dest;
        CScript scriptPubKeyKernel = out.tx->tx->vout[out.i].scriptPubKey;
        if (!coinControl.fAllowWatchOnly && !out.fSpendable)
            continue;
        if (!ExtractDestination(scriptPubKeyKernel, dest))
            continue;
        if (GetTime() - out.tx->GetTxTime() < Params().GetConsensus().nStakeMinAge)
            continue;
        if (out.nDepth < (out.tx->tx->IsCoinStake() ? 100 : 10))
            continue;
        if (out.tx->tx->vout[out.i].nValue == Params().GetConsensus().nMasternodeCollateral)
            continue;
        if (out.tx->tx->vout[out.i].nValue < Params().GetConsensus().nMinimumStakeValue)
            continue;
        if (!scriptFilterPubKey.empty() && (scriptPubKeyKernel != scriptFilterPubKey))
            continue;
        if (rejectCache.count(scriptPubKeyKernel))
            continue;

        nAmountSelected += out.tx->tx->vout[out.i].nValue;
        setCoins.emplace(out.tx, out.i);
    }
    return true;
}

inline CAmount GetStakeReward(CAmount blockReward, unsigned int percentage)
{
    return (blockReward / 100) * percentage;
}

void FillCoinStakePayments(CMutableTransaction &txNew, const CScript &scriptPubKeyOut, const COutPoint &stakePrevout, CAmount blockReward)
{
    const CWalletTx *walletTx = stakingWallet->GetWalletTx(stakePrevout.hash);
    CTxOut prevTxOut = walletTx->tx->vout[stakePrevout.n];
    auto nCredit = prevTxOut.nValue;
    unsigned int percentage = 100;

    auto nCoinStakeReward = nCredit + GetStakeReward(blockReward, percentage);
    txNew.vin.emplace_back(CTxIn(stakePrevout));
    txNew.vout.emplace_back(nCoinStakeReward, scriptPubKeyOut);
    {
        CTxOut &lastTx = txNew.vout.back();
        if(lastTx.nValue / 2 > nStakeSplitThreshold * COIN) {
            lastTx.nValue /= 2;
            txNew.vout.emplace_back(lastTx.nValue, lastTx.scriptPubKey);
        }
    }
}

bool CreateCoinStake(unsigned int nBits, CAmount blockReward, CMutableTransaction &txNew, unsigned int &nTxNewTime, std::vector<const CWalletTx*> &vwtxPrev)
{
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    CAmount nBalance = stakingWallet->GetBalance();
    static StakeCoinsSet setStakeCoins;
    static int nLastStakeSetUpdate = 0;
    if (GetTime() - nLastStakeSetUpdate > nStakeSetUpdateTime) {
        setStakeCoins.clear();
        CScript scriptPubKey;
        if (!SelectStakeCoins(setStakeCoins, nBalance, scriptPubKey)) {
            return error("Failed to select coins for staking");
        }
        LogPrintf("Selected %d coins for staking\n", setStakeCoins.size());
        nLastStakeSetUpdate = GetTime();
    }

    if (setStakeCoins.empty())
        return error("CreateCoinStake() : No Coins to stake");

    bool fKernelFound = false;
    CScript scriptPubKeyKernel;
    for (const auto &pcoin : setStakeCoins)
    {
        CBlockIndex* pindex = nullptr;
        BlockMap::iterator it = mapBlockIndex.find(pcoin.first->hashBlock);
        if (it != mapBlockIndex.end()) {
            pindex = it->second;
        } else {
            LogPrintf("failed to find block index\n");
            continue;
        }

        // Read block header
        CBlockHeader block = pindex->GetBlockHeader();
        COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
        nTxNewTime = GetAdjustedTime();

        //iterates each utxo inside of CheckStakeKernelHash()
        CScript kernelScript;
        auto stakeScript = pcoin.first->tx->vout[pcoin.second].scriptPubKey;
        fKernelFound = CreateCoinStakeKernel(kernelScript, stakeScript, nBits, block, sizeof(CBlock), pcoin.first->tx, prevoutStake, nTxNewTime, false);
        if (fKernelFound) {
            FillCoinStakePayments(txNew, kernelScript, prevoutStake, blockReward);
            break;
        }
    }

    if (!fKernelFound) {
        LogPrintf("Failed to find a coinstake\n");
        return false;
    }

    nLastStakeSetUpdate = 0;
    return true;
}

bool CreateCoinStakeKernel(CScript &kernelScript, const CScript &stakeScript, unsigned int nBits, const CBlock &blockFrom, unsigned int nTxPrevOffset, const CTransactionRef &txPrev, const COutPoint &prevout, unsigned int &nTimeTx, bool fPrintProofOfStake)
{
    if (blockFrom.GetBlockTime() + Params().GetConsensus().nStakeMinAge + nHashDrift > nTimeTx)
        return false;

    unsigned int nTryTime = 0;
    uint256 hashProofOfStake = uint256();
    for (unsigned int i = 0; i < nHashDrift; ++i)
    {
        nTryTime = nTimeTx - i;
        if (CheckStakeKernelHash(nBits, chainActive.Tip(), blockFrom, nTxPrevOffset, txPrev, prevout, nTryTime, hashProofOfStake))
        {
            if (nTryTime <= chainActive.Tip()->GetMedianTimePast()) {
                LogPrintf("CreateCoinStakeKernel() : kernel found, but it is too far in the past \n");
                continue;
            }

            LogPrintf("CreateCoinStakeKernel : kernel found\n");
            kernelScript.clear();
            kernelScript = stakeScript;
            nTimeTx = nTryTime;
            return true;
        }
    }
    return false;
}
