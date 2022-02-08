// Copyright (c) 2021 pacprotocol
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef POS_STAKE_H
#define POS_STAKE_H

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

extern CWallet* stakingWallet;
using StakeCoinsSet = std::set<std::pair<const CWalletTx*, unsigned int>>;

bool MintableCoins();
inline CAmount GetStakeReward(CAmount blockReward, unsigned int percentage);
bool SelectStakeCoins(StakeCoinsSet& setCoins, CAmount nTargetAmount, const CScript& scriptFilterPubKey);
void FillCoinStakePayments(CMutableTransaction &txNew, const CScript &scriptPubKeyOut, const COutPoint &stakePrevout, CAmount blockReward);
bool CreateCoinStake(unsigned int nBits, CAmount blockReward, CMutableTransaction &txNew, unsigned int &nTxNewTime, std::vector<const CWalletTx*> &vwtxPrev);
bool CreateCoinStakeKernel(CScript &kernelScript, const CScript &stakeScript, unsigned int nBits, const CBlock &blockFrom, unsigned int nTxPrevOffset, const CTransactionRef &txPrev, const COutPoint &prevout, unsigned int &nTimeTx, bool fPrintProofOfStake);

#endif // POS_STAKE_H
