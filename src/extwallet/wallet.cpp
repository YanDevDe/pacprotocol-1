// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <ui_interface.h>
#include <extwallet/device.h>
#include <extwallet/extkey.h>
#include <txmempool.h>
#include <util.h>
#include <wallet/extsigner.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>

std::shared_ptr<CWallet> CWallet::CreateWalletInMemory()
{
    uiInterface.InitMessage(_("Initializing hardware wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;

    //! generate memory-based wallet...
    std::shared_ptr<CWallet> walletInstance(new CWallet(WalletLocation(), WalletDatabase::CreateMock()));
    AddWallet(walletInstance);
    auto error = [&](const std::string& strError) {
        RemoveWallet(walletInstance);
        InitError(strError);
        return nullptr;
    };

    walletInstance->LoadWallet(fFirstRun);
    walletInstance->SetMinVersion(FEATURE_HD);
    walletInstance->SetMaxVersion(FEATURE_HD);

    //! ...deterministically from xpub
    CPubKey master_key = CPubKey();
    std::vector<CExtPubKey> acctKeys;
    std::vector<CKeyMetadata> acctKeyMetadata;
    if (!InitWithExtendedPubkey(master_key, acctKeys, acctKeyMetadata))
        return nullptr;
    walletInstance->SetHDMasterKey(master_key, acctKeys, acctKeyMetadata, true);
    walletInstance->TopUpKeyPool();
    walletInstance->SetBestChain(chainActive.GetLocator());

    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);

    {
        LOCK(cs_main);
        WalletRescanReserver reserver(walletInstance.get());
        CBlockIndex* pindexStart = chainActive[Params().GetConsensus().nExternalKeyHeight];
        if (!pindexStart)
            pindexStart = chainActive.Genesis();
        CBlockIndex* pindexStop = chainActive.Tip();
        if (!reserver.reserve()) {
            return error(_("Failed to rescan the wallet during initialization"));
        }
        walletInstance->ScanForWalletTransactions(pindexStart, nullptr, reserver, true);
    }

    walletInstance->m_last_block_processed = chainActive.Tip();
    uiInterface.LoadWallet(walletInstance);

    // Register with the validation interface. It's ok to do this after rescan since we're still holding cs_main.
    RegisterValidationInterface(walletInstance.get());

    {
        LOCK(walletInstance->cs_wallet);
        LogPrintf("setKeyPool.size() = %u\n", walletInstance->GetKeyPoolSize());
        LogPrintf("mapWallet.size() = %u\n", walletInstance->mapWallet.size());
        LogPrintf("mapAddressBook.size() = %u\n", walletInstance->mapAddressBook.size());
        LogPrintf("nTimeFirstKey = %u\n", walletInstance->nTimeFirstKey);
    }

    return walletInstance;
}

bool CWallet::ConvertToPSBT(std::string& rawHexTx, std::string& b64Psbt)
{
    const CBlockIndex* pindex = chainActive.Tip();

    //! Decode to hexstring
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, rawHexTx)) {
        return false;
    }

    for (CTxIn& input : tx.vin) {
        input.scriptSig.clear();
    }

    //! Create the PSBT
    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;

    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        psbtx.inputs.push_back(PSBTInput());
    }

    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        psbtx.outputs.push_back(PSBTOutput());
    }

    // Fill the inputs
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        uint256 blockHash;
        CTransactionRef stx;
        if (!GetTransaction(psbtx.tx->vin[i].prevout.hash, stx, Params().GetConsensus(), blockHash)) {
            LogPrintf("%s - couldnt retrieve tx %s\n", __func__, psbtx.tx->vin[i].prevout.hash.ToString());
            return false;
        }
        input.non_witness_utxo = stx;
    }

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    b64Psbt = EncodeBase64((unsigned char*)ssTx.data(), ssTx.size());

    return true;
}
