// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ui_interface.h>
#include <extwallet/device.h>
#include <extwallet/extkey.h>
#include <util.h>
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

