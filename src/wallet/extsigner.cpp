// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/extsigner.h>

#include <string>
#include <vector>

HardwareSigner::HardwareSigner(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn)
    : txTo(txToIn)
    , nIn(nInIn)
    , amount(amountIn)
    , nHashType(nHashTypeIn)
    , checker(txTo, nIn, amountIn) {};

bool HardwareSigner::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const
{
    const CWallet& wallet = dynamic_cast<const CWallet&>(provider);

    CKeyMetadata metadata;
    {
        LOCK(wallet.cs_wallet);
        auto it = wallet.mapKeyMetadata.find(keyid);
        if (it == wallet.mapKeyMetadata.end()) {
            return false;
        }
        metadata = it->second;
    }

    std::string sError;
    std::vector<uint32_t> vPath;
    if (!ParseExtKeyPath(metadata.hdKeypath, vPath, sError)) {
        return false;
    }

    LogPrintf("%s - Found matching entry %s\n", __func__, metadata.hdKeypath);

    return true;
};
