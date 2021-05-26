// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PACPROTOCOL_HARDWAREDEVICE_H
#define PACPROTOCOL_HARDWAREDEVICE_H

#include <extwallet/extkey.h>
#include <extwallet/util.h>
#include <extwallet/wrapper.h>
#include <key_io.h>
#include <primitives/block.h>
#include <rpc/rpcutil.h>
#include <util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <validation.h>

#include <univalue.h>

enum {
    UNINITIALIZED,
    NOTPRESENT,
    PRESENT
};

extern uint8_t extWalletState;
extern std::string extWalletType;

bool CheckExternalDeviceAttached();
bool IsExternalDeviceAttached();
bool InitWithExtendedPubkey(CPubKey& master_key, std::vector<CExtPubKey>& acctKeys, std::vector<CKeyMetadata>& acctKeyMetadata);

#endif // PACPROTOCOL_HARDWAREDEVICE_H
