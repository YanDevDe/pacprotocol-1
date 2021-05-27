// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <extwallet/device.h>

bool debugMode{true};
std::string extWalletType;
uint8_t extWalletState{UNINITIALIZED};

bool CheckExternalDeviceAttached()
{
    std::string error;
    std::string response;
    std::vector<std::string> paramsList;
    paramsList.push_back("enumerate");
    if (!execCommand(paramsList, response, error)) {
        return false;
    }
    UniValue json_data = json_read_doc(response);
    extWalletType = json_get_key_string(json_data, "type");
    return true;
}

bool IsExternalDeviceAttached()
{
    if (extWalletState == UNINITIALIZED) {
        if (!CheckExternalDeviceAttached()) {
            extWalletState = NOTPRESENT;
            LogPrintf("no device present\n");
        } else {
            extWalletState = PRESENT;
            LogPrintf("hardware device detected (%s)\n", extWalletType);
        }
    }
    return extWalletState == PRESENT;
}

bool InitWithExtendedPubkey(CPubKey& master_key, std::vector<CExtPubKey>& acctKeys, std::vector<CKeyMetadata>& acctKeyMetadata)
{
    if (extWalletState != PRESENT)
        return false;

    LOCK(cs_main);

    std::string error;
    std::vector<uint32_t> path;
    std::string path_string = GetDefaultAccountPath();
    if (!ParseExtKeyPath(path_string, path, error)) {
        LogPrintf("%s - %s\n", __func__, error);
        return false;
    }

    std::string response;
    std::vector<std::string> paramsList;
    paramsList.push_back("-t");
    paramsList.push_back(extWalletType);
    paramsList.push_back("getxpub");
    paramsList.push_back(path_string);
    if (!execCommand(paramsList, response, error)) {
        return false;
    }

    UniValue json_data = json_read_doc(response);
    std::string xpubKey = json_get_key_string(json_data, "xpub");
    CExtPubKey acctKey = DecodeExtPubKey(xpubKey);

    // prepare wallet
    path_string = FormatExtKeyPath(path);
    int64_t creation_time = GetTime();
    CKeyMetadata metadata(creation_time);
    metadata.hdKeypath = path_string;
    acctKeys.push_back(acctKey);
    acctKeyMetadata.push_back(metadata);
    master_key = acctKey.pubkey;

    if (debugMode) {
        LogPrintf("%s - extended pubkey %s\n", __func__, EncodeExtPubKey(acctKey));
    }

    return true;
}

