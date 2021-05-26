// Copyright (c) 2021 pacprotocol
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <extwallet/wrapper.h>

bool haveTested{false};
bool isConnected{false};

inline std::string trim(std::string& str)
{
    str.erase(0, str.find_first_not_of('['));
    str.erase(str.find_last_not_of(']')+1);
    return str;
}

bool execCommand(std::vector<std::string>& params, std::string& response, std::string& error)
{
    CProcess cmdInstance;
    cmdInstance.setForExecute("/usr/local/bin/hwi", params);
    cmdInstance.waitForFinished();
    response = trim(REF(cmdInstance.readAllStandardOutput()));
    if (!cmdInstance.readAllStandardError().empty()) {
        error = trim(REF(cmdInstance.readAllStandardError()));
        return false;
    }
    return true;
}
