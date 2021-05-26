#ifndef BLOCKSIGNER_H
#define BLOCKSIGNER_H

class CBlock;
class CPubKey;
class CKey;
class CKeyStore;

bool GetKeyIDFromUTXO(const CTxOut& txout, CKeyID& keyID);
bool SignBlock(CBlock& block, const CKeyStore& keystore);

#endif // BLOCKSIGNER_H
