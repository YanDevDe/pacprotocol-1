// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <uint256.h>


typedef std::vector<unsigned char> valtype;

TransactionSignatureCreator::TransactionSignatureCreator(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn) : txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn) {}

bool TransactionSignatureCreator::CreateSig(const SigningProvider& m_provider, std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    CKey key;
    if (!m_provider.GetKey(address, key))
        return false;

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

static bool GetCScript(const SigningProvider& provider, const SignatureData& sigdata, const CScriptID& scriptid, CScript& script)
{
    if (provider.GetCScript(scriptid, script)) {
        return true;
    }
    // Look for scripts in SignatureData
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider, SignatureData& sigdata, const CKeyID& address, CPubKey& pubkey)
{
    // Look for pubkey in all partial sigs
    const auto it = sigdata.signatures.find(address);
    if (it != sigdata.signatures.end()) {
        pubkey = it->second.first;
        return true;
    }
    // Look for pubkey in pubkey list
    const auto& pk_it = sigdata.misc_pubkeys.find(address);
    if (pk_it != sigdata.misc_pubkeys.end()) {
        pubkey = pk_it->second.first;
        return true;
    }
    // Query the underlying provider
    if (provider.GetPubKey(address, pubkey)) {
        KeyOriginInfo info;
        if (provider.GetKeyOrigin(address, info)) {
            sigdata.misc_pubkeys.emplace(address, std::make_pair(pubkey, std::move(info)));
        }
        return true;
    }
    return false;
}

static bool Sign1(const SigningProvider &provider, const CKeyID& address, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion)
{
    std::vector<unsigned char> vchSig;
    if (!creator.CreateSig(provider, vchSig, address, scriptCode, sigversion))
        return false;
    ret.push_back(vchSig);
    return true;
}

static bool SignN(const SigningProvider &provider, const std::vector<valtype>& multisigdata, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(provider, keyID, creator, scriptCode, ret, sigversion))
            ++nSigned;
    }
    return nSigned==nRequired;
}

static bool CreateSig(const BaseSignatureCreator& creator, SignatureData& sigdata, const SigningProvider& provider, std::vector<unsigned char>& sig_out, const CPubKey& pubkey, const CScript& scriptcode, SigVersion sigversion)
{
    CKeyID keyid = pubkey.GetID();
    const auto it = sigdata.signatures.find(keyid);
    if (it != sigdata.signatures.end()) {
        sig_out = it->second.second;
        return true;
    }
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(keyid, info)) {
        sigdata.misc_pubkeys.emplace(keyid, std::make_pair(pubkey, std::move(info)));
    }
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        auto i = sigdata.signatures.emplace(keyid, SigPair(pubkey, sig_out));
        assert(i.second);
        return true;
    }
    return false;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const SigningProvider &provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, txnouttype& whichTypeRet, SigVersion sigversion, SignatureData& sigdata)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();
    std::vector<unsigned char> sig;

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        if (!CreateSig(creator, sigdata, provider, sig, CPubKey(vSolutions[0]), scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        return true;
    case TX_PUBKEYHASH: {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (!GetPubKey(provider, sigdata, keyID, pubkey)) {
            // Pubkey could not be found, add to missing
            sigdata.missing_pubkeys.push_back(keyID);
            return false;
        }
        if (!CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) return false;
        ret.push_back(std::move(sig));
        ret.push_back(ToByteVector(pubkey));
        return true;
    }
    case TX_SCRIPTHASH:
        if (GetCScript(provider, sigdata, uint160(vSolutions[0]), scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;

    case TX_MULTISIG: {
        size_t required = vSolutions.front()[0];
        ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        for (size_t i = 1; i < vSolutions.size() - 1; ++i) {
            CPubKey pubkey = CPubKey(vSolutions[i]);
            if (ret.size() < required + 1 && CreateSig(creator, sigdata, provider, sig, pubkey, scriptPubKey, sigversion)) {
                ret.push_back(std::move(sig));
            }
        }
        bool ok = ret.size() == required + 1;
        for (size_t i = 0; i + ret.size() < required + 1; ++i) {
            ret.push_back(valtype());
        }
        return ok;
    }

    default:
        return false;
    }
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for(const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const SigningProvider &provider, const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    std::vector<valtype> result;
    txnouttype whichType;
    bool solved = SignStep(provider, creator, fromPubKey, result, whichType, SigVersion::BASE, sigdata);
    bool P2SH = false;
    CScript subscript;

    if (solved && whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        subscript = CScript(result[0].begin(), result[0].end());
        solved = solved && SignStep(provider, creator, subscript, result, whichType, SigVersion::BASE, sigdata) && whichType != TX_SCRIPTHASH;
        P2SH = true;
    }

    if (P2SH) {
        result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    return solved && VerifyScript(sigdata.scriptSig, fromPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

bool SignPSBTInput(const SigningProvider& provider, const CMutableTransaction& tx, PSBTInput& input, int index, int sighash)
{
    // if this input has a final scriptsig, don't do anything with it
    if (!input.final_script_sig.empty()) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    CTxOut utxo = input.non_witness_utxo->vout[tx.vin[index].prevout.n];
    MutableTransactionSignatureCreator creator(&tx, index, utxo.nValue, sighash);
    bool sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    input.FromSignatureData(sigdata);

    return sig_complete;
}

SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    return data;
}

void UpdateInput(CTxIn& input, const SignatureData& data)
{
    input.scriptSig = data.scriptSig;
}

void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data)
{
    assert(tx.vin.size() > nIn);
    UpdateInput(tx.vin[nIn], data);
}

bool SignSignature(const SigningProvider &provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType)
{
    assert(nIn < txTo.vin.size());

    CTransaction txToConst(txTo);
    TransactionSignatureCreator creator(&txToConst, nIn, amount, nHashType);

    SignatureData sigdata;
    bool ret = ProduceSignature(provider, creator, fromPubKey, sigdata);
    UpdateTransaction(txTo, nIn, sigdata);
    return ret;
}

bool SignSignature(const SigningProvider &provider, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(provider, txout.scriptPubKey, txTo, nIn, txout.nValue, nHashType);
}

bool IsSolvable(const SigningProvider& provider, const CScript& script)
{
    // This check is to make sure that the script we created can actually be solved for and signed by us
    // if we were to have the private keys. This is just to make sure that the script is valid and that,
    // if found in a transaction, we would still accept and relay that transaction. In particular,
    // it will reject witness outputs that require signing with an uncompressed public key.
    SignatureData sigs;
    if (ProduceSignature(provider, DummySignatureCreator(), script, sigs)) {
        return true;
    }
    return false;
}

static std::vector<valtype> CombineMultisig(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                               const std::vector<valtype>& vSolutions,
                               const std::vector<valtype>& sigs1, const std::vector<valtype>& sigs2, SigVersion sigversion)
{
    // Combine all the signatures we've got:
    std::set<valtype> allsigs;
    for (const valtype& v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    for (const valtype& v : sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    std::map<valtype, valtype> sigs;
    for (const valtype& sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey, sigversion))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    std::vector<valtype> result; result.push_back(valtype()); // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result.push_back(sigs[vSolutions[i+1]]);
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result.push_back(valtype());

    return result;
}

namespace
{
struct Stacks
{
    std::vector<valtype> script;

    Stacks() {}
    explicit Stacks(const std::vector<valtype>& scriptSigStack_) : script(scriptSigStack_) {}
    explicit Stacks(const SignatureData& data) {
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SigVersion::BASE);
    }

    SignatureData Output() const {
        SignatureData result;
        result.scriptSig = PushAll(script);
        return result;
    }
};
}

static Stacks CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                                 const txnouttype txType, const std::vector<valtype>& vSolutions,
                                 Stacks sigs1, Stacks sigs2, SigVersion sigversion)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.script.size() >= sigs2.script.size())
            return sigs1;
        return sigs2;
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.script.empty() || sigs1.script[0].empty())
            return sigs2;
        return sigs1;
    case TX_SCRIPTHASH:
        if (sigs1.script.empty() || sigs1.script.back().empty())
            return sigs2;
        else if (sigs2.script.empty() || sigs2.script.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            valtype spk = sigs1.script.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            std::vector<std::vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.script.pop_back();
            sigs2.script.pop_back();
            Stacks result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, sigversion);
            result.script.push_back(spk);
            return result;
        }
    case TX_MULTISIG:
        return Stacks(CombineMultisig(scriptPubKey, checker, vSolutions, sigs1.script, sigs2.script, sigversion));
    default:
        return Stacks();
    }
}

SignatureData CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                          const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    txnouttype txType;
    std::vector<std::vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, Stacks(scriptSig1), Stacks(scriptSig2), SigVersion::BASE).Output();
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
} // namespace

const BaseSignatureChecker& DummySignatureCreator::Checker() const
{
    return dummyChecker;
}

bool DummySignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const
{
    // Create a dummy signature that is a valid DER-encoding
    vchSig.assign(72, '\000');
    vchSig[0] = 0x30;
    vchSig[1] = 69;
    vchSig[2] = 0x02;
    vchSig[3] = 33;
    vchSig[4] = 0x01;
    vchSig[4 + 33] = 0x02;
    vchSig[5 + 33] = 32;
    vchSig[6 + 33] = 0x01;
    vchSig[6 + 33 + 32] = SIGHASH_ALL;
    return true;
}

template<typename M, typename K, typename V>
bool LookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}

const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR = DummySignatureCreator();
const SigningProvider& DUMMY_SIGNING_PROVIDER = SigningProvider();

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

void PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }

        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    non_witness_utxo = input.non_witness_utxo;
    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && hd_keypaths.empty() && unknown.empty();
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
}

bool HidingSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetKey(keyid, key);
}

bool HidingSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    if (m_hide_origin) return false;
    return m_provider->GetKeyOrigin(keyid, info);
}

bool FlatSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const { return LookupHelper(scripts, scriptid, script); }
bool FlatSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const { return LookupHelper(pubkeys, keyid, pubkey); }
bool FlatSigningProvider::GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const
{
    std::pair<CPubKey, KeyOriginInfo> out;
    bool ret = LookupHelper(origins, keyid, out);
    if (ret) info = std::move(out.second);
    return ret;
}
bool FlatSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const { return LookupHelper(keys, keyid, key); }

FlatSigningProvider Merge(const FlatSigningProvider& a, const FlatSigningProvider& b)
{
    FlatSigningProvider ret;
    ret.scripts = a.scripts;
    ret.scripts.insert(b.scripts.begin(), b.scripts.end());
    ret.pubkeys = a.pubkeys;
    ret.pubkeys.insert(b.pubkeys.begin(), b.pubkeys.end());
    ret.keys = a.keys;
    ret.keys.insert(b.keys.begin(), b.keys.end());
    ret.origins = a.origins;
    ret.origins.insert(b.origins.begin(), b.origins.end());
    return ret;
}
