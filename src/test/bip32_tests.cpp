// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <key.h>
#include <key_io.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>
#include <test/test_dash.h>

#include <string>
#include <vector>

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("pacp8kK8w3JCN9vkFNiSox9Ny37kaD9uvSE7n2MWyy6vXLyZnYhe9cjyjnAegsA9y8d73hh8fhrVZxxwfFmU7pRogj2teKCbedBrs4ZXQLuEYth",
     "pacv1G5EGA3Z6F94odpj4VWSa9NKGz37w7MPKL3vsN36phsW9mc9acUrgGTS25DSqmdPpzLa9vnmxzS9tZuemknmvEBdFshmASnrW3UY56TTTy2",
     0x80000000)
    ("pacp8naYvkbfTR3jPyrA1i21r5Dru2iGJWi8TdnQx4V3VYAr9pzpZrH4rvX4U8iriSXe3uyhXwPvJc32dejc4rABkcVcqwzrZw65Nzh5hywdMTA",
     "pacv1JLeFsM2BWG3xExSGFP5TBURbobUKBqPzwUpqTRDnu4nX3uKzr1woQoqoLZnFV1MY3EGXE7eMMH2cKwNRM4xiJG9KkNuQQVkD47PWG9N39e",
     1)
    ("pacp8pkg8Y9Yr7voERtbjxutSp7WxQhNJYSRPxTFYLFrSAy4PNVxHehNpVRHtDBS8PEz1dbkKMr2RCXWDxURYBL5SGKZ99qi3a6M1jDrzvqRocz",
     "pacv1LWmTetuaD97ngzszWGx3vN5fBaaKDZgwG9fRjC2jXrzkbQTieSFkyi5DPkqrQnPz7yxL3i5S4ESkGTbYgrwVTkaqXLdUAGbsrRm3C2ED7q",
     0x80000002)
    ("pacp8sMxB4yQYznD6bggzZKFop9fBZZta62QjVgvnfZ1c3LVoDh56QXoivyDSENGaFgJN9hUvjpdo96UgHciFGscViUPj3or8XA2jR9168w5Qup",
     "pacv1P83WBimH5zXernyF6gKQvQDtLT6am9gGoPLg4VBuQESASbaXQGgfRFzmRyTpeHtVb1LvWezrU4LyUCM8hn8cZCFC8uBd6WYV8AyfoMUD8M",
     2)
    ("pacp8ubM1W6MjUTCB5AQgpXLhKJyGNrdCgLcAyaE3d5UvUu7AKKSABEAvWS97ZMez3q2qTpf4kJaqszbEhxiLaJpDJwedqN2xi3rk73rEmRfEJp",
     "pacv1RMSLcqiTZfWjLGgwMtQJRZXy9jqDMTsiHGdw21fDqo3XYDwbAy3rzivSkNvHJhKZP93YRtZmHWWSf6oL8KUownHbNzHBBLFe6e9BKQCZ58",
     1000000000)
    ("pacp8wK7VBhbrbqPhQwroN6512Jy4cRw2B9dyDxnHuTd8ZHbsSipgbUqBcbCkPGbqJukKA7Ca6EPP5hBq8MjSRof4a6mWNn7mBdVZ4fmUsyoisL",
     "pacv1T5CpJSxah3iFg493uT8c8ZXmPK92rGuWXfCBJPoRvBYEfdL7bDi86sz5cA8CDpQAnYJKnsWcL3dSq7AsCLCvuRpvskWJ65xvSCVvVUZcvR",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("pacp8kK8w3JCN9vkEzDmv7DfREqWpQJLc4UwTc9FGuqkVj6S5XiqKmWvAgLF2yF8gNz4xFvvaNWey3UCP3VhF1Lxpe2qWFQ4V7gXBSEdgGD2sQm",
     "pacv1G5EGA3Z6F94oFL4Aeaj2M65XBBYcjcCzuqfAJmvo5zNSkdLkmFo7Ad2N8zW2HBV535zuDFEF6ULz6dkpBBUXbWPiHn1Jnhb5J6mS6RMcns",
     0)
    ("pacp8oatCkz9rAkpmFp53tbYV3F3BN3bK2yE1mtcSisCa8xPmWAou2rzKWuVcSD2UTzWAaR6SbWQN8KAYCvP8A3PAEh7nJ8jPTpuJvMJ7VWuPwr",
     "pacv1KLyXsjWaFy9KWvMJRxc69Vbt8voKi6VZ5b2L7oNsVrL8j5KL2bsG1CGweGJfM2KUhKpoDexgFtULcGaNTgXTpfniUC4hGsLCi1KoMkTKQY",
     0xFFFFFFFF)
    ("pacp8pjwTN1gE4vvw82FULbBxNvba7GVrX8v6vy9N7myDsinDoQGWvHJXah6DpT9ECbbx6Le6SN1fLjmCsniu4XVtP9kKNknkC5vBJctxBGeFGG",
     "pacv1LW2nUm2xA9FVP8XisxFZVBAGt9hsCGBeEfZFWi9XEcib2Jmwv2BU4ysYzkHPbkoNveiaErbjGPamr1M6qHf387M9CRQTnbazVLrZp8b1rF",
     1)
    ("pacp8sYusNzcPiE82jhPXzjkvKrpue8zxi4BRNU1DBSJXm5DtdGRpRp1RV5U4ceH25HtYGoBw5TFJU3bHg3joxxT9iceuexdxjX875HrChRnXRz",
     "pacv1PK1CVjy7oSSazofnY6pXS7PcR2CyPBSxgAR6aNUq7yAFrAwFRYtMyNFPnwuRJxVgt1RKXvz8p4o6YnW9ip33bveGxxDJtZyUHmb3S3PVKR",
     0xFFFFFFFE)
    ("pacp8tiwnLvy17BqKgvzGUZJHqZ1pNcN1gggT5Btju8iNXLULybMv6k1x1SZhGmnDSpLViSpjaWxM5NSwKD8Vr4xs5K7BZH8X2cXyJNRjex2srn",
     "pacv1QV37TgKjCQ9sx3GX1vMtwoaX9Va2MowzNtJdJ4tftEQiCVsM6UttVjM2VgJ3jLnETJ7dMhyXBeNufssffiXjSbp6uVXT6bbosn77G7S1F2",
     2)
    ("pacp8v5yjn9UXHW54x7szYgzGavzDS9UG1bm7Eon9gVD1KC4RAvw5jfn8aPZmfr4M2B31mf41W2NEnPSRkGdKwksBLAgpj7DTPuGebZcQL5zNRf",
     "pacv1Rr54ttqFNiPdDEAF643shBYvD2gGgj2eYWC35RPJg5znPqSWjQf54gM6uMJCkRrGm9qv7LnyHV4xDmPPz5knRLXum12WWjKWF7fBoopeyW",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("pacp8kK8w3JCN9vkE3fwSViTdE6Yh3dSMveDAwuogCsJmRBE3mx6yukt7wZmWxn7VyZi8LgnQNPfMiJ3pM8c5iPQEygydVJHDg8My9kLCiTqpvR",
     "pacv1G5EGA3Z6F94nJnDh35XELM7PpWeNbmUiFcDZboV4n5AQzrcQuVm4RrYr8ifyJQp9jkkU8wL9XD4LkF53cKuK51eEaLeWE3ZN1m85zQZMWJ",
      0x80000000)
    ("pacp8ngLg18L3XJ6RamLfe3xgUrDPQEpWn47aS9kVSZ9hj6bJo5ZZQXkCQMUpgcdELATKiBdBL9QCfVYSp4x1xKapDxvJbFAmXdATL7Es99zp5h",
     "pacv1JSS17sgmcWQyqscvBR2Hb6n6B82XTBP7jrANqVL15zXg1z4zQGd8teG9u52KFjjbtQAV5jCoFqWzHtDcpuf4qDGfiFhFPKNV2in3PufwqV",
      0);

void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
    CExtKey key;
    CExtPubKey pubkey;
    key.SetMaster(seed.data(), seed.size());
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;

        CDataStream ssPub(SER_DISK, CLIENT_VERSION);
        ssPub << pubkeyNew;
        BOOST_CHECK(ssPub.size() == 75);

        CDataStream ssPriv(SER_DISK, CLIENT_VERSION);
        ssPriv << keyNew;
        BOOST_CHECK(ssPriv.size() == 75);

        CExtPubKey pubCheck;
        CExtKey privCheck;
        ssPub >> pubCheck;
        ssPriv >> privCheck;

        BOOST_CHECK(pubCheck == pubkeyNew);
        BOOST_CHECK(privCheck == keyNew);
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_SUITE_END()
