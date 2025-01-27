#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwally-core/include/wally_core.h"
#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_map.h"
#include "libwally-core/include/wally_script.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-1-key-path-spend
//      private key:   55d7c5a9ce3d2b15a62434d01205f3e59077d51316f5c20628b3a4b8b2a76f4c
//      public key:    924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329
//      tweak:         8dc8b9030225e044083511759b58328b46dffcc78b920b4b97169f9d7b43d3b5
//      tweak pubkey:  0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
//      tweak privkey: 37f0f35933e8b52e6210dca589523ea5b66827b4749c49456e62fae4c89c6469
//      script pubkey: 51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
//      sighash:       a7b390196945d71549a2454f0185ece1b47c56873cf41789d78926852c355132
//      signature:     b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae
static const uint8_t INTERNAL_PRIVKEY[] = {
    0x55, 0xd7, 0xc5, 0xa9, 0xce, 0x3d, 0x2b, 0x15,
    0xa6, 0x24, 0x34, 0xd0, 0x12, 0x05, 0xf3, 0xe5,
    0x90, 0x77, 0xd5, 0x13, 0x16, 0xf5, 0xc2, 0x06,
    0x28, 0xb3, 0xa4, 0xb8, 0xb2, 0xa7, 0x6f, 0x4c,
};

static const uint8_t TWEAK_PRIVKEY[] = {
    0x37, 0xf0, 0xf3, 0x59, 0x33, 0xe8, 0xb5, 0x2e,
    0x62, 0x10, 0xdc, 0xa5, 0x89, 0x52, 0x3e, 0xa5,
    0xb6, 0x68, 0x27, 0xb4, 0x74, 0x9c, 0x49, 0x45,
    0x6e, 0x62, 0xfa, 0xe4, 0xc8, 0x9c, 0x64, 0x69,
};
static const uint8_t TWEAK_PUBKEY[] = {
    0x0f, 0x0c, 0x8d, 0xb7, 0x53, 0xac, 0xbd, 0x17,
    0x34, 0x3a, 0x39, 0xc2, 0xf3, 0xf4, 0xe3, 0x5e,
    0x4b, 0xe6, 0xda, 0x74, 0x9f, 0x9e, 0x35, 0x13,
    0x7a, 0xb2, 0x20, 0xe7, 0xb2, 0x38, 0xa6, 0x67,
};

#define TXHASH { \
    0xec, 0x90, 0x16, 0x58, 0x0d, 0x98, 0xa9, 0x39,\
    0x09, 0xfa, 0xf9, 0xd2, 0xf4, 0x31, 0xe7, 0x4f,\
    0x78, 0x1b, 0x43, 0x8d, 0x81, 0x37, 0x2b, 0xb6,\
    0xaa, 0xb4, 0xdb, 0x67, 0x72, 0x5c, 0x11, 0xa7,\
}

static const uint8_t WITNESS_PROGRAM[] = {
    0x51, 0x20, 0x0f, 0x0c, 0x8d, 0xb7, 0x53, 0xac,
    0xbd, 0x17, 0x34, 0x3a, 0x39, 0xc2, 0xf3, 0xf4,
    0xe3, 0x5e, 0x4b, 0xe6, 0xda, 0x74, 0x9f, 0x9e,
    0x35, 0x13, 0x7a, 0xb2, 0x20, 0xe7, 0xb2, 0x38,
    0xa6, 0x67,
};

static const uint8_t SIGHASH[] = {
    0xa7, 0xb3, 0x90, 0x19, 0x69, 0x45, 0xd7, 0x15,
    0x49, 0xa2, 0x45, 0x4f, 0x01, 0x85, 0xec, 0xe1,
    0xb4, 0x7c, 0x56, 0x87, 0x3c, 0xf4, 0x17, 0x89,
    0xd7, 0x89, 0x26, 0x85, 0x2c, 0x35, 0x51, 0x32,
};

static const uint8_t SIG[] = {
    0xb6, 0x93, 0xa0, 0x79, 0x7b, 0x24, 0xba, 0xe1,
    0x2e, 0xd0, 0x51, 0x6a, 0x2f, 0x5b, 0xa7, 0x65,
    0x61, 0x8d, 0xca, 0x89, 0xb7, 0x5e, 0x49, 0x8b,
    0xa5, 0xb7, 0x45, 0xb7, 0x16, 0x44, 0x36, 0x22,
    0x98, 0xa4, 0x5c, 0xa3, 0x92, 0x30, 0xd1, 0x0a,
    0x02, 0xee, 0x62, 0x90, 0xa9, 0x1c, 0xeb, 0xf9,
    0x83, 0x96, 0x00, 0xf7, 0xe3, 0x51, 0x58, 0xa4,
    0x47, 0xea, 0x18, 0x2e, 0xa0, 0xe0, 0x22, 0xae,
    0x01,
};

static const uint8_t TXDATA[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xec,
    0x90, 0x16, 0x58, 0x0d, 0x98, 0xa9, 0x39, 0x09,
    0xfa, 0xf9, 0xd2, 0xf4, 0x31, 0xe7, 0x4f, 0x78,
    0x1b, 0x43, 0x8d, 0x81, 0x37, 0x2b, 0xb6, 0xaa,
    0xb4, 0xdb, 0x67, 0x72, 0x5c, 0x11, 0xa7, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x01, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x16, 0x00, 0x14, 0x4e, 0x44, 0xca, 0x79,
    0x2c, 0xe5, 0x45, 0xac, 0xba, 0x99, 0xd4, 0x13,
    0x04, 0x46, 0x0d, 0xd1, 0xf5, 0x3b, 0xe3, 0x84,
    0x01, 0x41, 0xb6, 0x93, 0xa0, 0x79, 0x7b, 0x24,
    0xba, 0xe1, 0x2e, 0xd0, 0x51, 0x6a, 0x2f, 0x5b,
    0xa7, 0x65, 0x61, 0x8d, 0xca, 0x89, 0xb7, 0x5e,
    0x49, 0x8b, 0xa5, 0xb7, 0x45, 0xb7, 0x16, 0x44,
    0x36, 0x22, 0x98, 0xa4, 0x5c, 0xa3, 0x92, 0x30,
    0xd1, 0x0a, 0x02, 0xee, 0x62, 0x90, 0xa9, 0x1c,
    0xeb, 0xf9, 0x83, 0x96, 0x00, 0xf7, 0xe3, 0x51,
    0x58, 0xa4, 0x47, 0xea, 0x18, 0x2e, 0xa0, 0xe0,
    0x22, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00,
};

static void help(const char *cmd)
{
    printf("usage:\n");
    printf("  %s <1 or 2>\n", cmd);
    printf("     1: address\n");
    printf("     2: spent transaction\n");
}

static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void address(void)
{
    int rc;

    uint8_t internalPubKey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_from_private_key(INTERNAL_PRIVKEY, EC_PRIVATE_KEY_LEN, internalPubKey, sizeof(internalPubKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_from_private_key fail: %d\n", rc);
        return;
    }
    printf("internal pubkey: ");
    dump(internalPubKey, sizeof(internalPubKey));

    uint8_t tweakPubKey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_bip341_tweak(internalPubKey, sizeof(internalPubKey), NULL, 0, 0, tweakPubKey, sizeof(tweakPubKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    printf("tweak pubkey:    ");
    dump(tweakPubKey, sizeof(tweakPubKey));
    const uint8_t *tweakXonlyPubKey = tweakPubKey + 1;
    if (memcmp(tweakXonlyPubKey, TWEAK_PUBKEY, sizeof(TWEAK_PUBKEY)) != 0) {
        printf("tweakXonlyPubKey not same\n");
    }

    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN];
    rc = wally_ec_private_key_bip341_tweak(INTERNAL_PRIVKEY, sizeof(INTERNAL_PRIVKEY), NULL, 0, 0, tweakPrivKey, sizeof(tweakPrivKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_private_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    printf("tweak privkey:   ");
    dump(tweakPrivKey, sizeof(tweakPrivKey));
    if (memcmp(tweakPrivKey, TWEAK_PRIVKEY, sizeof(TWEAK_PRIVKEY)) != 0) {
        printf("tweakPrivKey not same\n");
    }

    // uint8_t witnessProgram[WALLY_SEGWIT_V1_ADDRESS_PUBKEY_LEN];
    // witnessProgram[0] = OP_1;
    // witnessProgram[1] = EC_XONLY_PUBLIC_KEY_LEN;
    // memcpy(&witnessProgram[2], tweakPubKey + 1, sizeof(tweakPubKey) - 1);
    // size_t witnessProgramLen = sizeof(witnessProgram);

    uint8_t witnessProgram[WALLY_WITNESSSCRIPT_MAX_LEN];
    size_t witnessProgramLen = 0;
    rc = wally_witness_program_from_bytes_and_version(tweakXonlyPubKey, EC_XONLY_PUBLIC_KEY_LEN, 1, 0, witnessProgram, sizeof(witnessProgram), &witnessProgramLen);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_program_from_bytes fail: %d\n", rc);
        return;
    }
    printf("witness program: ");
    dump(witnessProgram, witnessProgramLen);

    // // bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf
    char *address;
    rc = wally_addr_segwit_from_bytes(witnessProgram, witnessProgramLen, "bc", 0, &address);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_from_bytes fail: %d\n", rc);
        return;
    }
    printf("address: %s\n", address);
    wally_free_string(address);
}

static void spent(void)
{
    int rc;
    struct wally_tx *tx = NULL;

#if 0
    // create wally_tx from HEX data
    rc = wally_tx_from_bytes(TXDATA, sizeof(TXDATA), 0, &tx); // "flags" is used only for WALLY_TX_FLAG_USE_ELEMENTS
    if (rc != WALLY_OK) {
        printf("error: wally_tx_from_bytes fail: %d\n", rc);
        return;
    }
#endif

#if 0
    // create wally_tx using wally_tx_add_input/output
    rc = wally_tx_init_alloc(
        2, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        return;
    }

    const struct wally_tx_witness_item WIT_ITEM = {
        .witness = (unsigned char *)SIG,
        .witness_len = sizeof(SIG),
    };
    const struct wally_tx_witness_stack WITNESS = {
        .items = (struct wally_tx_witness_item *)&WIT_ITEM,
        .num_items = 1,
        .items_allocation_len = 1,
    };
    const struct wally_tx_input TX_INPUT = {
        .txhash = TXHASH,
        .index = 0,
        .sequence = 0xffffffff,
        .script = NULL,
        .script_len = 0,
        .witness = (struct wally_tx_witness_stack *)&WITNESS,
        .features = 0,
    };
    rc = wally_tx_add_input(tx, &TX_INPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        return;
    }

    const char OUTADDR[] = "bc1qfezv57fvu4z6ew5e6sfsg3sd686nhcuyt8ukve";
    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(OUTADDR, "bc", 0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        return;
    }

    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = 10000,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx, &TX_OUTPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_output fail: %d\n", rc);
        return;
    }
#endif

#if 1
    // create sigHash, sig and wally_tx
    rc = wally_tx_init_alloc(
        2, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        return;
    }

    // https://mempool.space/ja/tx/a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec#vout=0
    const struct wally_tx_input TX_INPUT = {
        .txhash = TXHASH,
        .index = 0,
        .sequence = 0xffffffff,
        .script = NULL,
        .script_len = 0,
        .witness = NULL,
        .features = 0,
    };
    rc = wally_tx_add_input(tx, &TX_INPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        return;
    }

    const char OUTADDR[] = "bc1qfezv57fvu4z6ew5e6sfsg3sd686nhcuyt8ukve";
    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(OUTADDR, "bc", 0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        return;
    }

    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = 10000,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx, &TX_OUTPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_output fail: %d\n", rc);
        return;
    }

    uint8_t sigHash[EC_MESSAGE_HASH_LEN];
    struct wally_map *scriptPubKey;
    rc = wally_map_init_alloc(1, NULL, &scriptPubKey);
    if (rc != WALLY_OK) {
        printf("error: wally_map_init_alloc fail: %d\n", rc);
        return;
    }
    rc = wally_map_add_integer(
        scriptPubKey,
        0, // key
        WITNESS_PROGRAM, sizeof(WITNESS_PROGRAM));
    if (rc != WALLY_OK) {
        printf("error: wally_map_add_integer fail: %d\n", rc);
        return;
    }

    const uint64_t VALUES[] = { 20000 };
    rc = wally_tx_get_btc_taproot_signature_hash(
        tx,
        0,
        scriptPubKey, // scripts
        VALUES, ARRAY_SIZE(VALUES),
        NULL,  0, // tapleaf
        0x00, // key version
        WALLY_NO_CODESEPARATOR, // codesep position
        NULL, 0, // annex
        WALLY_SIGHASH_ALL,
        0,
        sigHash, sizeof(sigHash)
    );
    if (rc != WALLY_OK) {
        printf("error: wally_tx_get_btc_taproot_signature_hash fail: %d\n", rc);
        return;
    }
    printf("sigHash: ");
    dump(sigHash, sizeof(sigHash));
    if (memcmp(sigHash, SIGHASH, sizeof(sigHash)) != 0) {
        printf("error: sigHash not same\n");
    }

    uint8_t sig[EC_SIGNATURE_LEN + 1];
    rc = wally_ec_sig_from_bytes(
        TWEAK_PRIVKEY, sizeof(TWEAK_PRIVKEY),
        sigHash, sizeof(sigHash),
        EC_FLAG_SCHNORR,
        sig, EC_SIGNATURE_LEN
    );
    if (rc != WALLY_OK) {
        printf("error: wally_ec_sig_from_bytes fail: %d\n", rc);
        return;
    }

    printf("sig: ");
    dump(sig, sizeof(sig));
    sig[EC_SIGNATURE_LEN] = 0x01; // SIGHASH_ALL
    if (memcmp(sig, SIG, sizeof(sig)) != 0) {
        printf("error: sig not same\n");
    }

    struct wally_tx_witness_stack *witness;
    rc = wally_witness_p2tr_from_sig(sig, sizeof(sig), &witness);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_p2tr_from_sig fail: %d\n", rc);
        return;
    }
    rc = wally_tx_set_input_witness(tx, 0, witness);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_set_input_witness fail: %d\n", rc);
        return;
    }
    wally_map_free(scriptPubKey);
#endif

    uint8_t txData[1024];
    size_t txLen = 0;
    rc = wally_tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS, txData, sizeof(txData), &txLen);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_to_bytes fail: %d\n", rc);
        return;
    }
    printf("hex: ");
    dump(txData, txLen);

    if (txLen != sizeof(TXDATA)) {
        printf("error: length not match: %lu(expect %lu)\n", txLen, sizeof(TXDATA));
    } else if (memcmp(txData, TXDATA, txLen) != 0) {
        printf("error: txData not same\n");
    }

    wally_tx_free(tx);
}

int main(int argc, char *argv[])
{
    int rc;

    if (argc != 2) {
        help(argv[0]);
        return 1;
    }

    if (argv[1][1] != '\0') {
        help(argv[0]);
        return 1;
    }
    if (argv[1][0] == '1') {
        address();
    } else if (argv[1][0] == '2') {
        spent();
    } else {
        help(argv[0]);
        return 1;
    }

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        printf("error: wally_init fail: %d\n", rc);
        return 1;
    }

    rc = wally_cleanup(0);
    if (rc != WALLY_OK) {
        printf("error: wally_cleanup fail: %d\n", rc);
        return 1;
    }
    return 0;
}
