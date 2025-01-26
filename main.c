#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwally-core/include/wally_core.h"
#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_script.h"

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-1-key-path-spend
//      private key:   55d7c5a9ce3d2b15a62434d01205f3e59077d51316f5c20628b3a4b8b2a76f4c
//      public key:    924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329
//      tweak:         8dc8b9030225e044083511759b58328b46dffcc78b920b4b97169f9d7b43d3b5
//      tweak pubkey:  0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
//      tweak privkey: 37f0f35933e8b52e6210dca589523ea5b66827b4749c49456e62fae4c89c6469
//      script pubkey: 51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
//      sighash:       a7b390196945d71549a2454f0185ece1b47c56873cf41789d78926852c355132
static const uint8_t internalPrivKey[] = {
    0x55, 0xd7, 0xc5, 0xa9, 0xce, 0x3d, 0x2b, 0x15,
    0xa6, 0x24, 0x34, 0xd0, 0x12, 0x05, 0xf3, 0xe5,
    0x90, 0x77, 0xd5, 0x13, 0x16, 0xf5, 0xc2, 0x06,
    0x28, 0xb3, 0xa4, 0xb8, 0xb2, 0xa7, 0x6f, 0x4c,
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
    rc = wally_ec_public_key_from_private_key(internalPrivKey, EC_PRIVATE_KEY_LEN, internalPubKey, sizeof(internalPubKey));
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

    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN];
    rc = wally_ec_private_key_bip341_tweak(internalPrivKey, sizeof(internalPrivKey), NULL, 0, 0, tweakPrivKey, sizeof(tweakPrivKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_private_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    printf("tweak privkey:   ");
    dump(tweakPrivKey, sizeof(tweakPrivKey));

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
