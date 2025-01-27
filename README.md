# key path

* Test data: [Toproot - learn me a bitcoin](https://learnmeabitcoin.com/technical/upgrades/taproot/#example-1-key-path-spend)

## prepare

I use system installed `libsecp256k1`(built with `--enable-module-recovery`).  
(Maybe "libsecp256k1-zkp" works fine too).

```bash
mkdir -p libs/libwally-core

git clone https://github.com/ElementsProject/libwally-core.git
cd libwally-core
git checkout -b v1.3.1 release_1.3.1

./tools/autogen.sh
./configure --prefix `pwd`/../libs/libwally-core --enable-minimal --disable-elements --enable-standard-secp --with-system-secp256k1 --disable-shared
make
make install
```

## build

```bash
git clone https://github.com/hirokuma/c-keypath.git
cd c-keypath
make
```

## run

```console
$ ./tst 1
internal pubkey: 03924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329
tweak pubkey:    020f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
tweak privkey:   37f0f35933e8b52e6210dca589523ea5b66827b4749c49456e62fae4c89c6469
witness program: 51200f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
address: bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf
```

* [outpoint](https://mempool.space/ja/tx/a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec#vout=0)
* [spent tx](https://mempool.space/ja/tx/091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe#vin=0)

```console
$ ./tst 2
sigHash: a7b390196945d71549a2454f0185ece1b47c56873cf41789d78926852c355132
sig: b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae01
hex: 02000000000101ec9016580d98a93909faf9d2f431e74f781b438d81372bb6aab4db67725c11a70000000000ffffffff0110270000000000001600144e44ca792ce545acba99d41304460dd1f53be3840141b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae0100000000
```
