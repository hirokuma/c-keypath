# key path

## prepare

use system installed `libsecp256k1`(built with `--enable-module-recovery`).

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
./tst 1
```