# Alpine build guide

Instructions for alpine 3.13

## Preparation

Minimal dependencies:

```sh
    apk add git boost-dev cmake libevent-dev openssl-dev build-base py-pip db-dev miniupnpc-dev libnatpmp-dev zeromq-dev help2man bash gmp-dev zlib
    pip install ninja
```

NOTE: Since alpine 3.12, `ninja` was replaced with `samurai`, which is not fully compatible with
the build system, hence the need for installing it with `pip`

You can do without the `db-dev`, `miniupnpc-dev`, `libnatpmp-dev`, `zeromq-dev`, and `help2man & bash` packages, then you
just need to respectively pass `-DBUILD_BITCOIN_WALLET=OFF`, `-DENABLE_UPNP=OFF`, `-DENABLE_NATPMP=OFF`,
`-DBUILD_BITCOIN_ZMQ=OFF`, or `-DENABLE_MAN=OFF` on the `cmake` command line.

If you want to build the GUI client `bitcoin-qt` Qt 5 is necessary.
To build with Qt 5 you need the following packages installed:

```sh
apk add qt5-qtbase qt5-qttools-dev  libqrencode-dev
```

You can do without the `libqrencode-dev` package, just pass `-DENABLE_QRCODE=OFF` on
the `cmake` command line.

## Building

Once you have installed the required dependencies (see sections above), you can
build Bitcoin Cash Node as such:

First fetch the code (if you haven't done so already).

```sh
git clone https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node.git
```

Change to the BCN directory, make `build` dir, and change to that directory

```sh
cd bitcoin-cash-node/
mkdir build
cd build
```

Next you need to choose between building just the node, the node with wallet support,
or the node and the QT client.

**Choose one:**

```sh
# to build just the node, no wallet functionality, choose this:
cmake -GNinja .. -DBUILD_BITCOIN_WALLET=OFF -DBUILD_BITCOIN_QT=OFF
```

```sh
# to build the node, with wallet functionality, but without GUI, choose this:
cmake -GNinja .. -DBUILD_BITCOIN_QT=OFF
```

```sh
# to build node and QT GUI client, choose this:
cmake -GNinja ..
```

Next, finish the build

```sh
ninja
```

You will find the `bitcoind`, `bitcoin-cli`, `bitcoin-tx` (and optionally `bitcoin-qt`)
binaries in `/build/src/(qt)`.

Optionally, run the tests

NOTE: As alpine is based on `musl` which doesn't have locales, in order to run tests
one must follow an extra [setup](https://github.com/gliderlabs/docker-alpine/issues/144#issuecomment-505356435)

```sh
export MUSL_LOCPATH=/usr/local/share/i18n/locales/musl
apk add --update git cmake make musl-dev gcc gettext-dev libintl
cd /tmp && git clone https://gitlab.com/rilian-la-te/musl-locales
cd /tmp/musl-locales && cmake . && make && make install && cd .. && rm -r musl-locales
# Go back to bitcoin-cash-node/build directory
```

```sh
# Test dependencies
apk add bash grep py-scipy
ninja check
```

After a successful test you can install the newly built binaries to your `bin` directory.
Note that this will probably overwrite any previous version installed, including
binaries from different sources.

```sh
sudo ninja install #optional
```
