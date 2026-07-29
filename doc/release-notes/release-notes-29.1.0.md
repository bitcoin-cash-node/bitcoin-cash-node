# Release Notes for Bitcoin Cash Node version 29.1.0

Bitcoin Cash Node version 29.1.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This release of Bitcoin Cash Node (BCHN) is a minor release. Most notably, it offers RPC improvements as well as
performance optimizations.

## Usage recommendations

Users who are running v29.0.0 or older are encouraged to upgrade to v29.1.0.

## Network changes

None

## Added functionality

- A new `-rpcwaittimeout` argument to `bitcoin-cli` sets the timeout in seconds to use with `-rpcwait`. If the timeout
  expires, `bitcoin-cli` will report a failure.

## Deprecated functionality

None

## Modified functionality

- The `createwallet` RPC can now create encrypted wallets if a non-empty passphrase is specified.
- The default values for -rpcthreads and -rpcworkqueue have been increased from
  4 to 16, and 16 to 64 respectively. The original defaults were set in
  2013/2015 and are now unreasonably low even for low spec machines.
- The  `getmempoolinfo` RPC results now contain a new additional key, `total_fee`, which is the sum of all fees paid by
  all transactions currently in the mempool, in BCH.
- The `testmempoolaccept` RPC now returns more information in its JSON object results. For more information see the
  RPC help for `testmempoolaccept`.
- The `gettxout` RPC has a new 4th argument, `patterns` (boolean, optional) which, if set to `true`, will cause the RPC
  results to also contain an additional `"byteCodePatterns"` JSON object. See the JSON-RPC help for `gettxout` for more
  information.
- The `getnetworkinfo`, `getpeerinfo`, and `getnodeaddresses` RPC methods now return additional new keys which
  contain human-readable network service flags.
- The `getnodeaddresses` RPC now returns a "network" field indicating the network type (ipv4, ipv6, or onion) for each
  address.
- The `getrpcinfo` RPC results now contains an additional key, `logpath`, which is the file system path to the debug.log
  file for the bitcoind instance.
- The `getchaintxstats` RPC now returns the additional key of `window_final_block_height`.

## Removed functionality

None

## New RPC methods

- Two new REST API endpoints have been introduced: `/rest/spenttxouts/<BLOCK-HASH>.<bin|hex|json>` and
  `/rest/spenttxouts/withpatterns/<BLOCK-HASH>.<bin|hex|json>`. They can be used for efficiently fetching spent
  transaction outputs using the block's undo data.

## User interface changes

None

## Regressions

Bitcoin Cash Node 29.1.0 does not introduce any known regressions as compared to 29.0.0.

## Limitations

The following are limitations in this release of which users should be aware:

1. CashToken support is low-level at this stage. The wallet application does
   not yet keep track of the user's tokens.
   Tokens are only manageable via RPC commands currently.
   They only persist through the UTXO database and block database at this
   point.
   There are existing RPC commands to list and filter for tokens in the UTXO set.
   RPC raw transaction handling commands have been extended to allow creation
   (and sending) of token transactions.
   Interested users are advised to consult the functional test in
   `test/functional/bchn-rpc-tokens.py` for examples on token transaction
   construction and listing.
   Future releases will aim to extend the RPC API with more convenient
   ways to create and spend tokens, as well as upgrading the wallet storage
   and indexing subsystems to persistently store data about tokens of interest
   to the user. Later we expect to add GUI wallet management of Cash Tokens.

2. Transactions with SIGHASH_UTXO are not covered by DSProofs at present.

3. P2SH-32 is not used by default in the wallet (regular P2SH-20 remains
   the default wherever P2SH is treated).

4. The markup of Double Spend Proof events in the wallet does not survive
   a restart of the wallet, as the information is not persisted to the
   wallet.

5. The ABLA algorithm for BCH is currently temporarily set to cap the max block
   size at 2GB. This is due to limitations in the p2p protocol (as well as the
   block data file format in BCHN).


## Known Issues

Some issues could not be closed in time for release, but we are tracking all
of them on our GitLab repository.

- The minimum macOS version is 14.5 (Sonoma).
  Earlier macOS versions are no longer supported.

- Windows users are recommended not to run multiple instances of bitcoin-qt
  or bitcoind on the same machine if the wallet feature is enabled.
  There is risk of data corruption if instances are configured to use the same
  wallet folder.

- Some users have encountered unit tests failures when running in WSL
  environments (e.g. WSL/Ubuntu).  At this time, WSL is not considered a
  supported environment for the software. This may change in future.
  It has been reported that using WSL2 improves the issue.

- `doc/dependencies.md` needs revision (Issue #65).

- For users running from sources built with BerkeleyDB releases newer than
  the 5.3 which is used in this release, please take into consideration
  the database format compatibility issues described in Issue #34.
  When building from source it is recommended to use BerkeleyDB 5.3 as this
  avoids wallet database incompatibility issues with the official release.

- The `test_bitcoin-qt` test executable fails on Linux Mint 20
  (see Issue #144). This does not otherwise appear to impact the functioning
  of the BCHN software on that platform.

- With a certain combination of build flags that included disabling
  the QR code library, a build failure was observed where an erroneous
  linking against the QR code library (not present) was attempted (Issue #138).

- Possible out-of-memory error when starting bitcoind with high excessiveblocksize
  value (Issue #156)

- A problem was observed on scalenet where nodes would sometimes hang for
  around 10 minutes, accepting RPC connections but not responding to them
  (see #210).

- Startup and shutdown time of nodes on scalenet can be long (see Issue #313).

- Race condition in one of the `p2p_invalid_messages.py` tests (see Issue #409).

- Occasional failure in bchn-txbroadcastinterval.py (see Issue #403).

- wallet_keypool.py test failure when run as part of suite on certain many-core
  platforms (see Issue #380).

- Spurious 'insufficient funds' failure during p2p_stresstest.py benchmark
  (see Issue #377).

- If compiling from source, secp256k1 now no longer works with latest openssl3.x series.
  There are workarounds (see Issue #364).

- Spurious `AssertionError: Mempool sync timed out` in several tests
  (see Issue #357).

- For some platforms, there may be a need to install additional libraries
  in order to build from source (see Issue #431 and discussion in MR 1523).

- More TorV3 static seeds may be needed to get `-onlynet=onion` working
  (see Issue #429).

- Memory usage can be very high if repeatedly doing RPC `getblock` with
  verbose=2 on a hash of known big blocks (see Issue #466).

- A GUI crash failure was observed when attempting to encrypt a large imported
  wallet (see Issue #490).

- The 'wallet_multiwallet' functional test fails on latest Arch Linux due to
  a change in semantics in a dependency (see Issue #505). This is not
  expected to impact functionality otherwise, only a particular edge case
  of the test.

- The 'p2p_extversion' functional test is sensitive to timing issues when
  run at high load (see Issue #501).

---

## Changes since Bitcoin Cash Node 29.0.0

### New documents

None

### Removed documents

None

### Notable commits grouped by functionality

#### Security or consensus relevant fixes

- 631f7f5b11b6e19a2a527d5fb1f2d8f60be4016c Post 2026 upgrade: Add checkpoints, switch to height-based activation, etc
- 0a9295a069b5c8a69750f1a6efb4121949b957e6 Update checkpoints for mainnet, testnet3, testnet4, and chipnet
- 5b3d88a96bad766a19c2eaf28e129f7878b90b6b [qa] Update "assume valid" and "minimum chain work" for v29.1.0 release
- 31c715ed160d25031774103638a29333e7c2a1ea Update chainTxData for main, test3, test4, and chipnet for v29.1.0

#### Interfaces / RPC

- 4bd0c3e678e44cea1c7bdbb5549863deb70cb510 backport: rpc: createwallet encryption
- 80b76bcb7a6bee85fa8c01d2d0799d0a5b041714 backport: rpc: Allow shutdown while in generateblocks
- be7b447b23b677b00d35199f4212d9038d9f1573 Allow createwallet to take empty passwords to make unencrypted wallets
- 539f6b50d17b2ec18f1694d64b1dc5fad842adb1 rpc: Increase the defaults for -rpcthreads and -rpcworkqueue
- f786be6df383d971cdba6230f4119aab8cd752e2 rpc: Add new key, "total_fee" to results for getmempoolinfo
- 3025b7bfda56e1c716f8aed7de27decaafeb0c19 Extend `testmempoolaccept` RPC response data
- 80a99c96d4dec25b128a9285d9dd1a6f610e8cbd RPC: Modifiy `gettxout` to add a 4th optional `patterns` argument
- 4f66e4f7da94ec34125bd2fdbc5dbeaeed292bf2 backport: rpc/net: decode the services flags in a new entry
- e07eca0f2abec1e54b9d51181410ba605a6f29fc Updated RPC for `getnodeaddresses` to also add a `servicesnames` field.
- f38556f90cb3310db94390a627395e34c74bc2b9 [backport] bitcoin-cli: Add a -rpcwaittimeout parameter to limit time spent waiting
- f27e9932a8c4a15dae51c289e376d85001a9476e [backport] RPC: Add username and ip logging for RPC method requests
- b1ac867a05a8efaaebc71552101d2a21862c0e84 [backport] rest: fetch spent transaction outputs by blockhash
- 38a5b3f72edf78ea1b9d5e5416891bea819688cb backport: rpc: add `network` field to `getnodeaddresses`
- 90ad8fd5df009c3a74ec1bdc48f42a0983e83a49 backport: rpc: add getorphantxs
- f3f726bad230cf735d42e493643ff42d28d3e11e backport: rpc: Adding a 'logpath' entry to `getrpcinfo`
- 31c3c6a796aa70da4231a6b63f72aefb8c2ac7f1 backport: rpc: Add logpath description to getrpcinfo
- 9906cdb7bab742a98e73dfc1a2b25133c17e7331 Add window final block height to getchaintxstats

#### Features in internal development: support for UTXO commitments

None

### Data directory changes

None

#### Performance optimizations

- 4878ac661226bcedf54dbeb035c7c0376d5029e0 Optimize `CScript` class to allow for pushing bytes without extra allocations
- 7966b2193e80ddf9667a9970b3fc5617a4868d2a Optimize rest.cpp slightly to avoid excessive copying & allocations
- e26c41560cdccc2a1c77628ce3b27e6d001c509d When inserting a new CBlockIndex, avoid double hash table lookups
- 3192dbc08a0b842ead052b656a3e7a2659402ccc Add `hwaccel::IsAllZeros`
- 6fc06434656a383aeca4b192df8103e49e1c7141 Leverage hwaccel::IsAllZeros and use it in base_blob::IsNull()
- 60fffbbcd278d5ff9bb8eb02fafeeda614cba747 Use hwaccel::IsAllZeros in interpreter.cpp CastToBool

#### GUI

- 3fa555c8f88e864a2deceefd87b3cbfdbff1a6fa [backport] macOS: disable AppNap during sync
- 6e20cf20a7cd7889c5658d741c9376f43bfef3c9 [backport] gui: Add close window shortcut
- 3290c1c0e047f31a88b54bd97c3b7d299828869b [backport] qt: Add privacy feature to Overview page

#### Code quality

- 033d22a86f86b49648cdac39fe065583ee80318a backport: replace wallet raw pointers with references
- 1bde9177024ec112b9b49c48f5c5c2e8902d7378 Move global variable `peerLogic` into the `NodeContext` struct
- dcd1e1042f2d816353a9e1419afab5444785231f Move global `CScheduler` into `NodeContext` + small refactor
- 799270fb90504ad05b64b78ed19a246458b4987f Logger: Add thread-safety macros and some other small fixups
- cd49b9bac83801d47cd3f086d56c17a6ab8e0289 backport: Move Tx Orphan code to a separate file and class
- 0a014041977081df8fee457eb42d4765cdb8d998 net_processing: Refactor static functions and some static data to be class members
- 12aa6513666750ee00ac841e42b1f3f236b9681e [backport] gui: Make RPCConsole::TabTypes an enum class
- 505a8879abc97efb4d6375282cadefb24b98335e script interpreter: Add `StackItem` abstraction and use it
- 0240bfbe00702acf881302ccbc3b67b4cd0e7a34 interpreter class StackItem: invalidate caches on move + add unit tests

#### Documentation updates

- 14558ecc674c2a0699ec4ea5081124ae8ab71318 Fix broken documentation reference link to code
- 0ca8f088beda6e62ca3ab7f840f4212fb3e1e34e Remove merge artifact
- 4ddcf2be5c36cda1cb164b2e57cc4fa207792c07 Docs: Add missing vin coinbase for getrawtransaction
- 5320305ec75ac4b58bcefa0171fa3c9a550eccf9 [doc] Some small fixes to Docker Gitian guide and docs contents menu styling
- 303828b405acf69b8560cb993ba945ce34155fce rpc: sendrawtransaction unconditionality/privacy note
- 2442ef23f633c78f109b0ea05624f2832d5015b1 [doc] Fix fence rendering and log package versions
- 66187e4d64cf76e75020759a60625fe6680e5a86 Update doc/REST-interface.md to talk about the /withpatterns/ endpoints
- f867a6a5cd9512015ddf9393889e2a26fe8d2508 Updated release-nodes.md and REST-interface.md
- b45c96c62800f1dc6fecf509545abd4fca852a1d Add link to source code
- 08a2e6e0c62f3af7cd562d0c1ff47d5223c60fd8 Add missing chipnet section in example config
- 5ea50e26ec1ece5860232017784da9ae3b7b90ee Add missing rpcworkqueue and rpcservertimeout configs to example file
- 82479539b1b31ed8dc560faf8c4fb8245617e0d7 Docs: Missing chipnet port mention

#### Build / general

- 05d177b4ab5b2a52a1227d3d25344dcbebc50835 Address CMP0167 CMake warning
- 151e79cb6e177070d80fc20afcf12f2ade5c7491 Further streamline gitian-build.py

#### Build / Linux

None

#### Build / Windows

None

#### Build / MacOSX

- 1077e7d49a7ea7e1bcb2c9abc16f2a1c77545d04 Add ARM64 (Apple Silicon) macOS support to depends build system & gitian
- 9603ac222bc445a11c4772586f16305ad1be4c72 Fix for gitian building for Darwin x86-64

#### Tests / test framework

- ac57147c1fb631846aa7a9c86cb42320e3129150 backport: test: servicesnames field in getpeerinfo and getnetworkinfo

#### Benchmarks

None

#### Seeds / seeder software

- a2c70c034ebd04645c01c7a7a48154c859c63bed [qa] Update mainnet static seeds in preparation for v29.1.0 release
- 29623a4f931e016883bbb9f050d22729fde42f2a [qa] Update all testnet static seeds in preparation for v29.1.0 release
- 882b2fd754e6698b2f45e7ce36994bb8e46b0a2c Add loping.net chipnet seeder

#### Maintainer tools

- d199144df07518a52cf0af8b3fd0438d3a29388e Fix abort-on-startup for bitcoind & bitcoin-qt debug builds
- 607e3951580552a0027fe35093b5815678c19558 contrib/devtools: add chaintxdata tool for generating ChainTxData from RPC

#### Infrastructure

None

#### Cleanup

- e9c9ce477fb73647376df4b3396d97ad12aa4e7e Fix issues when calling RegisterValidationInterface() after threads are started
- d200d7692cef5b0f5bff80485aba8caf3ce7a7e0 rpc: fix -rpcclienttimeout 0 option
- fa029cc4a1a1befe5d5b59a7aa22f77fa06a54c8 Electroncash.de is no more.
- c6ce3e64c350f133097297105b1d2e677e1d25e6 Remove script flags: SCRIPT_64_BIT_INTEGERS and SCRIPT_NATIVE_INTROSPECTION
- 742f0908bd4a72f4af126926be5eef42bc721aa8 backport: rpc: getorphantxs follow-up
- 08ff08ebb1e3d5e6b0c1ce4e4d1369c15e89e0d3 Fix rpc_rawtransaction.py
- 0a68f137700593d854ebdd5960e66fb4f02f0375 Fix formatting for getchaintxstats RPC help to not be 80-column
- 733abf66903f4c7ba4fc84a517dc6a7421d18270 Follow-up to MR 2080 -- don't hold locks when registering callbacks
- 9bfc0b8303b7a104bb88921f15feeb5ba572aa8b Pack of nits for script/ subdir
- 9d10a1ad747b67d36d4010f65c8d3fd8a7419274 Follow-up to recend SIMD work in `hwaccel::IsAllZeros`

#### Continuous Integration (GitLab CI)

- 0ad133d1ec5167544bc9fa0395f2eed5acdffae2 Install latest arcanist and use Python venv
- 4452e1a91f9e26445664cad5b82c0e373da04f7d Install scipy in the venv rather than system-wide

#### Compatibility

- 23b110628e913a61e1920fdbdddd588ef1cecbe1 [backport] qt: misc fixed for deprecation warnings
- 666739d06d92cfe581f4c2e34d69571cddd2bc00 [backport] qt: Remove `QApplication::globalStrut()` call
- 6343756878dda4ba717daee72825c584f3c13bb4 [backport] qt: Do not use `QKeyEvent` copy constructor
- 902c3a8ce6cdc344fff6f02bd0ec816f3fde4886 [backport] qt: Do not assume `qDBusRegisterMetaType` return type

#### Backports

- 033d22a86f86b49648cdac39fe065583ee80318a backport: replace wallet raw pointers with references
- 80b76bcb7a6bee85fa8c01d2d0799d0a5b041714 backport: rpc: Allow shutdown while in generateblocks
- 4bd0c3e678e44cea1c7bdbb5549863deb70cb510 backport: rpc: createwallet encryption
- be7b447b23b677b00d35199f4212d9038d9f1573 Allow createwallet to take empty passwords to make unencrypted wallets
- 539f6b50d17b2ec18f1694d64b1dc5fad842adb1 rpc: Increase the defaults for -rpcthreads and -rpcworkqueue
- f786be6df383d971cdba6230f4119aab8cd752e2 rpc: Add new key, "total_fee" to results for getmempoolinfo
- 3025b7bfda56e1c716f8aed7de27decaafeb0c19 Extend `testmempoolaccept` RPC response data
- 4f66e4f7da94ec34125bd2fdbc5dbeaeed292bf2 backport: rpc/net: decode the services flags in a new entry
- ac57147c1fb631846aa7a9c86cb42320e3129150 backport: test: servicesnames field in getpeerinfo and getnetworkinfo
- e07eca0f2abec1e54b9d51181410ba605a6f29fc Updated RPC for `getnodeaddresses` to also add a `servicesnames` field.
- 303828b405acf69b8560cb993ba945ce34155fce rpc: sendrawtransaction unconditionality/privacy note
- d200d7692cef5b0f5bff80485aba8caf3ce7a7e0 rpc: fix -rpcclienttimeout 0 option
- f38556f90cb3310db94390a627395e34c74bc2b9 [backport] bitcoin-cli: Add a -rpcwaittimeout parameter to limit time spent waiting
- f27e9932a8c4a15dae51c289e376d85001a9476e [backport] RPC: Add username and ip logging for RPC method requests
- b1ac867a05a8efaaebc71552101d2a21862c0e84 [backport] rest: fetch spent transaction outputs by blockhash
- 38a5b3f72edf78ea1b9d5e5416891bea819688cb backport: rpc: add `network` field to `getnodeaddresses`
- cd49b9bac83801d47cd3f086d56c17a6ab8e0289 backport: Move Tx Orphan code to a separate file and class
- 90ad8fd5df009c3a74ec1bdc48f42a0983e83a49 backport: rpc: add getorphantxs
- 742f0908bd4a72f4af126926be5eef42bc721aa8 backport: rpc: getorphantxs follow-up
- 08ff08ebb1e3d5e6b0c1ce4e4d1369c15e89e0d3 Fix rpc_rawtransaction.py
- f3f726bad230cf735d42e493643ff42d28d3e11e backport: rpc: Adding a 'logpath' entry to `getrpcinfo`
- 31c3c6a796aa70da4231a6b63f72aefb8c2ac7f1 backport: rpc: Add logpath description to getrpcinfo
- 9906cdb7bab742a98e73dfc1a2b25133c17e7331 Add window final block height to getchaintxstats
- 3fa555c8f88e864a2deceefd87b3cbfdbff1a6fa [backport] macOS: disable AppNap during sync
- 6e20cf20a7cd7889c5658d741c9376f43bfef3c9 [backport] gui: Add close window shortcut
- 12aa6513666750ee00ac841e42b1f3f236b9681e [backport] gui: Make RPCConsole::TabTypes an enum class
- 3290c1c0e047f31a88b54bd97c3b7d299828869b [backport] qt: Add privacy feature to Overview page
- 23b110628e913a61e1920fdbdddd588ef1cecbe1 [backport] qt: misc fixed for deprecation warnings
- 666739d06d92cfe581f4c2e34d69571cddd2bc00 [backport] qt: Remove `QApplication::globalStrut()` call
- 6343756878dda4ba717daee72825c584f3c13bb4 [backport] qt: Do not use `QKeyEvent` copy constructor
- 902c3a8ce6cdc344fff6f02bd0ec816f3fde4886 [backport] qt: Do not assume `qDBusRegisterMetaType` return type
