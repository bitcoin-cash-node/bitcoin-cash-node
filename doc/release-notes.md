# Release Notes for Bitcoin Cash Node version 29.0.1

Bitcoin Cash Node version 29.0.1 is now available from:

  <https://bitcoincashnode.org>

## Overview

This release of Bitcoin Cash Node (BCHN) is a patch release.

## Usage recommendations

Users who are running v29.0.0 or older are encouraged to upgrade to v29.0.1.

## Network changes

None

## Added functionality

None

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

## Removed functionality

None

## New RPC methods

None

## User interface changes

None

## Regressions

Bitcoin Cash Node 29.0.1 does not introduce any known regressions as compared to 29.0.0.

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

None

#### Interfaces / RPC

None

#### Features in internal development: support for UTXO commitments

None

### Data directory changes

None

#### Performance optimizations

None

#### GUI

None

#### Code quality

None

#### Documentation updates

None

#### Build / general

None

#### Build / Linux

None

#### Build / Windows

None

#### Build / MacOSX

None

#### Tests / test framework

None

#### Benchmarks

None

#### Seeds / seeder software

None

#### Maintainer tools

None

#### Infrastructure

None

#### Cleanup

None

#### Continuous Integration (GitLab CI)

None

#### Compatibility

None

#### Backports

None
