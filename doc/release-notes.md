# Release Notes for Bitcoin Cash Node version 29.1.1

Bitcoin Cash Node version 29.1.1 is now available from:

  <https://bitcoincashnode.org>

## Overview

This release of Bitcoin Cash Node (BCHN) is a patch release.

## Usage recommendations

Users who are running v29.1.0 or older are encouraged to upgrade to v29.1.1.

## Network changes

- Bitcoin Cash Node clients no longer advertise their P2P protocol user agent strings with the "(EB32.0)" suffix.
  This is because the "excessive block" concept has been removed from the codebase entirely (it was a holdover from
  pre-ABLA days). ABLA now manages all block size limit growth, based on demand, and so this user agent suffix is no
  longer needed.

## Added functionality

- A new CLI arg, `-signschnorr` (default: 1) has been added. It controls whether the node signs with Schnorr signatures
  or not. If disabled (by e.g.: `-signschnorr=0` and/or `-nosignschnorr`), the node reverts back to signing with ECDSA.

## Deprecated functionality

None

## Modified functionality

- The `scantxoutset` RPC adds a few new keys to its results:
  - `coinbase`, which is a boolean to indicate whether the UTXO is a coinbase tx output or not
  - `blockhash`, which is the block hash of the unspent transaction output
  - `confirmations`, which is the number of confirmations of the unspent transaction output when the scan was done
  - `height`, which is the blockchain tip height when the scan was done
  - `bestblock`, which is the blockchain tip hash against which the scan was done
- The `listbanned` RPC now returns two new numeric fields: `ban_duration` and `time_remaining`.
  Respectively, these new fields indicate the duration of a ban and the time remaining until a ban expires,
  both in seconds. Additionally, the `ban_created` field is repositioned to come before `banned_until`.
- The `gettransaction`, `listtransactions`, and `listsinceblock` RPCs now return an additional optional key,
  `blockheight`, which is the height of the block that contains the wallet transaction.
- The `-blockmaxsize` argument (used for mining) now has slightly changed behavior. If it is set to a value larger
  than the consensus default block size (32000000 on mainnet), it will no longer error-out on startup. Instead, the cap
  used for mining will be the lesser of: the current blocksize limit and this specified value.
- The `savemempool` RPC command now returns the full path and name of the file to which the mempool was saved.
- The `listunspent` RPC now has a new argument `include_immature_coinbase` to include coinbase UTXOs that don't meet the
  minimum spendability depth requirement (which before were silently skipped).
- The node RPC, node wallet, and the `bitcoin-tx` tool now always sign all transactions with Schnorr signatures. To
  disable this behavior, and go back to ECDSA-only signing, restart the node and/or `bitcoin-tx` with `-signschnorr=0`
  (or `-nosignschnorr`).
  - Compatibility note: This means that all node-signed transactions now have a different shape by default, so any
    external tooling depending on e.g. exact output from `signrawtransactionwithwallet` might need to be updated if they
    depend on assumptions related to ECDSA signatures that don't hold for Schnorr signatures. In that hopefully unlikely
    case, the node must be started with `-nosignschnorr` to revert to previous behavior (until the tooling itself is
    updated).
  - The RPCs `finalizepsbt`, `walletprocesspsbt` and `combinerawtransaction` now may return a JSON-RPC error code -25
    should they be tasked to sign or combine a multisig transaction that ends up having a mixture of ECDSA and Schnorr
    signatures. Mixing Schnorr and ECDSA signatures when spending a multisig input is forbidden by consensus. If you use
    the node wallet to sign or prepare multisig transactions from external signers, always be sure that all cosigners are
    either all signing with Schnorr (`-signschnorr=1`) or with ECDSA (`-signschnorr=0`).
- The `getpeerinfo` RPC now returns a `connection_type` field. This indicates the type of connection established with
  the peer. It will return one of five options. For more information, see the JSON-RPC help for `getpeerinfo`.
- A new optional 5th argument `include_change` was added to the `listsinceblock` RPC method.
- A new optional 6th argument `label` was added to the `listsinceblock` RPC method which allows fetching wallet
  transactions that have the specified label.

## Removed functionality

- The `-excessiveblocksize` argument has been removed. It was previously used to signal support for larger blocks than
  the default. However, since 2024, ABLA has activated (adaptive block-size limit algorithm), thus this argument is no
  longer necessary. Block size limits grow with demand as part of consensus, so this argument isn't helpful anymore.
  - Correspondingly, the RPC method `getexcessiveblock` has been removed.
  - Additonally, the user agent string for the P2P protocol no longer appends the "(EBnn.n)" e.g. "(EB32.0)" suffix.

Upgrade note: users with `excessiveblocksize=X` set in bitcoin.conf (or passed via CLI wrappers/systemd units) must
remove that setting before upgrading, otherwise bitcoind will refuse to start with
`Error reading configuration file: Invalid configuration value excessiveblocksize`.

## New RPC methods

- A new REST endpoint has been introduced: `/rest/blockhashbyheight/<HEIGHT>.<bin|hex|json>`, which can be used to
  retrieve the block hash of a block in the active chain, given a block height.

## User interface changes

None

## Regressions

Bitcoin Cash Node 29.1.1 does not introduce any known regressions as compared to 29.1.0.

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

## Changes since Bitcoin Cash Node 29.1.0

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
