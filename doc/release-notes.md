# Release Notes for Bitcoin Cash Node version 29.2.0

Bitcoin Cash Node version 29.2.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This release of Bitcoin Cash Node (BCHN) is a minor release. It contains several corrections and improvements, most
notably, the node now natively signs transactions using Schnorr signatures by default, to align better with other
software in the space such as Electron Cash, Selene wallet, etc, thus increasing privacy. Many RPCs were updated and/or
added to maintain compatibility with other software in the Bitcoin space. Additionally, many internal optimizations were
made to improve node performance and optimize memory usage in certain use cases.

## Usage recommendations

Users who are running v29.1.0 or older are strongly encouraged to upgrade to v29.2.0.

## Upgrade notes

- The `-excessiveblocksize=` conf argument has been removed (see "Removed functionality" below). Users with
  `excessiveblocksize=X` set in bitcoin.conf (or passed via CLI wrappers/systemd units) must remove that setting before
  upgrading, otherwise bitcoind will refuse to start with
  `Error reading configuration file: Invalid configuration value excessiveblocksize`.
- The node now signs all transactions with Schnorr signatures by default. Operators that depend on previous behavior
  should specify `-signschnorr=0`.

## Network changes

- Bitcoin Cash Node clients no longer advertise their P2P protocol user agent strings with the "(EB32.0)" suffix.
  This is because the "excessive block" concept has been removed from the codebase entirely (it was a holdover from
  pre-ABLA days). ABLA now manages all block size limit growth, based on demand, and so this user agent suffix is no
  longer needed.

## Added functionality

- A new CLI arg, `-signschnorr` (default: 1) has been added. It controls whether the node signs with Schnorr signatures
  or not. If disabled (by e.g.: `-signschnorr=0` and/or `-nosignschnorr`), the node reverts back to signing with ECDSA.
- Added the ability to restrict which RPC methods may be accessed on a per-user basis via the new CLI & conf arg
  `-rpcwhitelist`. For more information see the built-in help for this option (`bitcoind --help`). Note that
  cookie-authenticated clients such as some configurations of `bitcoin-cli` authenticate as the user `__cookie__`; when
  using -rpcwhitelist with such configurations, you must either add an `-rpcwhitelist` entry for `__cookie__` or set
  `-rpcwhitelistdefault=0`.

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

## New RPC methods

- A new REST endpoint has been introduced: `/rest/blockhashbyheight/<HEIGHT>.<bin|hex|json>`, which can be used to
  retrieve the block hash of a block in the active chain, given a block height.
- `simulaterawtransaction` - Calculate the balance change resulting in the signing and broadcasting of the given
   transaction(s). For more information see the RPC built-in help, e.g.: `bitcoin-cli help`.

## User interface changes

None

## Regressions

Bitcoin Cash Node 29.2.0 does not introduce any known regressions as compared to 29.1.0.

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

- 035fd2ade0ebc561cb7c26ff2baf96dd81134238 Added Schnorr-signing capability to node, made it on-by-default
- d8e3550ea58abccf060c33af3cecb6334aebb1e9 Sanitize JSON-RPC method names coming from network
- d408e289ed87326c9bb82451b716e68127fee079 Update checkpoints for mainnet, testnet3, testnet4, and chipnet
- 1124d0a3dc4bd8cd3236512fcd8a727c52142824 [qa] Update "assume valid" and "minimum chain work" for v29.2.0 release
- b294ba6dc909786be6c4e4ee087821e77993e469 Update chainTxData for main, test3, test4, and chipnet for v29.2.0

#### Interfaces / RPC

- 56831de55144142219820a37ee291378b4a50d73 [backport] rest: add blockhashbyheight call, fetch blockhash by height
- 19fbab9049eb9760650ad92ca324aff6cf26173b backport: rpc: Return coinbase flag in scantxoutset
- 98c57cd21c77f4e59608d619505b6a2b610757cf rpc: Update scantxoutset, add 4 new fields
- cacc51ed4925fddae00d0b4d01f8bd4860a3b938 backport: rpc: add additional ban time fields to listbanned
- b45bd092e89039865af3d8b08dec4424b1760883 [backport] rpc: Expose block height of wallet transactions
- 429c46048574085199986fbc4cb4c670a89596e0 backport: rpc: add return message to `savemempool` RPC
- d7e06bd6467a3ef59913e8151694c25a7d040e1b [backport] rpc: listunspent, add "include immature coinbase" flag
- 87413623e25853811f768e31e074cdfd14e2b524 [backport] RPC: Add connection type to getpeerinfo, improve logs
- 4bb7bc3d2da6a39c04bfcdde6ddd34e28c9b0648 [backport] rpc: add an include_change parameter to listsinceblock
- 26b482364d929d54f285536d34e6da1242e81f71 [backport] wallet, rpc: add label argument to listsinceblock
- 37eaf3a1d5b7537119159af4e0d434f6692e097f [backport] Add RPC Whitelist Feature
- 7f97ca37086698d9b920f9f1fd1781adcbfc19ca rpc/wallet: add simulaterawtransaction RPC

#### Features in internal development: support for UTXO commitments

None

### Data directory changes

None

#### Performance optimizations

- cc042194f0700695446b445a6c878f8dc43f2d09 Performance nit: Properly call .reserve() in DisconnectedBlockTransactions::addNoLimit
- 64fb9e7facfdc79b815d85f32bcfaa9f5591efae Small performance tweak to FastBigNum class + add a unit test
- 64579c0f832a17a8540f564826fea3c04f797a6f Performance nit for ABLA: pass the blockSize (if known) to TipChanged()
- 45186d31359e4285b4716d481bb7565cf70161b6 Reduce memory usage of CBlockIndex by ~48-176 bytes (depending on platform)
- 374b05faf1cbfd932e23c2a9bae8dc323b8fd0d0 Avoid redundant rehashing of the block header in ProcessGetBlockData
- a5459c7c0b977cce93aad4df00c6fa9045161fda BlockStorage: Avoid calling `GetSerialSize()` twice when saving blocks
- fd5ac52448946405c19b3d89ea581d6e3d1fc5ad p2p: Use the cached compact block
- cf989d4b4fb6f243520de7bdac33c1cbbde7f2d3 net: Stream larger block files directly from disk, rather than reading into RAM
- 4bf64fbf98ef56cd2ce1948c4aff2f5679fc7c1a p2p: Serve getblocktxn for the tip only
- 075cdd5e4887b2cbd41d89d56411fa7cdf5e8d2d p2p: Batch dsproof getdata requests

#### GUI

None

#### Code quality

- 1171d3b42b752fdcb09bb6a8c64d94280fec70e5 [backport] net: Cleanup logic around connection types
- a583d1918b34a14a35efa67dc6f2d75d572d13f3 [backport] net: Cleanup connection types - followups
- c6b8e0e9c2a618e067028c911149712fdb62ef3e Avoid magic number in cashaddr
- 1bd034d81acbd46f8cbe6cab5a6c60116e2e1aad Refactor: Move some compactblk related globals into class PeerLogicValidation
- 34bf4e706ec64e593745d3647dd5b6409f0e4596 dsproof: Refine the logic used to check dsproof sanity
- de88d2580f1aeb4881b2c9e90928fd84eb076bc8 Fix compiler warning in wallet/wallet.h
- 327741bbc3b151e9a2e8620d4e812123441d2dd7 Pruning: Catch potential exception that may be thrown by `fs::remove`
- 6fdea949c4f437d6e1898a9b8500349270a12e4c Make CConnman::SocketSendData return uint64_t not size_t
- 8810f48075f5aa354a6f17b85121794296395972 Pack of nits and other minor fixups to the DSProof subsystem
- 05610345b15d9fe058189076a710546b2e16a600 net: Harden serialized data source reads
- 45691f26dfc69d3369d6c12c6d81536641b0051a RPC: Refactor results & help for `getblock` and `getblockheader`
- b729f85caf28241a3bd2e529ca8f5317f7c91dc4 Fix compile warning in src/net_datasource.cpp

#### Documentation updates

- 08faecdad026a9dcef21877b2c0d3e98d173939f super minor doc nit
- c58839ce8f13fe515e1aa1e45c99b2c9b8a324ec Update release notes as a follow-up to 2127
- c50af2f6be4cf2825ae83184c28d63cff857a725 Clarified wording about cookie behavior for rpcwhitelist in help + release-notes
- 568ebab4815dd5020626d8c6fdc4c78268868bd9 Updated release-notes.md to mention the new `simulaterawtransaction` RPC method
- e0dd600d9e73bb78f488822b9aefa57125061c22 Adjuest help text
- 440b450db105883b9d5d3528b613bb0618478389 Adjusted help text as per review suggestion

#### Build / general

- 1a78f0dc796462838b01bd1494819121b94c1067 Fix and tidy the FindAtomic CMake module
- 365c10799083f0d7982a80e7957f6991705399c7 Bump version to 29.2.0

#### Build / Linux

None

#### Build / Windows

None

#### Build / MacOSX

- f2cf3d3d5062fc097218ed69e66c86656d54ef45 osx build: Update generated Info.plist
- 5ddbbd8231b7fa5d63891e956827cc413aeb757c gitian: Don't strip OSX binaries + get rid of .app tarball + rename CLI program tarball

#### Tests / test framework

- 6b9d849161f1054cd108707e3f7e8bff73eeda8c unit tests: Add extra "cached MTP value" check to CheckBlockIndex
- 3c605f534b59f312de8bfdcb73838cd396978a8b Fix a compiler warning in test/script_standard_tests.cpp
- a979cee33e616d03e66b4ad411c08c402bd7b99e Tests for the packed abla::State in CBlockIndex
- cf1c320e1e522465460ed2ef26a9c8f9265b5ca7 [backport] test: Add test for rpc_whitelist
- 12dfc36e19d86237045acb88b1144b588e0fc025 Strengthen functional test slightly

#### Benchmarks

None

#### Seeds / seeder software

- 9b0cd7683a2d319b615a75877f536d41845e8986 seeder: Sanitize string
- 2f611e536a0dbd527d8de7e8e36d0d1604056c03 [qa] Update mainnet static seeds in preparation for v29.2.0 release

#### Maintainer tools

- c767fda4f3d1c22c8a821f235e3635b04f072617 Fix arcanist

#### Infrastructure

None

#### Cleanup

- ad7e9ac8f1372e97ec315dc09bc4e4225ad6ed9d rest: Fix /headers/ endpoint error message when missing/invalid format requested
- 2cb84ecef6f227386a7ac336d44896e5a45c690c Minor Fix: Correct UniValue object `.reserve()` in `rpc/net.cpp`
- c320003786d6b0473d11a7abbfe139a04cede88d [qa] Bump version to 29.1.1, rotate release notes
- 5c02f1801327bd92794e0bddeb31396f1c9cafe6 Remove the `-excessiveblocksize` arg, get rid of "EB32.0" string in user agent
- bc8b1f2fb10ebe9dd8239abe3cbc29328275b0b1 Minor nit in dsproof_validate.cpp: use canonical GetHashType() function
- 568c5d1b2c971145549d92d79c3fe18736ee2a17 Some follow-ups to MR 2078
- 90e3ade8f8213771e44e5ad036d29c10c1c6fc56 Fix to use LabelFromValue plus other nits from review
- 93df00dadd1fb854ad3fc4dbcb0394428a39a4e5 Added mention of the new `-rpcwhitelist` option to release-notes.md
- 5509daf0de2d5b72464d5f0c005a6395f5e74f65 Added a note about cookie auth using user __cookie__ for rpc whitelist
- 3217f59a9753669d8e0ab47aa4b3d8dfd313e83a Handle remaining nits/review concerns

#### Continuous Integration (GitLab CI)

None

#### Compatibility

None

#### Backports

- 56831de55144142219820a37ee291378b4a50d73 [backport] rest: add blockhashbyheight call, fetch blockhash by height
- 19fbab9049eb9760650ad92ca324aff6cf26173b backport: rpc: Return coinbase flag in scantxoutset
- 98c57cd21c77f4e59608d619505b6a2b610757cf rpc: Update scantxoutset, add 4 new fields
- cacc51ed4925fddae00d0b4d01f8bd4860a3b938 backport: rpc: add additional ban time fields to listbanned
- b45bd092e89039865af3d8b08dec4424b1760883 [backport] rpc: Expose block height of wallet transactions
- 429c46048574085199986fbc4cb4c670a89596e0 backport: rpc: add return message to `savemempool` RPC
- d7e06bd6467a3ef59913e8151694c25a7d040e1b [backport] rpc: listunspent, add "include immature coinbase" flag
- 1171d3b42b752fdcb09bb6a8c64d94280fec70e5 [backport] net: Cleanup logic around connection types
- a583d1918b34a14a35efa67dc6f2d75d572d13f3 [backport] net: Cleanup connection types - followups
- c6b8e0e9c2a618e067028c911149712fdb62ef3e Avoid magic number in cashaddr
- 87413623e25853811f768e31e074cdfd14e2b524 [backport] RPC: Add connection type to getpeerinfo, improve logs
- 4bb7bc3d2da6a39c04bfcdde6ddd34e28c9b0648 [backport] rpc: add an include_change parameter to listsinceblock
- 26b482364d929d54f285536d34e6da1242e81f71 [backport] wallet, rpc: add label argument to listsinceblock
- 37eaf3a1d5b7537119159af4e0d434f6692e097f [backport] Add RPC Whitelist Feature
- cf1c320e1e522465460ed2ef26a9c8f9265b5ca7 [backport] test: Add test for rpc_whitelist
- 1216d7ba6a862bc1b52cbcbf6cc0c76fb862e8b5 Chain interface: Add utility function findCoins() Chain::Lock class
- 5f04a665241857f55904537a9b488093dcc98994 rpc: Modify RPCTypeCheckObj function to optionally disallow unknown keys
- 7f97ca37086698d9b920f9f1fd1781adcbfc19ca rpc/wallet: add simulaterawtransaction RPC
