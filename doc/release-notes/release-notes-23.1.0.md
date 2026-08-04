# Release Notes for Bitcoin Cash Node version 23.1.0

Bitcoin Cash Node version 23.1.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This is a minor release of Bitcoin Cash Node (BCHN) containing several minor bugfixes and some performance improvements, such as:

- Mempool: 40% performance speedup in removing confirmed txs and multiple speedups for other operations as well.
- Mempool: removal of all pre-May 15 2021 logic and data structures, including structures dealing with unconfirmed ancestor limits, saving memory and CPU cycles.
- Scalenet: Ensure the "disconnected block transactions" pool has enough memory.
- Added the JSON-RPC command: `getdsproofscore`.
- Save known DSProofs across restarts to `dsproofs.dat`.
- Fixed misspelling of "hexstring" param name in the "signrawtransactionwithwallet" method.
- Fix bug where `-txbroadcastinterval=0` would lead to a numerical singularity where no txs were sent. Instead, with this arg at 0, txs are now just sent as quickly as possible.
- Remove `-tachyonactivationtime` from CLI args & consensus rules.
- DSProofs: Bug fix where sometimes nodes would "discourage" each other incorrectly after they clean up expired proofs.
- Mining: Add `-gbtcheckvalidity` arg to CLI; `"checkvalidity"` arg to GBT/GBTL.
- Mining: Fix potential crash in `submitblock` if 2 RPC threads are submitting a block simultaneously.
- Speedup to block validation and tx validation by removing a redundant map lookup when checking inputs.

## Usage recommendations

Users who are running v22.x.x or earlier are strongly urged to upgrade to v23.1.0, since the v22 series (and previous) do not implement the recent [May 15, 2021 Network Upgrade](https://upgradespecs.bitcoincashnode.org/2021-05-15-upgrade/).  Users running v23.0.0 may also wish to upgrade to this version, since it does improve performance and does fix some minor bugs.


## Network changes

A minor bug has been corrected where in some corner cases P2P nodes may end up "discouraging" each other incorrectly when an old DSProof is removed after a block is confirmed.


## Added functionality

- Double-spend proofs now are persisted across restarts to a file in the data directory called `dsproofs.dat`. The mechanism for this is similar to how the mempool is already persisted across restarts. Double-spend proofs are not persisted if the node was started with `-persistmempool=0` or `-doublespendproof=0`.

### `gbtcheckvalidity` configuration option and `checkvalidity` RPC arg

This new command-line option (as well as its counterpart RPC arg) may be of interest to miners. With `-gbtcheckvalidity=0` (or RPC arg `checkvalidity=false` to the `getblocktemplate`/`getblocktemplatelight` RPC), all validity checks on a new block template are skipped. This saves significant time in generating a new block template (50% or greater speedup for large blocks).

The validity checks are redundant "belt-and-suspenders" checks -- and it should never be the case that this codebase produces an "invalid" block in `getblocktemplate`. Producing an invalid block that fails these checks would be a serious bug in this codebase. As such, these checks can be optionally skipped for the intrepid miner wishing to maximize performance and minimize latency to `getblocktemplate` and/or `getblocktemplatelight`.

The default for these options is to preserve the status-quo (default: `-gbtcheckvalidity=1` and/or `checkvalidity=true` to the RPC), and perform these (redundant) validity checks on new block templates.

## Deprecated functionality

In the `getmempoolentry` RPC call, the verbose modes of the `getrawmempool`/`getmempoolancestors`/`getmempooldescendants` RPC calls, and the JSON mode of the mempool REST call, the `height` field is deprecated and will be removed in a subsequent release. This field indicates the block height upon mempool acceptance.

The `bip125-replaceable` field in the result of `gettransaction` is deprecated and will be removed in a subsequent release.

The `arc lint` linting is deprecated and developers should use the `ninja check-lint` target instead.

## Modified functionality

The CLI/conf arg `-txbroadcastinterval=0` would previously lead to a situation where the node would never relay transactions. This is considered a bug and has been corrected. Now, if the node operator specifies `-txbroadcastinterval=0`, the node relays transactions as quickly as possible.

## Removed functionality

The CLI arg `-tachyonactivationtime` has been removed. All relay rules behave as if "tachyon" (the internal name for the May 15, 2021 network upgrade) has always been active.

The following CLI args (all related to the now-removed ancestor limit) have been removed: `-walletrejectlongchains`, `-limitdescendantcount`, `-limitancestorcount`, `-limitdescendantsize`, `-limitancestorsize`.

## New RPC methods

### `getdsproofscore`

`getdsproofscore` returns a double-spend confidence score for a mempool transaction.

This new method should help merchant or wallet server implementors quickly decide if a transaction is reliable for 0-conf (1.0: has no DSProofs and is eligible for DSProof mechanism), or is unreliable for 0-conf (<1.0: has DSProofs, or is ineligible for the DSProof mechanism, or has a very long ancestor chain).

Please refer to the documentation pages for [getdsproofscore](https://docs.bitcoincashnode.org/doc/json-rpc/getdsproofscore/) for details about additional arguments and the returned data.

## Low-level RPC changes

The `getmempoolancestors` and `getmempooldescendants` RPC methods now return a list of transactions that are sorted topologically (with parents coming before children). Previously they were sorted by transaction ID.

Mempool entries from the verbose versions of: `getrawmempool`, `getmempoolentry`, `getmempoolancestors`, and `getmempooldescendants` which contain a `spentby` key now have the transactions in the `spentby` list sorted topologically (with parents coming before children). Previously this list was sorted by transaction ID.

The `getblocktemplate` and `getblocktemplatelight` template-request dictionary now accepts an additional key: `checkvalidity` (default if unspecified: true). If set to false, then validity checks for the generated block template are skipped (thus leading to a faster return from the RPC call).

## User interface changes

Bitcoin Cash Node 23.1.0 does not introduce any user interface changes as compared to 23.0.0.

## Regressions

Bitcoin Cash Node 23.1.0 does not introduce any known regressions as compared to 23.0.0.

## Known Issues

Some issues could not be closed in time for release, but we are tracking all of them on our GitLab repository.

- MacOS versions earlier than 10.12 are no longer supported. Additionally,
  Bitcoin Cash Node does not yet change appearance when macOS "dark mode"
  is activated.

- Windows users are recommended not to run multiple instances of bitcoin-qt
  or bitcoind on the same machine if the wallet feature is enabled.
  There is risk of data corruption if instances are configured to use the same
  wallet folder.

- Some users have encountered unit tests failures when running in WSL
  environments (e.g. WSL/Ubuntu).  At this time, WSL is not considered a
  supported environment for the software. This may change in future.

  The functional failure on WSL is tracked in Issue #33.
  It arises when competing node program instances are not prevented from
  opening the same wallet folder. Running multiple program instances with
  the same configured walletdir could potentially lead to data corruption.
  The failure has not been observed on other operating systems so far.

- `doc/dependencies.md` needs revision (Issue #65).

- `test_bitcoin` can collide with temporary files if used by more than
  one user on the same system simultaneously. (Issue #43)

- For users running from sources built with BerkeleyDB releases newer than
  the 5.3 which is used in this release, please take into consideration
  the database format compatibility issues described in Issue #34.
  When building from source it is recommended to use BerkeleyDB 5.3 as this
  avoids wallet database incompatibility issues with the official release.

- The `test_bitcoin-qt` test executable fails on Linux Mint 20
  (see Issue #144). This does not otherwise appear to impact the functioning
  of the BCHN software on that platform.

- An 'autotools' build (the old build method) fails on OSX when using Clang.
  (Issue #129)

- With a certain combination of build flags that included disabling
  the QR code library, a build failure was observed where an erroneous
  linking against the QR code library (not present) was attempted (Issue #138).

- The 'autotools' build is known to require some workarounds in order to
  use the 'fuzzing' build feature (Issue #127).

- Some functional tests are known to fail spuriously with varying probability.
  (see e.g. issue #148, and a fuller listing in #162).

- Possible out-of-memory error when starting bitcoind with high excessiveblocksize
  value (Issue #156)

- There are obstacles building the current version on Ubuntu 16.04 (see #187).
  These are worked around by our packaging system, but users trying to build
  the software from scratch are advised to either upgrade to more recent Ubuntu,
  or retrofit the necessary toolchains and perform the same build steps for
  Xenial as registered in our packaging repository, or build in a VM using
  the gitian build instructions, or run our reproducible binary release builds.
  There is ongoing work on the build system to address underlying issues,
  but the related code changes were not ready in time for the v23.0.0 release.

- A problem was observed on scalenet where nodes would sometimes hang for
  around 10 minutes, accepting RPC connections but not responding to them
  (see #210).

- In the `getmempoolentry` RPC call, the verbose modes of the
  `getrawmempool`/`getmempoolancestors`/`getmempooldescendants` RPC calls, and
  the JSON mode of the mempool REST call, the `height` field shows an incorrect
  block height after a node restart. Note the field is deprecated and will be
  removed in a subsequent release.

- On some platforms, the splash screen can be maximized, but it cannot be
  unmaximized again (see #255). This has only been observed on Mac OSX,
  not on Linux or Windows builds.

---

## Changes since Bitcoin Cash Node 23.0.0

### New documents

- [doc/build-unix-alpine.md](../build-unix-alpine.md): Alpine Linux build instructions.

### Removed documents

There are no removed documents in the BCHN software repository.

### Notable commits grouped by functionality

#### Security or consensus relevant fixes

- 6d174078ab68aa7a8d9ea831be16b699c36abc43 Ensure the DisconnectedBlockTransactions pool has enough space
- 48ce9eeaa8ac79afedda9c2ca9d9928161e6bb10 Remove -tachyonactivationtime from CLI args & consensus rules
- 3944570c60a5f7789ad670dfbd2e658b4fafa2b6 dsproof: When an orphan is claimed, clear the nodeId
- e3d6f75f6211de88811ee4a572c0731bc7e8eaa9 update checkpoints for main, test3, and test4 nets
- 6a358cc87fead2e23b1d994035e46fca7de14f4f Update default assume valid and minimum chain work params

### Misc. bugfixes

- e877fe4801b5cbff9dd6c159ccbdc0d790871a82 Fix `-txbroadcastinterval=0` leading to no txs sent + add functional test
- 6a8892b07d8dfdf168718ca82ac2ed1fbb370297 [mining] Fix potential crash bug in `submitblock`

#### Interfaces / RPC

- 12d34cc74bb5ea67ed91b5c127edae2f34565a16 Fix "hexstring" param name in "signrawtransactionwithwallet" method
- e43045a8ffa96f8acfe9d73c62c085686d214dec Added RPC method `getdsproofscore`
- fd29ab6ccdf65a57bd52c9d85e7c0030b6e82c62 Add -`gbtcheckvalidity` arg to CLI;`"checkvalidity"` arg to GBT(L)

#### Performance optimizations

- bf6e231626f0463c61602e2b815564aa913236ae mempool: optimization of removeForBlock + general optimizations
- 431374d9867bfb9191f31ccdb22deecd94f16ffd Remove pre-tachyon logic and code from txmempool and related tests
- 44150d7ed46b2e3f662d3e71650ce5006e3b3833 Removed remaining unconf. ancestor limit args & logic
- 837452de17ada4e506f6f3d578afdaccc78bbb81 Speedup Consensus::CheckTxInputs by removing a redundant coin lookup

#### GUI

- d124fc8d987bf11a76e28f840efd4227e05a97d6 New translations: Polish

### Data directory changes

- 62c65273c375d57c36f345d7c62ba589b7165c98 Save dsproofs across restarts to datadir/dsproofs.dat

#### Code quality

- 7119bbf096b6bdad2e81e54e55b7943de2f4ce86 util: Refactor the Defer class to a header to be reusable
- d20a0d27bbe8effee024bf255c8b1485d7f1554e Prefer emplace to insert in CTxMemPool::addUnchecked for map insertion
- 2a651f392187153ba121b7358b878bcd90bac91f Avoid double copy when emplacing into DisconnectedBlockTransactons::txInfo
- 9919f92a0a97f63372b4142189081be3e1509f27 Fix fcntl warnings on alpine build
- c52df0ed233bf34ed0a6d30313795e935e5efd91 Nit: Fix compiler warning for g++-8 in txmempool.cpp

#### Documentation updates

- c53c1065e2f0f7ed9264d0df16ca036d9118a325 [doc] Add -DENABLE_MAN=OFF to cross-build instructions
- baab4c28598adedb334ee28c1b56a75fbdbaf0b7 [qa] Remove Win32 cmake build file and target reference in doc
- 479d56521ba260c4b4804887b99472622d781f7d [doc] Add a clarification about SDK_PATH to depends/README.md
- dffef9d8a6338f78657108a3687de8ec7eafe7bc Add alpine build instructions
- 4499999da41bb8cce51fc6dc8ae87ea7467732d7 [doc] Call out additional dependencies that contributers likely need

#### Build / general

- 8f6ccf6c74f3c495da7ce542c0275c3b101360e9 Add more build options
- 8181d27a03eb9ff02d00a508b0223e8fd1f4811f Update ZeroMQ library to 4.3.4

#### Build / Linux

None.

#### Build / Windows

None.

#### Build / MacOSX

None.

#### Tests / test framework

- 4f1cc4788227b5f655b736d19c7b34ca1f72a1e7 Fix rare timing-related failures in dsproof functional tests
- b1d47fa18660841e1fd3263dece19ed6e7770f10 Fix randomly failing scheduler_tests test
- 3e79059929a5c28b73744c4c27b01d92ff2d84c9 Reduce bchn-rpc-getblocktemplate-timing success threshold to 50%
- 7e0011617d329f053b0d435501cea4074d544162 Fix for rare failure in the bchn-rpc-getblocktemplatelight functional test
- 446deaf62e0ae1fe98cd253ac38c290169a18085 Add mempool_fee_delta functional test
- cb6b037026ac1e1aeeb03c8726a07d10c98c75ad Disable test: bchn-rpc-getblocktemplate-timing.py
- e2ba753eb5654d6baf26a33b98e15ff17939e895 Added Unit test that exercises the Consensus::CheckTxInputs function

#### Benchmarks

- 305f40214dcc539d89ed439c313b394dd3d7b921 bench: Add removeForBlock benchmark
- cc4d85c30afebc5584bae7da0fcd4c1c5efcfcd0 bench: Benchmark CCheckQueue using real block data
- bac0a4ec477db07841bfe0899e5d8956622d8d12 Added CLI args to bench: -par and -maxsigcachesize
- aff593f106ad7742b8c08466a4fe191e11898696 bench: Add CheckTxInputs bench

#### Seeds / seeder software

- a20b80e2e61fe2f296a54a55f3037ea6eb4528f2 Add Bitcoin Unlimited operated seeder for testnet3
- 378b2bbef6eccb58a87e33a0af2a05fcbde1147a Update mainnet seeds

#### Maintainer tools

- 67cb583de44ed935af27b0c3ae5ce13f4ead7c5f Update the chainparams update scripts to NOT touch scalenet chainwork
- 3d94dff0b0df46e833dde5fce42e2d0cf232b1b7 Add VSCode settings to gitignore
- 8e806b3780482d300826bc223eba989349374d32 Fix fuzz-libfuzzer undefined references for IsPayToPubKeyHash / IsPayToScriptHash

#### Infrastructure

- cd854c91821f08d4ef75c0b1ef1f858bcb703100 Remove personal disclosure contact
- 1a0a3287df0cc68627e7092d45cbc1cf49404947 Add personal disclosure contact
- 23fcaa267459cd8b59c297081d5fa491ed3bd4dc New Crowdin updates

#### Cleanup

- 14dcc05357d487432af049b0b7598e8475f64b5a mempool: Remove BatchUpdater classes, consolidate & clean-up removeForBlock
- dbbc51d9dbe434e57614b3e2f4e5ca364e295647 Remove allowMultipOpReturn flag
- ae2c2fbaa86de7c1378b1b055a3ad692492080e8 Remove g_parallel_script_checks global variable
- 4c6aaf3affa753896d068f6da6e1f3b0d90e843e Nit: Undo some of the changes of core#18710

#### Continuous Integration (GitLab CI)

None.

#### Backports

- 44d102f75fe4951e6f925c2dd3a32c973c666825 [depends] ZeroMQ 4.2.2
- 2dc29161247c8a1a155ab1cc3c83747cf5195abe depends: zeromq 4.2.3
- d66713f185ae54c802cb937691744fbace763cfa [tests] Remove rpc_zmq.py
- 323a004923117b3248727a17735531bad033f9c8 [depends, zmq, doc] upgrade zeromq to 4.2.5 and avoid deprecated zeromq
- 55c001e63f6a5013b923e2afc49423e30da61ab9 Update zmq to 4.3.1
- ca284daf00f6f23b883bdb1d36d762e2af4f2c0c depends: expat 2.2.6 and qt 5.9.7
- 076e67d4e23dcae7057aeafbebb23ded536fcbe5 depends: Purge libtool archives
- 1612a624c96d07a82c831b0d005f0b03d8bc2d91 depends: cleanup package configure flags
- 7638688c39c9187833f25030cd20c89a45fdd2fc depends: expat 2.2.7
- d97fbb7d0ed1a3518268c91ea290ae0c6dbf1b12 Only pass --disable-dependency-tracking to packages that understand it
- 2a7dc8f2420ca7fedaadf9473496ab931edc78f8 build: prune dbus from depends
- 66c8e65678bb3460172e367d06573eb5eaad1409 depends: Prune X packages
- ed7706e687859f81bd34f9bc16e47c416be41758 build: Drop all of the ZeroMQ patches
- 354e5004370c922930af9ab950f56ee9eabe4309 build: improve sed robustness by not using sed
- d0f97c02a645d8b7f95c4a7222c802e548e7726e [refactor] Replace global int nScriptCheckThreads with bool
- ad49f4f093725d415f2ac552cae6c2c40687f9b5 [tests] Don't use TestingSetup in the checkqueue_tests
- 9151ce2c0daba3c5368e17f1bc544a4d77c0407c Add WITH_LOCK macro: run code while locking a mutex
- 6d5e21a342709d0600bc70c6a0a01b6af040dd54 sync: Use decltype(auto) return type for WITH_LOCK
- 0e94c77f6ef5b6db5e88fca3736da834e5e51172 Add local thread pool to CCheckQueue
