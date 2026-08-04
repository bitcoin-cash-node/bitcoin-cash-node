# Release Notes for Bitcoin Cash Node version 22.1.0

Bitcoin Cash Node version 22.1.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This is a minor release of Bitcoin Cash Node that implements some
interface enhancements and includes a number of other corrections and
improvements.

Users who are running any of our previous releases are recommended to
upgrade to v22.1.0 ahead of November 2020.

We remind that the 0.21.x family of BCHN releases does not implement the
new rules for the coming November 2020 upgrade. Users must upgrade to a
release in the 22.x family before November 15th, 2020.


## Usage recommendations

Installing this version is optional, but we recommend that users of
22.0.0 upgrade to this minor release for the corrections contained in it.

This update is compatible with the November 15, 2020 Bitcoin Cash network
upgrade.


## Network changes

### New test network options.

This release delivers the ability to access two new test networks:

- testnet4 (more lightweight test network to be kept spam-free)
- scalenet (for high-throughput tests, including at block sizes beyond
  current main network maximum)

Please refer to `doc/test-networks.md` or <https://docs.bitcoincashnode.org/doc/test-networks/>
for further information.


### New seeder configuration

Added configuration to access new DNS seeders from loping.net and a new
electroncash.de mainnet seeder.

- dnsseed.electroncash.de (mainnet)
- seed.bch.loping.net     (mainnet)
- seed.tbch.loping.net    (testnet3)
- seed.tbch4.loping.net   (testnet4)
- seed.sbch.loping.net    (scalenet)

Removed the defunct seeder entry deadalnix.me.


## Added functionality

### extversion

This release implements the 'extversion' extended versioning handshake
protocol (ref. BCHN merge requests !558 and !753), previously implemented
by Bitcoin Unlimited. We thank Greg Griffith and the Bitcoin Unlimited
developers for their efforts to achieve this implementation in BCHN.

The extversion handshaking is disabled by default and can be enabled
using the `-useextversion` CLI argument or the `useextversion=1`
configuration file setting.

Nodes indicate extversion support by setting service bit 11 (EXTVERSION).

Right now the BCHN implementation of ExtVersion supports only 1 key -- the
"Version" key.

The specification can be found in `doc/xversionmessage.md` or at
<https://docs.bitcoincashnode.org/doc/xversionmessage/> .


### indexdir

A new `indexdir` configuration option allows the user to specify a path
under which the leveldb 'index' folder is stored.

The use case for this new option is to store the index on a separate volume
of faster access media while the blocks can be stored on slower media.

If the argument is not specified, the index is stored in the usual place
(in the `blocks/index/` folder).


### finalizeheaders

A new `finalizeheaders` configuration option (enabled by default) rejects
block headers which are below the finalized block height (if a block has
indeed been finalized already).

Finalized blocks are not supposed to be re-organized under any circumstances
(just like checkpointed blocks). There is therefore no need to accept
headers for alternate chains below the last finalized block.

Nodes which submit such blocks are penalized according to a penalty score
determined by the `finalizeheaderspenalty` option (default is 100, meaning
such nodes will be disconnected).

In practice this works to quickly disconnect nodes from old chains like
the "Clashic" network which sometimes submit headers of forked off chains
with vastly lower block heights.


### New debugging tracepoints

Two new debugging tracepoints have been added:

- `debug=finalization`
- `debug=parking`

These can be used to log events related to automatic finalization and
parking/unparking.


## Deprecated functionality

No functionality is deprecated in this release.


## Removed functionality

No functionality is removed in this release.


## New RPC methods

No new RPC methods are added in this release, however some argument
aliases are added to existing calls (for backward compatibility) and
a new optional parameter is added to the `sendtoaddress` method (for
improved coin selection performance).


## Low-level RPC changes

An optional coin selection ('coinsel') argument has been added to the
`sendtoaddress` RPC method.

An alias `blockhash` has been added for the `hash_or_height` parameter of
the `getblockheader` call, for backward compatibility.

An alias `dummy` has been added for the `parameters` argument of
the `submitblock` call, for backward compatibility.


## Regressions

Bitcoin Cash Node 22.1.0 does not introduce any known regressions compared
to 22.0.0.


## Known Issues

Some issues could not be closed in time for release, but we are tracking
all of them on our GitLab repository.

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

- `arc lint` will advise that some `src/` files are in need of reformatting
  or contain errors. - this is because code style checking is currently a work in
  progress while we adjust it to our own project requirements (see Issue #75).
  One file in `doc` also violates the lint tool (Issue #153), and a new
  script in `test/benchmark/` likewise contains code that is flagged by
  the current linting configuration.

- `test_bitcoin` can collide with temporary files if used by more than
  one user on the same system simultaneously. (Issue #43)

- For users running from sources built with BerkeleyDB releases newer than
  the 5.3 which is used in this release, please take into consideration
  the database format compatibility issues described in Issue #34.
  When building from source it is recommended to use BerkeleyDB 5.3 as this
  avoids wallet database incompatibility issues with the official release.

- There is a documentation build bug that causes some ordered lists on
  docs.bitcoincashnode.org to be rendered incorrectly (Issue #141).

- There is a report that the `test_bitcoin-qt` test executable fails on
  Linux Mint 20 (see Issue #144). This does not otherwise appear to impact
  the functioning of the BCHN software on that platform.

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

---

## Changes since Bitcoin Cash Node 22.0.0

### New documents

- `doc/test-networks.md` : an overview of the test networks supported by BCHN

### Removed documents

None.

### Notable commits grouped by functionality

#### Network fixes

No changes.


#### Interfaces / RPC

- 3379ccd12d9c1ff7ff5e9a449916a052d446f320 Fix getblocktemplate sigop/blocksize limits to reflect -excessiveblocksize setting
- 558a4a38f73e30834cb0fc4bb0ab96009cafac2d Add -expirerpc to list of intentionally undocumented CLI arguments
- c21c8ee16213295cd9cd40abf8e047dca2653f73 Implement Extversion
- ac8192a8b9c90677377cd71521c97e0f36e213b2 Fix to `EXTVERSION` handshake causing peers to punish each other for misbehavior (simplified)
- ad701aa8e1030182e0b502cc4a340317d505c9d4 [rpc] Override error messages in sendtoaddress
- 1e90a52c75717a6771516065e29b51f4356eea02 Add 'finalization' & 'parking' debugging tracepoints
- 5c62505ca77c325d35a63850e8d7ebb4c3b9d3b1 Add indexdir parameter to bitcoind
- 44669a2e353a8df28872b7aadfec924efea70fc7 rpc: Add coin selection argument with fast option to sendtoaddress
- 897b181bb0aa16e96d054568685194da0708103f RPC: Add alias `blockhash` to `getblockheader` for backward compatibility
- 1df9b1c8114922d41088cd89a715e58be6477fe7 RPC: Alias `dummy` for second arg to `submitblock` for compatibility


#### Peformance optimizations

- 692fdfb4bda8da8af61ff20ccb2d44887b02b453 [Net] Don't keep 3 copies of the NetMsgType strings in memory
- f60a16c581ff255a251788b015ac194846cf4127 fix CTxMemPool::TrimToSize including too many things in pvNoSpendsRemaining
- 84b36dd632958dfd2c63dac3ffba8d51c7c828eb rpc: Change error checking of sendtoaddress to improve success path performance
- 59a23ae3123bfe359c4d5d161140b4a95f7630ef [validation] Make CheckRegularTransaction about 2x-10x faster for typical tx by avoiding malloc
- bf43658c2b82f2bee32f2299b1366118bb4b0cb2 Add option to reject and penalize headers deeper than finalized block


#### GUI

- 1fc367e5dc1290c2615b2f73e89c96925668fa3a Fix Windows crash at startup introduced by MR !786


#### Code quality

- 1de532917b2a5e80aba1cc4add1a4fd274cf47b7 SigHashType: document the footgun
- 534469c0b3f577b7a4929fb28d1f15f8a500bd10 [net] Follow-up to !622, reduce/remove some double-copies and other nits
- a69b88a7127fb4b49b64e6c1d895eaa7b579ee26 Restrict CBlockIndex to not allow copy, move, or assignment
- e6748bc7c6d1721b5fb91cb4fad18c7e9f75f9ed Remove unreferenced AVAPOLL and AVARESPONSE symbols from protocol.cpp
- 42b1739e47b889cb83469ddba81e0f4e7c0ceedd Make src/rpc/mining.cpp use config.GetMaxBlockSize() instead of DEFAULT_MAX_BLOCK_SIZE
- fcb23ba7c92f2e2d0b6f297c9c2c10cf7163153b Strong typing for UniValue, part 1: rename ObjectEntries, ArrayValues, write() (#51)
- efeacd0c9105e97afd012a79c11acbb480f5ea61 [Net] Make protocol string commands const-correct
- 268537d19bbb05fd7c1ceaa7e1b7371dbace3f4f Remove UniValue::__pushKV()
- 63c3240b67cf591a19bcad847b0ad0af55d1725a Improve UniValue array/object constructors/setters
- 5abc0b8e1f02385d27ca04a6cb011304bb4c2cc6 Rename UniValue::find() to locate()
- f0d956c12844cc80dd39e2c2f75628e503bfac46 Strong typing for UniValue, part 2: minor preparatory refactors (#51)
- 027ecf82d7a41ede6efd83e02fb04bd2534f62d6 [txmempool] Remove dangling/obsolete code in removeForBlock(...)
- 56878c80e916dad9d8169e4928bf8d5eb90431b2 Introduce UniValue::at()
- 198429f9420db9def9ad44718bbeb139446c8fd6 Made the CTransaction class no longer default constructible
- 8dd5b0763c94691d9937735fee01cac5e1b86337 Remove copy & assignment for CTranscaction for type safety
- bbad18da16b62fca79e131215bb85b72e47e4cc4 [qa] Fix misleading comment in script_flags.h
- 077d1d446fdcfbdb58a752ae557c7e9d8fa2976d [trivial] Fixed a typo in a comment in the `CTransaction` class
- 156de35edd0faeb9daa6576116037e848e49c3c7 Introduce UniValue::size_type
- be048a11ec6a46702d2d5935a7004e05b6b08823 Strong typing for UniValue, part 3: Object and Array classes
- 1cd875bffaaffe9dac2598a0748bc928a3029488 Improve UniValue::at() exception messages
- 71f2d6b04de9327d19f68c57e4669a5eb99d1f70 Upgrade UniValue::get_obj/get_array()
- a657de330612fbca7b5d364b2f7225b91cb67d68 Remove UniValue::takeArrayValues()
- ea36c77d41b43de63d499ce69c1b129e2edb2df1 Remove UniValue::getArrayValues()
- 3a524cf01e4cbd3cac70f65e6e74a8746eec0221 Remove UniValue::getObjectEntries()
- 66ca616bce874c925afffb1b5118fd526e30fc78 Strong typing for UniValue, part 4: remove redundant object/array getter methods
- bdbc0765cd4ad7344a23e776c45214178525638b Fixed UniValue bug: don't take pointers to temporaries
- 6785f66221321ece3049e4cf575256adb71bff2e Strong typing for UniValue, part 5: make copy-upcast constructors explicit
- 2d30582fd697cbcbff3f827f525d4571ab7dc132 Remove declared but undefined function: fsbridge::freopen
- e60b06a1422b8a0c447fa425399deb75b6bd1e89 Prohibit implicit UniValue::VType to UniValue conversion
- 53f5d4b43839656c83efac03d3809a8b0f141b03 Prohibit implicit UniValue copying
- 3b5f03cf54e2a52b9dc53a8fed9dfbd196f52c83 Prohibit implicit UniValue::Object copying
- 0587870af7dc8e9f767174ab8d3dff1258d512b8 Prohibit implicit UniValue::Array copying
- ff0ea6b5b1ae55b10f7006cbdf8e4e7e7aebabe8 Replaced many instances of std::string pass-by-value with pass-by-ref
- caf6845a63955948595040098bda2b650ab51f99 Removed use of designated initializers from code: Not supported in C++-14
- a9e3e4daf554fea5d4f8311b0ff7e4632abee5ff Make more UniValue copy constructors explicit
- 2313ef2b92090c8fabdb3263b7bb92528c9d9f22 Make chainparamsseeds.h use numeric strings for human-readability
- bfb3794c0ddaa2d32846401a706f3b57ed7353e4 [wallet] Change return type of CreateTransaction
- 2e5d7de39d6eda54ce8d736132fd578380911b0f [rpc] Replace error heuristics with rc check
- 6eea1e105e026f9e690ca212398d0cbb708e35f7 Remove 'Optional'-related false positive uninitialized warnings on GCC
- e3107d7c298488162624933bb186424ea5b1be3d Fix GCC compile warning in `seedspec6_tests.cpp` related to missing braces
- bf46211b584daad6c3d3517ebda39aed99b58e2c [qa] Various cleanups in p2p_stresstest.py (linting and #173)


#### Documentation updates

- 06557a8db82b907fbb331637cb58ab661ecc00ec mr -> mreq and mark commands and packages as such
- c2d59dd3ca34cef49027f633f289f05c97c8df6b [doc] Add 'bounty' label
- 42706ea1c0c26ef4b6d772cca3a6e0b596b5b70f Update UniValue readme
- 0fd21e4a4693ee9c98d93695d0e6d32a33613713 [doc] Add test-networks document (to accompany introduction of testnet4/scalenet)
- 24c868e8d99298ff06e15081c5f3e7a984a449c7 [doc] Regenerate (update) the manpages and markdown docs for v22.1.0


#### Build / general

No changes.


#### Build / Linux

No changes.


#### Build / Windows

- 7f87de8946d907f6a13cfe440649e231cb219fdb Add NSIS related shortcut code changes


#### Build / MacOSX

No changes.


#### Tests / test framework

- 229c11daa5c092e09a90818cccdd309bddb322b1 [backport] tests: Make updatecoins_simulation_test deterministic
- b970299e8cec26da66c3e6dee51663d7da86e76c Functional test that getblocktemplate's size/sigop limits change with -excessiveblocksize
- e56eaa039d0c3821c7803437059acd88f3b8aa88 Fix bchn-rpc-outdated-warnings functional test on slow PC
- 610275b4a0775eb62a2957f2a67a9c1cce88dbee [qa] Improve `sendtoaddress` test coverage
- db686fa91bf8e361941233a761f481a6edfb700b Faster sendtoaddress RPC and p2p_stresstest.py spam generation/stress testing script
- c8bd3ed92dd36247839a31dbc6755958b64ab988 Fix EXPECTED_VIOLATION_COUNT warning for `check-functional`


#### Benchmarks

- db686fa91bf8e361941233a761f481a6edfb700b Faster sendtoaddress RPC and p2p_stresstest.py spam generation/stress testing script


#### Seeds / seeder software

- c8c66af8f0b019ecdfb8e0c74fd0b2b587f97e3e Fix seeder on chains without checkpoints


#### Maintainer tools

- 4c2a598bf8361471beb1eb23458a4535fa7741ad This updates the static seed tools.
- 1151bb26cf8bd2d7d7267bee6d399583ecb9beb2 Update static seed tooling and chainparams naming of static seed lists
- 255e013ac72d4d8ed69f8cc546f9c89713ceec3a Detect -testnet4 and -scalenet from GetNetBoolArg call


#### Infrastructure

- fd8f0ff85c32522a8e252a50f4fe0d3fd43c44ed Make the default blocksize limit a consensus/chainparam value
- d04560fca9a5513bbe558fa9a45694c4dc2b9808 Update contrib/gitian-signing/keys.txt, contrib/gitian-signing/pubkeys.txt files
- 29e5d7d3e06cde000323e031c3d4419c3e3aa265 [qa] Add imaginary_username gitian signing pubkey
- 8ec7f4c6b6cf6068bd184b14d7201fe6b803c3ac [qa] Add freetrader launchpad signing pubkey
- 174b0fd223ff4c37f985515a9d6eac3273239008 Add testnet4
- fcd80dd17fe3f5d2e193fa3662f5c407f64b78e3 Scalenet
- cae98627fdbdd0432458c8caace59e0505e78357 Remove deadalnix.me seeders, they haven't been working for 8 months
- e0904b56bc1e6a7817e8033d5950c65d86b09ebb Add new loping.net seeders
- 16da9bf3ecc77e58c99a0d19eff2c70785d712a4 Add new electroncash.de mainnet seeder
- 08e332d0bd0c480e560c7b3ebe953854d038d03f Scalenet and Testnet4 must use May 2020 HF height of 0


#### Cleanup

- 0e610d26f3c88800442ebe0353e806332e31d3d1 remove SCRIPT_VERIFY_CHECKDATASIG_SIGOPS flag
- e2edfe594474a8c7340e6546ddcf5f40715962c6 [cleanup] Remove radix-tree


#### Continuous Integration (GitLab CI)

No changes.


#### Backports

- 229c11daa5c092e09a90818cccdd309bddb322b1 ABC: D6620: [backport] tests: Make updatecoins_simulation_test deterministic
- 631697e3a13c972edb3752e615266edcae09c1c6 ABC: D5689,D5619: [backport] Replace the test runner with a test wrapper ; Set environment variables when running tests with sanitizers
