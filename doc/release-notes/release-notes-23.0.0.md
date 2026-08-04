# Release Notes for Bitcoin Cash Node version 23.0.0

Bitcoin Cash Node version 23.0.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This is a major release of Bitcoin Cash Node (BCHN) that implements the
[May 15, 2021 Network Upgrade](https://upgradespecs.bitcoincashnode.org/2021-05-15-upgrade/).
This upgrade will remove the unconfirmed chain limit and enable
transactions with multiple OP_RETURN outputs.

This version contains many corrections and improvements, such as:

- Introducing the Double Spend Proof (beta) feature compatible with
  other clients
- Removing the limits on number of unconfirmed ancestors and
  descendants, and the limits on the byte size of these chains
- Raising the default soft limit for block generation to 8MB
- Adding support for multiple OP_RETURN standardness
  (within existing data carrier size)
- Removal of CPFP functionality
- Changes in mempool eviction order
- New ZMQ functionality (related to dsproof)
- Minor RPC additions and changes (incl. dsproof related)
- Minor changes in error codes
- Improving the graphical user interface
- Extension of software expiry timeframe (to 15 May 2022)
- Switch from C++14 to C++17

Users who are running any of our previous releases (0.22.x) are urged
to upgrade to v23.0.0 ahead of May 2021.


## Usage recommendations

The update to Bitcoin Cash Node 23.0.0 is required for the May 15, 2021
Bitcoin Cash network upgrade.

## About the CPFP & unconfirmed chain limit removal

The CPFP (child-pays-for-parent) and the unconfirmed transaction chain limit will both be deactivated on May 15, 2021 when MTP of the chain tip reaches 12:00 UTC.  After that time,
it will be possible to "chain" unconfirmed transactions beyond the current limit of 50, in
a limitless way, without any negative performance consequence for the node.

This has been accomplished by removing the algorithmically complex and slow code we inherited
from Bitcoin Core which tries to maintain what is known as "Child Pays for Parent" (CPFP) -- a way
in which a child transaction can bump up the priority of its parent transaction via paying a
larger fee.  Maintaining
this feature, which is not even being used on BCH, was the reason for the algorithmic complexity
in the mempool code and why we had a limit of 50 for unconfirmed tx chains.

Additionally, we removed a lot of the slow "quadratic" (complex) per-tx stats that were being maintained (also inherited from Core, and also used in fee calculations). Removing those stats,
which only were added so that Core could limit the blocksize and also get a hyper-fee-market,
allowed us to unleash the true scalability of BCH.  The mempool code was slow -- and it was only
slow because of Bitcoin Core's philosophy about what Bitcoin should be.

One might wonder if allowing limitless unconfirmed transaction chains opens up avenues of attack or flood/DoS.  It does not do this.  Since now our mempool and mining algorithm is linear and not quadratic, there is no real difference between a transaction that has an unconfirmed parent and
one that does not.  They both now cost the same amount of CPU time to process (and in some cases
the unconfirmed parent tx is actually faster to process due to not needing to hit the UTXO db).

Should some user perform a (costly) attack and flood the network with unconfirmed tx chains,
the only consequence will be that he will drain his own resources in fees. Under mempool
pressure, normal fee bump logic occurs. Transactions get evicted in a "lowest fee first" order
and then the mempool's minimum fee for acceptance is bumped up by some small increment. This logic has always been in place and is the way we prevent floods.

In summary, removing the unconfirmed tx chain limit does not impact performance and/or availability whether under normal usage or under congestion.

## Network changes

The `dsproof-beta` network message can be emitted and relayed
when Double Spend Proofs are enabled (which they are by default).

For miners/pools running without a blockmaxsize configuration,
the default soft limit of generated blocks will increase from 2MB to 8MB
in this update. The default hard limit of 32MB remains unchanged in
this release.


## Added functionality

### Double Spend Proofs (DSProof)

This release adds Double Spend Proofs that are compatible
with the published `dsproof-beta` message specification and
existing implementations in Bitcoin Unlimited and Flowee The Hub.

Double spend proofs are enabled by default, but can be turned
off with the `doublespendproof=0` configuration setting.

This functionality is still in beta. In future BCHN releases
we plan to gradually add more application interfaces to query
double spend proof information about transactions and to provide
wallet user with double spend notifications.

Please refer to <doc/dsproof-implementation-notes.md> for more
information details on the DSProof implementation in BCHN,
and the sections on New RPC methods and New ZeroMQ notifications
below for a listing of the new API calls.

### `maxgbttime` and `maxinitialgbttime` configuration options

These two new command-line options may be of interest to miners (pools).
They enable setting maximum time limits for getblocktemplate calls,
instead of relying on blockmaxsize limits to limit the time taken
to construct a template.

The `-maxinitialgbttime` setting determines the maximum number of
milliseconds that can be spent adding transactions to block templates
for the first template after an UpdateTip, whereas the
`-maxgbttime` setting does the same thing but for all block templates
(not just the first).

This should allow pools to create larger block sizes on average without
taking on significantly greater costs and risks.

The default settings for `-max*gbttime` are both 0 in this release,
so it has no effect on node behavior when the default options are used.

### `-rejectsubversion` configuration option

This can be used to reject peers which have certain fixed strings
in their user agents. Useful for blocking non-compatible SV and ABC
peers. The option can be specified multiple times to filter several
matches.

Example:

```
bitcoind -rejectsubversion="Bitcoin SV" -rejectsubversion="Bitcoin ABC"
```

Care should be taken to filter out only peers which are definitely not
useful to your Bitcoin Cash node.

## Deprecated functionality

In the `getmempoolentry` RPC call, the verbose modes of the
`getrawmempool`/`getmempoolancestors`/`getmempooldescendants` RPC calls, and the
JSON mode of the mempool REST call, the `height` field is deprecated and will be
removed in a subsequent release. This field indicates the block height upon
mempool acceptance.

The `bip125-replaceable` field in the result of `gettransaction` is deprecated
and will be removed in a subsequent release.

The `arc lint` linting is considered deprecated and developers should use
the `ninja check-lint` target instead.

## Modified functionality

Mempool expiry works slightly differently now. Previously, the expiry of an old
mempool tx would be checked thoroughly every time a new tx was accepted to the
mempool, but this consumed a bit of extra memory to accomplish precisely and
efficiently.  Instead, we save on memory by doing a fast (imprecise) check each
time a new tx is added to the mempool.  This check may miss some txs that
should be expired.  In order to catch those txs, we
now also run a perfect (slower) expiry check of the mempool periodically. A new
CLI arg, `-mempoolexpirytaskperiod=` was added to control the frequency of this
thorough check (in hours). The new  argument's default value is "24" (once per
day).

## Removed functionality

Manpages are no longer available in the autotools build system. You must switch
to the CMake build system to continue using manpages. Note the autotools build
system has been deprecated since v22.0.0.

## New RPC methods

### `validateblocktemplate`

The 'validateblocktemplate' RPC call has been added.
This call checks if a block template would be accepted if the hash solution
were solved.  The semantics of this call are the same as on BCHUnlimited from
where a substantial portion of this new functionality has been ported.
It is intended to be used by services that test compatibility of block
generation with BCHN's consensus rules.

### `getdsproof` and `getdsprooflist`

`getdsproof` retries more information about a specific double spend proof.

`getdsprooflist` lists the double spend proofs that are known about
transactions in the node's mempool.

Please refer to the documentation pages for
[getdsproof](https://docs.bitcoincashnode.org/doc/json-rpc/getdsproof/) and
[getdsprooflist](https://docs.bitcoincashnode.org/doc/json-rpc/getdsprooflist/)
for details about additional arguments and the returned data.

## New ZeroMQ (ZMQ) notifications

BCHN can now publish notification of both hashes and full raw double spend
proofs generated or accepted by the node.

The notifications can be enabled via the `-zmqpubhashds=address` and
`-zmqpubrawds=address` configuration options where `address` must be a
valid ZeroMQ endpoint. Please refer to the [ZMQ
API](https://docs.bitcoincashnode.org/doc/zmq/) documentation for further
details.

## Low-level RPC changes

The `getblockstats` RPC is faster for fee calculation by using BlockUndo data.
Also, `-txindex` is no longer required and `getblockstats` works for all
non-pruned blocks.

In the `getmempoolentry` RPC call, the verbose modes of the
`getrawmempool`/`getmempoolancestors`/`getmempooldescendants` RPC calls, and the
JSON mode of the mempool REST call, the fields `fee` and `modifiedfee` are
removed. These fields were deprecated since v0.20.4. Please use the `fees`
subobject instead.

The (non-default) option in the `getnetworkhashps` RPC call to calculate average
hashrate using "blocks since last difficulty change" has been removed. The
option relied on an incorrect assumption of when the last difficulty change
happened. On Bitcoin Cash, difficulty changes every block, rendering the option
meaningless. The removal of this option was announced in the release notes of
v22.2.0.

## User interface changes

The transaction viewer (configurable via the Settings -> Display dialog)
configuration now accept only valid HTTP or HTTPS URLs.
Existing URLs that do not conform to these schemes are not displayed in
the context menu.

Qt GUI settings are no longer automatically copied from Bitcoin ABC on first
use of Bitcoin Cash Node.

## Regressions

Bitcoin Cash Node 23.0.0 does not introduce any known regressions compared
to 22.2.0.

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

## Changes since Bitcoin Cash Node 22.2.0

### New documents

The following are new documents in the BCHN software repository:

- [doc/dsproof-implementation-notes.md](../dsproof-implementation-notes.md): Technical notes about the
  implementation of the Double Spend Proofs in the BCHN software
- [doc/linting.md](../linting.md): Information for developers about the linting of BCHN
  software and some package dependencies needed for this
- [doc/release-notes/release-notes-22.2.0.md](release-notes-22.2.0.md): The previous Release Notes

### Removed documents

All Markdown (.md) documents previously in the `doc/json-rpc/` folder have
been removed.

These are now generated on the fly during the build and deployed to the
documentation website at <https://docs.bitcoincashnode.org>.
It is planned in future to provide a downloadable standalone documentation
set (in HTML and Markdown).

### Notable commits grouped by functionality

#### Security or consensus relevant fixes

- 352a94efe6427b14a77cbb92adea4760947d26b5 update checkpoints for main, test3, and test4 nets

#### Interfaces / RPC

- 0f7c703dd6f358a6c5ef67da497a51d867d2834b Double Spend Proof (dsproof-beta) core code
- eacb361ea33768a53f3a4b3475591d4e464909b1 [Mining] Add -maxgbttime and -maxinitialgbttime command-line options
- 9355e96b1e1c32838fdba416ce38a93513d5339f [rpc] Port validateblocktemplate RPC call
- 1033b0f4e4c920eb0a4ed384e24c72909f7f7e4f Fix argument parsing bug in transaction construction RPC
- 94bff23f7f186e9389d51fdec9f05deda1f5d807 Fix for UB in getblocktemplate
- 362c6db78661b0fe03c29cb6e9dab0f491120ff6 rpc: Add missing convert param
- c8f7ca5d239d1b9205dac02fa6f0b8dc5e578e13 DSProof: Add ZMQ notifications
- bb6a6804af8265f4df085adc819782d9a5cc9d81 DSProof: Add RPC methods
- 906aadc38178a32b405e301ade191781d0b70e20 Wallet: Remove random component of locktime
- b14e26b1081f8733c6c74c0e99dea49421d0388e Update bitcoin_en.ts
- e3ae9f8a3763452e3b023211a6949775c73112cf Fast command-line help for bitcoin-qt without loading Qt
- f7b30b5b5472ebfc7cfef7a1c8642708af2f5e4a Tachyon: Add a `tachyonLatched` atomic bool to CTxMemPool
- 31bf662e4df16e4508cba20ff8e5303d09f823ea Add debug CLI/conf option `-rejectsubversion=`
- a199ff469098a3227a491466e3493f51e3747ea7 mempool & dsproof: Make orphans stickier, make tx removal "orphanize" dsproofs first before removal later
- 58ee973d20a624bb68e7d52d5b72a2bae69bbd05 Tachyon: Allow multiple OP_RETURN outputs in a transaction
- f58576a9c532adc967707968f54628349fa3cb42 Add tentative activation time for the 8th BCH Upgrade (May2022)
- 2d4963e0851ef5a5b78a3f14bf4029cb9cf74271 Push back the "software outdated" warning to May 15, 2022
- f32f72da7106dfcc42219bc27e7190c452496603 Deprecate options related to unconfirmed transaction chain limits
- d7b8b0ed701795465815e842db3399f346784f9f Deprecate height field in getmempoolentry RPC and friends
- b6035f56c0da295e8b0a2e5af167b86515107600 Remove fee and modifiedfee fields from getmempoolentry RPC and friends
- 3b44a7fe1ba2fd41e04f8165f3ee4f116130f821 Remove "blocks since last difficulty change" option from getnetworkhashps RPC
- d04df08bc14916bdf1ef26ed0bc14e91c32d27a2 Increase default mined blocksize to 8MB
- dec29b45466b3842003799c64acb1ff8d4f14857 update ChainTxData for main, test3, and test4 networks
- 1da684ecc42b2dd4dda944b98615d4321f046681 Deprecate the bip125-replaceable field in gettransaction

#### Performance optimizations

- 7f6787150f3fe41997fa5573784e4e0017451364 Limit libevent HTTP workaround to 2.1.5 < version < 2.1.9
- 77576fdc190b1b59cde1cac3f0f448479d696793 UniValue: Eliminate bound checks in JSON parser by making use of terminating null
- 8d5e1f306d10518bbf47a128d99700632202bd58 mempool: Add new index for sorting txs by fee
- d958277a0c5cbbcaa2527a7331d9001d54d30bef Optimize CheckRegularTransaction for larger vin sizes
- d8ea14282665793cf421359ea534bbe8bdae737b mempool: Evict transactions by modified feerate
- 92e5c509aa95069d3125c81b3f976aaab3dc14b4 miner: Remove use of CPFP in CreateNewBlock
- 2eb479f3303ec6336e06f846718d4b2f91ef12be mempool: Removed the ancestor_score index
- 086009e7f1c5e86694bc1ca5c345aca2258226bf mempool: Add topological index, enforce consistency, updated reorg logic
- b6522eb4b8299c39433edf246539882a5bf0ab58 mempool & mining: Use the topological ordering to break ties
- 268e03975a2920a46d0d26a6aa33b13c41ca799c mempool: Remove ancestor/descendant related stats from RPC
- 0ce476c4a251daf9ec21953eb5042125bea99946 mempool: Remove all quadratic stats; add activation logic for tachyon
- 24e2ac46f139fc9c151b0e5bd4d8ba768fdfe3d5 mempool: entry_time index removal
- d408e3b094a2e031460c91ef53b8bce3481139bb Update default assume valid and minimum chain work params prior to Tachyon activation
- 93ad75adec6bfdf67f458e66c831808e1eb2d03a mempool: Slight performance nit when erasing from setEntries

#### GUI

- d87b20bb9a8ccd0f88dbfa3817a1d4797df6816f GUI nit: Display last block hash in Node Window in monospace
- ca0a4bb6571382c05f3b5b0fbef7cc1cdb2dd8ad GUI nit: Do not translate SI time units
- 51c9413e8c451c3d2545730f7a329ee087261989 GUI: Display mempool total tx size alongside memory usage in Node window
- 8d3191456b00e8ba04a1001e830a02e19686083d GUI: Fix icon for About menu entry
- d8e8342c5f6bee53ed8eaa9e550261a9ba457571 GUI: Fix network traffic unit
- 85584b66ce664576e4a293514838e0077b9a71d4 GUI: Further Window menu improvements
- 26c8a2daf9f48b6cdc28186fb4974e5bdaff9171 GUI: Improve UX of various subdivision units
- 9471627f390b89981844408e9ed1ce5191514ab6 GUI: Localise decimal separator in other places
- 2d287b0b3ccb4991bd3bc38aaf15c8d57b77975b GUI: Localise the decimal separator in amounts
- 2f034a62e6dffbde7f0b00f0ae15cdf2168e0941 GUI: Move debug log file button to General
- 7047ed6d70a83cccce03150487854c7a45e25264 GUI: Remove C-style pre-processor defines and other nits
- 8c8d029912177b24d58826322dae4c30e1d1dca3 GUI: Use consistentent labels in Node Window Information tab
- 5435bb466443cda16c2dcd3714da0d6db82f4701 New Crowdin updates
- b8babce1decc920ebe8d64396c68eb2a487b7422 New translations: Chinese Simplified
- bfd7a3f61e4514eafa7b6ea1e12680c2923e8340 New translations: Chinese Traditional
- 548544c50acaf1c516f570f42bed5bbd0136c88b New translations: Dutch
- da61d5d2525e315a9f6a916f25cad791af107b40 New translations: English, United Kingdom
- e3c3f6475e426a1b496420cdaaadc93a57dc00cf New translations: German
- 15fef4f4f07a1141fded2ef77028bff0987a5e2e New translations: Italian
- a2b3984a3dd55165f0f7ccd4d30afff7588b7966 New translations: Polish
- fca389ab3022ef8efdab64608736cc4494ed8aea New translations: Swahili
- 057b057c83d8eb1008147cc2830a94128eecd09a Normalise address input on blur
- 785e5343a2c1f58e3fe8dfc0fd68da7220f97b10 Remove separate "Node window" option from systray menu if wallet is disabled
- 026dace7115fed4c224b49a1daa119be304cd0b8 Remove version info from Node window
- e0b4595c69d35eaebdd666063eeff9c2bd4c241b Update language registrations in bitcoin-qt
- cd2206585979c7d321e1da2fc0f39ef9558ec029 [qa] Update the copyright year in the GUI to 2021
- aa0d5e3ba566df317657d782ac562edd8c9a30ad qt: Fix deprecated warning on newer Qt5 & always localize date format
- d836e896ecc743514a7f484f974988bd3d2e367e qt: Preventing a crash using "window" menu during application start-up
- da167fe801bc81b6f81c05555894676ca2229e9f qt: Use proper "Title Caps" for the Node Window & other windows
- f1cf72a2141eae43ee57b6702c31627b88c2a9d5 ui: Make "Send" and "Receive" actions in systray have proper ellipsis

#### Code quality

- 4e99f6fd8519990708062ac031cf21bfc19f558e Upgrade UniValue code in zmq/zmqrpc.cpp (#51)
- 0fea83247ff92be2d38d85eb2d40f27558fe9fa5 Upgrade UniValue code in core_write.cpp (#51, #89)
- 2ea8a6d428c78f019abf0c80538e1fcb6509ba1a Upgrade UniValue code in rest.cpp (#51)
- b7fb46510cde46fcc9518a3bec7b950ff59bd5e0 UniValue: Replace VBOOL with VFALSE and VTRUE (#51 item 2)
- 3934d493e41665672d78db40a6c0c070cb5959c2 UniValue: Use operator= for setters
- 8571176e7c43f25309a8c97e18396204ee86dc42 UniValue: use C++17 std::string_view and [[nodiscard]] (#51)
- ef76250065d3fad7a2196895a10e3b3d770b6fed UniValue: Refactor getJsonToken, fix bad setNumStr impl, and more
- aa144ae4af9f64bd2ef497908536f26498ffbc8f UniValue: Add a `static_assert` to the `setInt64` private function
- 97cb84d7a6e99ee9a55804442134c1d94b35af06 Remove deprecated UniValue methods
- febc8c09e37163d41b1f4d0572581de4c1356f6a "The Bitcoin developers" with lowercase "d"
- 9809a2f74299b4d08e09f4ffdd7b51d2cf425bb2 Add missing word to error message
- 02ac581b6cfe40f59116a2c86a7eba852dd05d2d Block index: Add an additional sanity check when loading the block index
- 7df431d3a1d427052b0ee1b6f4090e32dd303333 C++17: Replace NODISCARD with [[nodiscard]]
- 8dc1c7da99f0bf3875c94bd6d849136615aa0846 C++17: Replace boost::optional with std::optional
- 5d7407805187b5eaa2a71ac7bf84004ee17c9277 Change text "Bitcoin address" into "Bitcoin Cash address"
- 6d40c0ff5eef5e445a5f1f63b86740416230641f Code improvements (in mempool code)
- 0f8e8da8e65bba305bb8cd0630e419d9fccd0ef9 Code quality: Fix encapsulation of CTxMemPoolEntry::dspId
- de799128279b133a8ee38ead7faeddfd539d8e3d Code quality: Miscellaneous nits and fixups
- 3190772303b6bc52f01de99e506c090a7e23de63 DSProof: Minor fixup to questionable use of incrementOrphans()
- a994e73b63263615832a6ceee86ebe2c61b756f8 DSProof: refactor and fixups; preparation for adding ZMQ
- 18453fc0904e97e339ac2e7b8848c377890604ad Distinguish between singular and plural when verifying wallets
- bb219812c014525fc9d54f700d60a5ceb8a27c22 Explicit QString conversion of QLocale groupSeparator
- f8293eeb6c84a75cfb823de230a1757ad9f69c0f Fix #246
- 011374d4f27bed23d1aefe1dc3e8bbb263c17b82 Fix GCC 8.3.x warning for uint256_tests.cpp
- e469da67d2533af6993635cd9d992c41d47ad5aa Fix compiler warning for cuckoocache_tests.cpp
- 7e130484a9b911b3a0eea24a3897605da732d29f Fix for esoteric clang-7.0.1 crash
- 1c1a76c1d1387007289b5ef26d33ad3e5d48641a Fix self-contradiction in mempool eviction order
- 05997768ebf6c85013d9fa00bb185d618d7bb539 Fix variable shadowing compiler warnings introduced by !1079
- d7a0dddb8b651b0a8c96d8ff191249a986267b03 Minor code improvements
- 1d4694a9620af0f1fb914a448381a29243364e1e Nit: Fix clang-11 warning: "uninitialized variable as const referenece"
- 6cf6c364c63439e1565baac6b92a4414a989d53a Prefer clamping nBlocksTotal to >1 rather than asserting
- f0f7391fe7d035ade7ac5353e81d4bb9f6326813 Preserve negative fee deltas on reorg (!1128 regression)
- 87388d0acd48c62e9c542c8cd0489a09ed4bebea Pruning nodes: Take cs_main for `getblock` and `getblockstats`
- e47461665d21e17637572391d1de22ef7cf84b16 Readability improvements
- 2d255e7106e326bf05a9de9fb857d1491fe799cc Readability: use proper algorithms.
- 7628469b88a11b354e170f85915befc8c1d27498 Refactor `DEFAULT_MAX_GENERATED_BLOCK_SIZE` into chain-specific defaults
- 54e3cf10d6922f087cbfe0201e313e148310130d Refactor the SipHash-based salted hashers to all use common code
- cb03d34719b039d494c1f393a1c0968d94625407 Refactor: Make SeedSpec6 inherit from CService (and ultimately CNetAddr)
- d0813677d8326b83f01617854a1f21adb3881190 Remove C macro ARRAYLEN in favor of C++17's std::size
- 1294303bd1a38e2a752162c8d08f885e4a1b0850 Remove comment about replace-by-fee
- b6bbbda6757848e84fd9e116f9b7764739ff77ca Rename OP_INVALIDOPCODE to drop the "OP" and remove non-opcodes
- c12484e5eada2c7aef7fbffb7b8f405bdd5121b7 Replace magic numbers with constants
- b2099b6f43c7632ec6d8737e05d396f35d17e7b5 [The unit tests for the `DspIdPtr` class were separated into another file]
- 79fff113963233c775e9a3fa411c019356014076 [qa] Add C++ linter detection of C++17 features we want to avoid
- c9f8c6eed4dfa499cd8e93fc53e7fd6114602224 [qa] Fix for function `hash256` appearing twice in test framework
- a9cdff979ba69078a584714486ef699f786614fb [qa] Suppress compiler warning about unused return value
- 30f1f1f90acf14405cfaf652bcea6c5b36eb2882 bitcoin-qt: Remove ifdef i386 stuff in the version string builder
- a98277276cf1d1b012501c5a9e5bc380a820277d lint: Add circular dependency
- 76d33bec17a068b30f2213af89493b6ebf5f01e7 lint: Add new circular dependencies
- 7e814a3ce98239af5623e320d2a4c0ddc63e3ac3 lint: Fix lint-python errors
- ba4461b7a8f744162bda8fb5e0dde4061d45b2e7 lint: Fix lint-python-mutable-default-parameters errors
- 56c4de3727b5f52c874ffd1b61a3c77db1d92697 lint: Fix lint-python-utf8-encoding errors
- 06e61d4551cddb433394caf83703c00fb895f921 mempool: ModifiedFeeRate getter for mempool entry
- 707b1192a5f3f9065326a69bc8b8e9a6f0659d1c mempool: Save & restore mempool entry acceptance height on reorg
- e352240b56e3819118de10d664f90340130558fc miner: Add fPrintPriority member variable
- fa8a25bc897d3e840720cced32e7867af38ca57c miner: Remove mentions of 'package' in names
- 443e35e4bc7ddce32747ee6553139844435c3b90 qa: Use .format instead of %
- 33c57c84acc8bc348f9c95d7859eee72e578d6bc qt: Fix usage of QDateTime::fromSecsSinceEpoch
- dbed589142bae4d2a97e585ad12fae6b3ee78757 refactor: Allow alternative mempool batch updates
- 4ca1f9193eb2c4a395472fb970d8b4d051bf1768 uint256: Modernize code to use `noexcept` and `constexpr` where possible

#### Documentation updates

- 9451c5bf18cf37bd6e6793b4d660cd5191e9589f Doc bug: fix outdated MacOS SDK download info
- 3fbdb528dcaf8186e8f3b497c1fa656a8425a27e Doc nit: remove table of contents
- ccd620b4aa0e4962a469eccd7a901568a1e23211 Document May 15th 2021 network upgrade
- a34314d4dd8cb87d5c9ca59dbd1626c4ce309a20 Document implementation of BIP158
- 91b120b5ed4941e8d546b953803fe0a2eb1ba51f Document implementation of BIP340
- 16a3e8c7f6100386ded4b8458bccfa1a374515df Documentation: Clarify what version 0.14.1 was
- 63cda98ac8e2f1986f0293fd5f1b0601edcde848 Link DSProof spec on upgradespecs.bitcoincashnode.org
- 0b071607f0b615b7eed5397ef4404cb1d362fe78 New translation process based on Crowdin
- a1edf52d9886dd083cfa85dc25f6f8abd69d8861 Remove table of contents
- ab3c74aa9055f72ab6843b7a80c301ee0a14f20b Show licence in documentation
- 2af21035b972e301e692aefcc0984da17c1388f3 Update copyright year in COPYING to 2021
- 16102f7d298c629e5589dcfc8b1b5af6f275164e [DOC] Clear up text, and remove link to bitcoin.it
- a508596c33f40cb91f319555344b72603785f74c [DOC] Delete reference to previously deleted directory
- f3d0fc908402d9e6c13c073f25e0aa8788c53f96 [DOC] Line length in /doc/*.md
- 6f969adc9e411b35cda6b81c1369903a53a4a87a [DOC] Markdown lists and headers
- 47f81c66fa798ef07ad5423e787d8b125846e607 [DOC] Markdown lists, lists and more lists.
- 10ce294d3646b1934dc239f4e1b81f0ff74a53b6 [DOC] Reduce markdown lint warnings
- 8d3b06979e1b8accfac70343600a3c992f6f0f0e [DOC] Remove bare URL markdown warnings
- 66b958d87c152839ad3ba4c4b5b94a919d431dbd [DOC] Remove more line length warnings (MD013)
- 4e87a1055c2e96caf889a9190617f0614e74a015 [DOC] fix markdown list warnings MD007 and MD029
- 41d28147557212741c5424429b586086bad0dbe3 [doc] Add a useful link about writing good git commit messages
- 30aa62105844730460e997ddd39ece0d8f54aa60 [doc] Add detail to Mac OSX depends build description
- 4f7e87a00509aa726e48ff067a24017d9d3caa5c [doc] Add some explanation for MR 746 which was missing in relnotes of 22.2.0
- 58851d0ebe970830c73ccbc3b89c04def9b44c3d [doc] Bump minimum required Python version to 3.6
- 8aff361bc96481272281f4fc8a8d30806921b381 [doc] Double Spend Proof (dsproof-beta) implementation notes etc
- 1704c3163c79987a9ab9f2d0fb44561e74cb5b8e [doc] Fix Bitcoin Core reference in translation strings policy document
- f7ddd4b8e0daa41e95d0ba36ee49052d68a67c77 [doc] Fix linkage between gitian build docs; update example versions
- 80d669510ce236aea5d6bddb82f8a139a1018c2b [doc] Reduce markdown lint errors
- ba02c14e692663ba40ce9068d2dd0d1639510388 [doc] document scipy as a functional test dependency
- ec7f11c0f6d53440f26d90dad48f2f9385aac4f8 [qa] Add 'mining' and 'wallet' labels
- f5c003d8e72b0285f79e2a295d9b79b616f36dfd [qa] Add two-approvals maintainer rule for critical code
- 8d81e753ce1ee5708ab81a32a42341c616dc3c3f brew install qt installs Qt6 right now
- ce0205e9e4c8dd3009cf8b2b0d36c175423b335a doc: Document linting
- 947b03dc1c98e487a6ecf14a4ab885549b4b0b87 doc: Expectations of contributors and maintainers
- b485d3c8de1b5d73734ef96e06cc3edc9df42991 docs: Fixed typo in benchmarking.md
- 419fc4af54bca7728f0045f01982ad438f16d3d7 fix list warnings
- 386e5af79393f8df1f0426250594a7a9d5627caa ninja translate
- f71cd1b5a95cf2dda2ce1d6b2ad9d1bfcdbd4acd two files
- c9cb1abd2d22ead3bf44a8b4a4af5f31a99921a4 ABC:D8758(partial) Document implementation of BIP158

#### Build / general

- 1a0ac9a7daf633f4f0404cce1cb605d97ba8da5d Add 'lint-yaml' linter. Fix lint errors in existing yaml files.
- cf7106114d65c4f661a4fede71a860490e99f721 Add jemalloc support
- 5ced972cc559a1fbd61d073f302d7c571a078dc5 Add the SuperFences extension to MkDocs
- 78f9989a549374fe878e6a4068f0b10f9ced8038 Create ninja target for building Markdown documentation
- 3b16ec4ad373c2bebab9dfbe124a9c16dc283103 Enable 'lint-format-strings' linter
- cf03d7894ac616b20e68e8b3fa2f51fcb69c5475 Enable 'lint-tests' linter
- e7b14eecec46ffa4c479fb270d490fc2771b69ce Merge manpage generation into the build system
- abf734ed5dbc7b7392c3e8479660c87186f9b510 [qa] Fix bench-bitcoin target
- 932a9de88bbcb6aab247beae2c4282240ea07f59 build: Add EXCLUDE_FUNCTIONAL_TESTS build option
- f76ddca764cdea20f7e80051ff848b133a7552f5 build: Add a translate target
- 2f826a5a53da4bb6479683eabf5ba711eaf59344 build: Add linter targets to CMake
- 76d33bec17a068b30f2213af89493b6ebf5f01e7 lint: Add new circular dependencies
- f1ac5d3f8d81744a4a24b4f00e261620d62ce3df lint: Check locale on template shell scripts
- 6802fad361fca2f0bfc8b836959d458fa2cca34f lint: Enable check-rpc-mappings.py linter
- 3b6943e1bd24b369cbc685b26c38a8ac64df7a08 lint: Enable linter lint-python-format.py
- 4a64ad2b2440cb1be6a84faf6e53bfb9f10880f0 lint: Enable python linters
- 80960d5cefd00427a1b1bd0a7f70b09f225b2a2f linter: Add cpp include linter
- f4ea392d60f3bb18e48c4d80838743e948482cf9 ABC:D6311 [CMAKE] Add a facility to add flag groups and use it for -Wformat-*
- 287215f4e614fdf9c299ae99dd3372fde706248f ABC:D6545 [CMAKE] Fail early if a lib header is missing, remove garbage in version
- db17bca277e205ef7f41a0a97be0f641a376e559 ABC:D6960 [CMAKE] Optionally install bench_bitcoin
- 36532250153da10e7af75182e5e0f04485cf2671 ABC:D7024 [CMAKE] Add the test suite to the log name

#### Build / Linux

- 6414b0aa92224e6e49249753ea6d9c0da03997bb [build] Add batchupdater files to autoconf build
- 2cce42c05512dc58a6da21feef7f50081c823064 Update _COPYRIGHT_YEAR in configure.ac to 2021
- dabc9bbcced4d04e2b4eb6995166c7f64d39436d autoconf build: Fix broken build from latest commits
- 78d7dd9fd074d4bfacf5498c8ac684f1c76a2119 Create ninja target for building HTML documentation with mkdocs

#### Build / Windows


#### Build / MacOSX

None.

#### Tests / test framework

- c9cd304942b866b6ed64839e6ee3f2fb46b0c933 Added StdHashWrapper, also added some tests
- bac0b6447abfd51f65510ee78a8763cd2ca76cd6 Double Spend Proof (dsproof-beta) deserialization fuzzer
- 54466c7e195b63dd5b869feb47abee6a55bbae63 Double Spend Proof (dsproof-beta) functional test + test framework adaptations
- 751be1ebf88ebccda408226b502b108a3140fc57 Double Spend Proof (dsproof-beta) unit tests
- a0262c9d2d2f95b5c485b77579c78f9850172910 Mininode: Add testnet4 and scalenet network magic
- 83dbe4a6fa94f826f1d51f567e1f016da9a6e183 Mininode: Speed up big message reception significantly
- 777c04a6bdab87955ade3494f1fa20bf7893d4a8 Retroactively enable Tachyon on all test networks
- add245a23f103a621683bbf44eff2901b7b9c56a [qa] Add RPC HTTP pipelining test
- 53bdb7819eae64d9591747334edacd16cf8562c5 [qa] Temporarily evict frequently failing getblocktemplate tests from aarch64 functional test job
- 3d2324ad210c2b2bf61778736f1827455d500d72 [qa] allow bchn test name prefix and dashes
- 3f0c99d63294e648bc5a086ea3af9b0c4a95ce25 [qa] fix unreliable getblocktemplate(light) tests
- 6492f06533470f7ddddfd2edae66a5354556b733 [test] Add a functional test that transacts with ANYONECANPAY hash type
- f3a8710f04b7f12eb5c6d1e60f766ae5499e8d21 [tests] Additional tests to verify ancestor/descendant counting and limit behavior
- 826b8c35160e245cd3a38ddbaee8b3530cb65091 test: Add option to pass extra bitcoind arguments
- 5334436c6e7792f68920a6f49198cbf131231161 test: fix return type in bchn-rpc-pipelining
- decf354a4cbf1bdd8f494e5825e938c51f98de38 tests: Fix the failing rpc-getblocktemplate-timing test

#### Benchmarks

- 72d7d20891844ef0e8968f0d2e8441a4a01de2e3 Bench: Add mempool eviction benchmark for chained tx's
- ae7cc171480be683320a7e4f0878d232b7c872ca Bench: add -debug option to bench_bitcoin
- fd0a7dadecddd0ea108291e39378763343957bd0 Double Spend Proof (dsproof-beta) benchmarks
- f1ac02cc56c2b6992ac2b663f601e42bc558b756 bench: Add benchmarks of CheckRegularTransaction
- 21faeb6ceec80ea2e7b7aa64142e912b3eee5a46 bench: Adjust block generation benchmarks
- 3f9634fefd0c5fc7ade029f3c763ae61aae06902 bench: CreateNewBlock with long tx chains
- 6386f146c7bdee3f308cce94bc5fda80853fc868 bench: Mempool acceptance for chained transactions
- 9e2e70e779bf8244f9ee65f24e7a2b505b6448d9 bench: Reorg benchmarks without mempool removal
- 072b3d0787498d30047a8e0c3611ab071326342e bench: Reorgs of blocks with long tx chains
- c8e9fde3f0331ce7b7eac3a145e9f3202acb7d02 util: Added functions to help with profiling code (more precise time & more)

#### Seeds / seeder software

- dd5ff6dc6e113e767c875b0f05a959ee0b669653 Add seeder: bchseed.c3-soft.com
- 8f6b5f71d7df8e67e6c19f22b009886fcabeb423 Seeder: Add Flowee's testnet4 seeder
- c3fe092dfadccccb1fd7026462a168a4c6df6ab6 Seeder: Fix getaddr interval to actually query address lists once a day
- b332633585bc6f5cdc8b54f5474246e634a164a7 Seeder: Fix nodes discovered through seeds having zero service flags
- 7ced6725285a702a1350b515fa6f625c4d7a2fcc Seeder: Fix two potential crash bugs plus some code nits
- 41c2196e77544bde8125bdcd4a8cab8a4f65bb87 Seeder: Seed the database with fixed seed IPs
- 6eaf1683bd5e95ad9ac8b7b67838f3e6969de9f6 Seeder: Verify that nodes are on the correct chain
- a47f73d1ae460295e9994aee6384cdf7fb1155e9 Update mainnet seeds
- 491929eb1527ab0b060e7d8254bfaaf6722fbcb4 Update testnet seeds
- 0b41baf0195973caedf3533f50b37b0d46d1e6a4 [backport] Seeder: Set BIP37 fRelayTxs flag to false

#### Maintainer tools

- 9866c59fa0b181bc0891f159bda20feb50bf7338 Remove unused and Core specific script

#### Infrastructure

- 172b4fce3f25772ac748040966f659d93d034112 Crowdin configuration file
- 2e77868011ffc703e251f0bb988a298627d518b8 Fix Crowdin configuration file
- 1e5d72313cb2ee095d773b3dd5d1eda4e6639e5c Add BigBlockIfTrue release signing key
- 30a3eb561d9a305d7296e758edc5b537611bbd8f [qa] Update freetrader public key (expiry extension to 2023-04-08)

#### Cleanup

- 5112ec4687ee385f207242993ff47fcb74508c01 [qa] Nuke obsolete test framework self-tests
- b2cf1b554405e3c0fb186446fa09fe5114a21e59 [qa] Remove boost/optional.hpp from expected dependencies
- 568c2e53ad39ac905f8774ad2fc0826e628a87ea Remove unused idea
- 43adbc8a41b3bd1634ac83ecadbbcc9bbea735b4 Remove GUI settings migration from Bitcoin ABC

#### Continuous Integration (GitLab CI)

- 10c3507c32bfcd57067b96f1bc09ab1b83e86c7a [ci] Skip cloning of LFS files in static-checks jobs
- 9af7e9681a10f4f56f511a2fa263f156ae3b4fbf ci: Add debug builds
- b1dabdbbcf6ffe6934f43e6065bb18299427b07d ci: Add job for running check-lint
- 8e77c0ca4cfc7a1ae842c919c6b42482562740e1 ci: Exclude bchn-rpc-getblocktemplate-sigops from aarch64
- 82ee7d137a34c04e1a34e30df301bb1d8ea2f6e7 ci: Fix build lint artifact path
- fe5c9e38cb69e30954e0994fe1f82fb5e6513d6e ci: Reduce ccache size and DRY on common steps

#### Backports

- aecbde56fa2e05c1b61fcb8f3e88601ecdc27e70 ABC:D5809,Core PR#14987(partial) Pass rpc/abc RPC Results and Examples to RPCHelpMan
- d1bf6d0d717b995e0e117919ca7a1cbe55be073e ABC:D5815,Core PR#14987(partial) Pass rpc/server RPC results and examples to RPCHelpMan
- abf3302a1583b3442796f4a016239c36f365caec ABC:D5818,Core PR#14987(partial) Pass zmq RPC results and examples to RPCHelpMan
- c4f396d8ad7fd49e8f9a5eaa7a0613ec6bf57e3d ABC:D5822,Core PR#14987 Pass rpc/mining RPC results and examples to RPCHelpMan
- 383becdcbd99357cc1f4651c7b2d74a40ac76c56 ABC:D5838,Core PR#14987(partial) Pass rpc/net RPC Results and Examples to RPCHelpMan
- d30c9ba33cbf7d478e517476d5ec51691dc87d4e ABC:D5877 [CMAKE] Use the crosscompiling emulator to run the tests
- 66e2bc85e7ab3bf717b31f93d3addb977d2084a6 ABC:D6056 [DEPENDS] Remove the facilities for building win32
- a0b24b7586d6382fe78fe7bce3b00fd51c835c8e ABC:D6108,Core PR#16839 [backport] scripted-diff: Rename InitInterfaces to NodeContext
- bb780786957784ef4df510fda95cbb437c7010bf ABC:D6109,Core PR#16839 [backport] MOVEONLY: Move NodeContext struct to node/context.h
- 44813cf8a7e07a3c656f7af6a48600546df8e03f ABC:D6283 [backport] Seeder: Request headers from new connections
- dd9c3380fbc0527776ec8fcd317d3dea2204c3dc ABC:D6462,Core PR#17931 Merge #17931: test: Fix p2p_invalid_messages failing in Python 3.8 because of warning
- 37f426bac424d2a8b4df703d9834f5b5fc35ab69 ABC:D7441 [CMAKE] Fix issues when looking for libraries installed with homebrew
- 459b3bb5d02a8deed9456ff9087f3c5b3e4e88e1 ABC:D7892,Core PR#14573,#16514 qt: Add Window menu
- b515ce60ff65562d4e14183dc60f439531a95a19 ABC:D7894,Core PR#14979 [Qt] Restore < Qt5.6 compatibility for addAction
- e282d7c8b02561a33466647172eec97ae5e49f6b ABC:D7895,Core PR#18549 qt: Fix Window -> Minimize menu item on linux
- 1a1ac4e5a032e03fa3ffe05af996b81a8b325965 ABC:D7917,Core PR#14879 [backport#14879]Add warning messages to the debug window
- c54452be37a1e964297eb2599dd76570f2c6e612 ABC:D7930,Core PR16735 GUI: Remove unused menu items for Windows and Linux
- 0a9ec4feea5f553f85b795dc36e477f5624371c5 ABC:D7971 [secp256k1] Enable endomorphism by default
- 3c10dd6534d91d72a8a76c327414aa7399aa50c6 ABC:D8123,Core PR#17809 rpc: Move OuterType enum to header
- 401d66d2796aad8bf89e6307fc15a1f2643e7dc3 ABC:D8146,Core PR#14383,#15023 Clean systray icon menu for -disablewallet mode
- e8022382e1180988c6e6f24c96b88b58e885e740 ABC:D8148,Core PR#15756 gui: Add shortcuts for tab tools
- 195296fe207d2d78b27ef6776d1b5e24dacbff63 ABC:D8493,Core PR#18591 Switch to using C++17
- cf5a10a0ce990e230c7aeb6e420ab5e9d7400f22 ABC:D8523,Core PR#17096 Merge #17096: gui: rename debug window
- 3ab3c55f06040c84cadf5d19ebf3a5cc3d47c786 ABC:D8546,Core PR#14594 [backport#14594] qt: Fix minimized window bug on Linux
- 5d83d0eab6eceb5e38781c60a2a9d02b5a316e3d ABC:D8623 [backport] Seeder: Use netmagic from chainparams instead of a cached global
- 64eac60b4d560353e54df53af57aff6b61f96fab ABC:D8624 [backport] Seeder: Add a test to check outgoing messages in response to VERACK
- 37261c6d4fc4af498c93742a9f401258e2e01743 ABC:D8835,Core PR#16902 Benchmark script verification with 100 nested IFs
- bea1a7fab6795a6d7081d3ddd499bf8490ec4c28 ABC:D8836,Core PR#16902 [refactor] interpreter: define interface for vfExec
- 30313fdb51052446af8b08acb03c9fe841807abe ABC:D8837,Core PR#16902 Implement O(1) OP_IF/NOTIF/ELSE/ENDIF logic
- 52c26df3863111ff630241e1b9813c37e1a4be11 ABC:D8857,Core PR#15283 Fix UB with bench on genesis block
- 43ddf9477086f407db096a28d3d80a7703e82934 ABC:D8951 Fix typo in Sighash tests
- 333436177e9e5b457cde82bb03c1e32276dfc7d0 ABC:D8992,Core PR#18754 [backport#18754] bench: add CAddrMan benchmarks
- 511a1e7d098b1576b1e4e44805cc1b17ecc699c0 ABC:D8998,Core PR#18769 qt: remove todo bug fix for old versions of Qt
- be0453753c02e7027e57661059f1f51fb4d7a1e2 ABC:D9094,Core PR#18931 net: use CMessageHeader::HEADER_SIZE, add missing include
- 27206031e03fb59502ec7b1ced37de883ec75faa BCHUnlimited MR2401 [backport] Transaction viewer URL validation
- d60b32074098d50b04e408c1304dd6f6120654ed Core PR#11835 practicalswift - Add Travis check for unused Python imports
- c36b720d009f1ab1c3900750e05c1f17412e564d Core PR#11878 practicalswift - Add Travis check for duplicate includes
- ea04bf786263eb0c933648bce43627c0de4d84ef Core PR#12284 practicalswift - Enable flake8 warning F841 ("local variable 'foo' is assigned to but never used")
- 0b9207efbe9403225480284298fccc3a2652e895 Core PR#12295 practicalswift - Enable flake8 warning for "list comprehension redefines 'foo' from line N" (F812)
- a9d0ebc26207b4771b7c240ca0c516debd330985 Core PR#12295 practicalswift - Enable flake8 warnings for all currently non-violated rules
- fad0fc3c9a9759dfb2bb1bdf1aaa5e1d08c0ab9c Core PR#12933 MarcoFalke - Refine travis check for duplicate includes
- 643aad17faf104510ba123b596676256f26549c2 Core PR#12987 practicalswift - Enable additional flake8 rules
- 68400d8b9675d00ea7126b432e208c1e52658c2e Core PR#13054 practicalswift - tests: Use explicit imports
- 0d31ef4762f5a1428a57439d26551a99f15ddc2e Core PR#13210 John Bampton - Enable W191 and W291 flake8 checks. Remove trailing whitespace from Python files. Convert tabs to spaces.
- 506c5785fbf8dfaf713e06e53b23ce589ac29518 Core PR#13214 practicalswift - Enable Travis checking for two Python linting rules we are currently not violating
- 6d10f43738d58bf623975e3124fd5735aac7d3e1 Core PR#13230 practicalswift - Enforce the use of bracket syntax includes ("#include <foo.h>")
- fa3c910bfeab00703c947c5200a64c21225b50ef Core PR#13281 MarcoFalke - test: Move linters to test/lint, add readme
- fa3c910bfeab00703c947c5200a64c21225b50ef Core PR#13281 MarcoFalke - test: Move linters to test/lint, add readme
- 9d6c9dbb88593dea995072ba812f115a51ea2b4b Core PR#13301 Ben Woosley - lint: Add linter to error on #include <*.cpp>
- 81bbd32a2c755482c6e8ef049a59de672715b545 Core PR#13385 practicalswift - build: Guard against accidental introduction of new Boost dependencies
- c8176b3cc7556d7bcec39a55ae4d6ba16453baaa Core PR#13448 practicalswift - Add linter: Make sure we explicitly open all text files using UTF-8 or ASCII encoding in Python
- 6b31118468a7d378b5a2e45c7519ff9b49832d58 Core PR#13454 Add linter: Make sure all shell scripts opt out of locale dependence using "export LC_ALL=C"
- 3352da8da1243c03fc83ba678d2f5d193bd5a0c2 Core PR#13454 practicalswift - Add "export LC_ALL=C" to all shell scripts
- f447a0a7079619f0d650084df192781cca9fd826 Core PR#13482 Chun Kuan Lee - Remove program options from build system
- 7b23e6e13f042aa06741dbb7127eb291a61752a7 Core PR#13494 practicalswift - Follow-up to #13454: Fix broken build by exporting LC_ALL=C
- 000000035b20402dea3e8168165cd4eefdc97539 Core PR#13510 DesWurstes - Obsolete #!/bin/bash shebang
- 962d8eed5bdbe62b9926f01cb85bdce9d435d3d6 Core PR#13545 practicalswift - Remove boost dependency (boost/assign/std/vector.hpp)
- 854c85ae904075503215f94d6329d38d2d8dfb6b Core PR#13649 James O'Beirne - test: allow arguments to be forwarded to flake8 in lint-python.sh
- e3245f2e7b6f98cda38a3806da854f7d513fec2f Core PR#13656 251 - Removes Boost predicate.hpp dependency
- b193d5a443bfd994936ad21b807b2bb37756ef2c Core PR#13671 251 - Removes the Boost case_conv.hpp dependency.
- 01f5955382af8ba73adaa145085c94b6470bba89 Core PR#13686 [backport] ZMQ: Small cleanups in the ZMQ code
- 5f019d5354cb12e343ea4bb88da04fbe0e98f102 Core PR#13726 251 - Removes the boost/algorithm/string/join dependency
- 1c5d22585384c8bb05a27a04eab5c57b31d623fb Core PR#13734 Chun Kuan Lee - Drop boost::scoped_array
- cb53b825c26af6e628ba88d72b2000e75bedbbc6 Core PR#13743 Chun Kuan Lee - scripted-diff: Replace boost::bind with std::bind
- 1661a472b8245eb4588fedbf19c9ed07a41e7602 Core PR#13862 Chun Kuan Lee - add unicode compatible file_lock for Windows
- 2d6ec0486bde9641e0a24aeb59d84a96dd32c5a7 Core PR#13863 use export LC_ALL=C.UTF-8
- 2c3eade704f63b360926de9e975ce80143781679 Core PR#13877 Chun Kuan Lee - Make fs::path::string() always return utf-8 string
- 55fbd5a8deecd466b44366fea577db29ad338da0 Core PR#14088 Add regression test: Don't assert(...) with side effects
- 604f836815db301683eae26d7abc8514c396327f Core PR#14115 macOS fix: Work around empty (sub)expression error when using BSD grep
- 341f7c7b0e77edcc02cb3429fb9a3d49745332cc Core PR#14115 practicalswift - macOS fix: Check for correct version of flake8 to avoid spurious warnings. The brew installed flake8 version is Python 2 based and does not work.
- 5d62dcf9cfb5c0b2511c10667ed47ec3b3610d72 Core PR#14128 Chun Kuan Lee - lint: Make sure we read the command line inputs using utf-8 decoding in python
- ef95a78f6ea43c61f58744ff923febfe62c9029f Core PR#14796 rpc: Pass argument descriptions to RPCHelpMan
- c9ba253f4f5d675d7736d24c1167229d0898ef1a Core PR#14903 Daniel Ingram - Add E711 to flake8 check
- 948d8f4f10c31220ba4b6779cc862e2b6a0af5f6 Core PR#15219 Ben Woosley - lint: Enable python linters via an array
- 838920704ad90a71cf288b700052503db8abb17e Core PR#15257 Ben Woosley - lint: Disable flake8 W504 warning
- 3c84d85f7d218fa27e9343c5cd1a55e519218980 Core PR#15382 Sjors Provoost - [build] msvc: add boost::process
- 3c5254a820c892b448dfb42991f6109a032a3730 Core PR#16124 practicalswift - Limit Python linting to files in the repo
- 37577d4f3f80459bc9467989f3867f6dcbf2a4ff Core PR#16291 gui: Stop translating PACKAGE_NAME
- 490da639cbd48ce0dc438abbfc89ab796391cb2a Core PR#16768 Kristaps Kaupe - Make lint-includes.sh work from any directory
- 80c9e66ab84f8cecc2bf2eebf508a5aad8911246 Core PR#17353 Hennadii Stepanov - build: Remove install command samples
- 3a037d0067c2c12a1c2c800fb85613a0a2911253 Core PR#17398 Wladimir J. van der Laan - test: Add crc32c exception to various linters and generation scripts
- 3a037d0067c2c12a1c2c800fb85613a0a2911253 Core PR#17398 Wladimir J. van der Laan - test: Add crc32c exception to various linters and generation scripts
- aaaaad6ac95b402fe18d019d67897ced6b316ee0 Core PR#17829 MarcoFalke - scripted-diff: Bump copyright of files changed in 2019
- aaaaad6ac95b402fe18d019d67897ced6b316ee0 Core PR#17829 MarcoFalke - scripted-diff: Bump copyright of files changed in 2019
- bd7e530f010d43816bb05d6f1590d1cd36cdaa2c Core PR#18210 Kiminuo - This PR adds initial support for type hints checking in python scripts.
- d0ebd93270758ea97ea956b8821e17a2d001ea94 Core PR#18234 Anthony Towns - scheduler: switch from boost to std
- fa488f131fd4f5bab0d01376c5a5013306f1abcd Core PR#18673 MarcoFalke - scripted-diff: Bump copyright headers
- fa488f131fd4f5bab0d01376c5a5013306f1abcd Core PR#18673 MarcoFalke - scripted-diff: Bump copyright headers
- bb6fcc75d1ec94b733d1477c816351c50be5faf9 Core PR#18710 Hennadii Stepanov - refactor: Drop boost::thread stuff in CCheckQueue
- e0f5f6f2e4eddc94c0cac1ec0df145081a203149 Core PR#18752 [backport] test: Fix intermittent error in mempool_reorg
- 89f9fef1f71dfeff4baa59bc42bc9049a46d911b Core PR#18758 Hennadii Stepanov - refactor: Specify boost/thread/thread.hpp explicitly
- 13639e05944bfda025b7fe983dc315ba0e13e65d Core PR#18873 [backport] test: Fix intermittent sync_blocks failures
- 7dda912e1c28b02723c9f24fa6c4e9003d928978 Core PR#19172 Hennadii Stepanov - test: Do not swallow flake8 exit code
- f1a0314c537791f202dfb7c1209f0e04ba7988c3 Core PR#19256 Cory Fields - gui: change combiner for signals to optional_last_value
- 39d526bde48d98af4fa27906e85db0399b6aa8b1 Core PR#19348 Duncan Dean - test: Bump linter versions
- 9637ff39f8e2de9f3f3d7b1abed53ecd41388426 Core PR#19504 [tests] Recommend f-strings for formatting, update feature_block to use them
- 39ab7ecdfe94a9ea3d16c88475576f75030ff7d5 Core PR#19844 lint: add C++ code linter
- b6121edf70a8d50fd16ddbba0c3168e5e49bfc2e Core PR#20346 Tyler Chambers - swapped "is" for "==" in literal comparison
- faa8f68943615785a2855676cf96e0e96f3cc6bd Core PR#20480 MarcoFalke - Replace boost::variant with std::variant
- fa4435e22f78f632a455016ce00a357009aac059 Core PR#20671 MarcoFalke - Replace boost::optional with std::optional
- dc8be12510c2fd5a809d9a82d2c14b464b5e5a3f Core PR#21016 fanquake - refactor: remove boost::thread_group usage
- e99db77a6e73996d33d7108f8336938dd57037a7 Core PR#21059 Hennadii Stepanov - Drop boost/preprocessor dependencies
- 7097add83c8596f81be9edd66971ffd2486357eb Core PR#21064 fanquake - refactor: replace Boost shared_mutex with std shared_mutex in sigcache
- 0ba89ddc9717357d6f21d2bd77d0cd5cccf2e752 Core:(various PRs listed separately): lint: Add lint-python and lint-python-utf8-encoding
- 5ba70316d529ad0613f632257175f61279e5f896 Core:PR#16726  lint: Catch use of [] or {} as default parameter values in Python functions
- 594924b1969daad4398965d909af3764c07fe1e6 Dash PR#3672,Core PR#3685 [QT] Add last block hash to debug ui: Trivial addition to display last block hash next to last block time
