# Release Notes for Bitcoin Cash Node version 22.0.0

Bitcoin Cash Node version 22.0.0 is now available from:

  <https://bitcoincashnode.org>


## Overview

This is a major release of Bitcoin Cash Node that implements the
[November 15, 2020 Network Upgrade](https://upgradespecs.bitcoincashnode.org/2020-11-15-upgrade/).
This will upgrade the difficulty targeting used in Bitcoin Cash to a
commonly agreed new algorithm called ASERT.

Additionally, this version contains many corrections and improvements.

User who are running any of our previous releases (0.21.x) are urged to
upgrade to v22.0.0 well ahead of November 2020.


## Usage recommendations

The update to Bitcoin Cash Node 22.0.0 is required for the November 15, 2020
Bitcoin Cash network upgrade.


## Semantic version numbering

As of version 22.0.0, Bitcoin Cash Node uses
[Semantic Versioning](https://semver.org/) for its version numbers.
Hence our version numbers no longer start with a zero.

Semantic versioning makes it easy to tell from the change in version
number what are the impacts on interfaces and backward compatibility:

- A major version (first number) change indicates that an interface changed
in a way that makes the new software incompatible with older releases.

- A minor version change indicates added functionality that is backwards
compatible.

- A patch version (third number) change indicates that a new release only
contains bug fixes which are backward compatible.


## Network changes

### Changes to automatic banning

Automatic banning of peers for bad behavior has been slightly altered:

- Automatic bans are now referred to as "discouraged" in log output, as
  they're not (and weren't even before) strictly banned: incoming connections
  are still allowed from them (as was the case before this change), but they're
  preferred for eviction.

- Automatic bans will no longer time-out automatically after 24 hours.
  Depending on traffic from other peers, automatic bans may time-out at an
  indeterminate time.

- Automatic bans will no longer be persisted across restarts. Only manual bans
  will be persisted.

- Automatic bans will no longer be returned by the `listbanned` RPC.

- Automatic bans can no longer be lifted with the `setban remove` RPC command.
  If you need to remove an automatic ban, you must clear all automatic bans with
  the `clearbanned false true` RPC command, or restart the software to clear
  automatic bans.

- All extant automatic bans ("node misbehaving") that are currently stored in the
  node's `banlist.dat` file will be converted into "manual bans" and will expire
  within 24 hours after first running this version of BCHN.


### Regtest network now requires standard transactions by default

The regression test chain, that can be enabled by the `-regtest` command line
flag, now requires transactions to not violate standard policy by default.
Making the default the same as for mainnet, makes it easier to test mainnet
behavior on regtest. Be reminded that the testnet still allows non-standard
txs by default and that the policy can be locally adjusted with the
`-acceptnonstdtxn` command line flag for both test chains.


### Graceful expiration of this version on May 15, 2021

A mechanism has been added to this version such that it will gracefully
expire on May 15, 2021, at the time of the network upgrade which is
tentatively scheduled to occur then. Once this software expires, the RPC
subsystem will disallow RPC commands. This feature can be disabled with
the `-expire=0` option. Furthermore, the date of expiration can be altered
with the `-tachyonactivationtime=<n>` option.

This feature has been added as a safety measure to prevent this version of
the node software from mining or otherwise transacting on an incompatible
chain, should an upgrade take place on May 15th, 2021. This version will begin
to warn via RPC "warnings", via a GUI message, and via periodic messages to the
log starting 30 days prior to May 15th, 2021.

Once the future consensus rules of the May 15th, 2021 upgrade to the Bitcoin
Cash network have been determined, a new version of Bitcoin Cash Node will be
made available well in advance of May 15th, 2021. It is recommended that all
users of Bitcoin Cash Node update their nodes at that time so as to ensure
uninterrupted operation.

*Related configuration options:*

- `-expire`: Specify `expire=0` in the configuration file or `-expire=0`
on the CLI to disable the aforementioned graceful expiration mechanism
(default: 1).

- `-tachyonactivationtime=<n>`: This option controls when the expiration
mechanism (if enabled) will expire the node and disable RPC (<n> seconds since
epoch, default: 1621080000).


## Deprecated functionality

### Autotools build system

The autotools build system (`autogen`, `configure`, ...) is deprecated and
will be removed in a future release. CMake is the replacement build system,
look at the documentation for the build instructions. To continue using the
autotools build system, pass the --enable-deprecated-build-system flag to
`configure`.

### CashAddr enabled by default in bitcoin-tx

The bitcoin-tx tool has fully supported CashAddr since v0.21.2. CashAddr in JSON
output was disabled by default, but relying on this default was deprecated.
Version 22.0.0 now changes the default to enabled. Specify `-usecashaddr=0` to
retain the old behavior.


## Removed functionality

### `medianfeerate` field removed from `getblockstats`

The `medianfeerate` field in `getblockstats` output has been removed. The 50th
percentile from the `feerate_percentiles` array should be used instead.

### `-datacarrier` removed

The bitcoind/bitcoin-qt option `-datacarrier` was deprecated in v0.21.2 and has
now been removed in v22.0.0. Instead, use the existing option `-datacarriersize`
to control relay and mining of OP_RETURN transactions, e.g. specify
`-datacarriersize=0` to reject them all.

### BIP9 support removed

Bitcoin Cash Node 22.0.0 removed the (incomplete) BIP9 support. In earlier
versions, it already was inactive due to no available proposals to vote on. The
empty `softforks` field in `getblockchaininfo` has been removed.

### Prototypical Avalanche removed

The Avalanche prototype features have been removed from this release
pending specification and evaluation.

### Windows 32-bit build removed

The 32-bit Windows target is no longer supported and has been removed from
the release shipment.

Users that wish to build for 32 bits Windows should be aware that
this will not be tested by the Bitcoin Cash Node team and be prepared to
resolve issues on their own.


## New RPC methods

No changes.


## Low-level RPC changes

- The `sigops` and `sigoplimit` values returned by the `getblocktemplate`
  and `getblocktemplatelight` methods are now calculated according to the
  SigChecks specification.

- The `clearbanned` method now optionally can take two additional boolean
  arguments (both default to true if unspecified). These arguments can be used
  to control whether manual or automatic bans are to be cleared (or both).

- The `listbanned` method no longer lists automatic bans.

- The `listbanned` method's results array has changed slightly. All entries
  now have their `banned_reason` as "manually added" (since `listbanned` can
  now only ever show manual bans). The "node misbehaving" value for this key
  will never appear. This key is now deprecated and may be removed altogether
  in a future release of BCHN.

- The `setban` method can no longer lift individual automatic bans. Use
  `clearbanned` instead to clear all bans, or `clearbanned false true` to
  clear all automatic bans (while preserving all manual bans).


## Regressions

Bitcoin Cash Node 22.0.0 does not introduce any known regressions compared
to 0.21.2.


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

- `arc lint` will advise that some `src/` files are in need of reformatting or
  contain errors - this is because code style checking is currently a work in
  progress while we adjust it to our own project requirements (see Issue #75).
  One file in `doc` also violates the lint tool (Issue #153 )

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
  linking against the QR code library (not present) was attempted (Issue 138).

- The 'autotools' build is known to require some workarounds in order to
  use the 'fuzzing' build feature (Issue #127).

---

## Changes since Bitcoin Cash Node 0.21.2

### New documents

- `doc/bch-upgrades.md`: List of all supported Bitcoin Cash upgrades
- `doc/coverage.md`: Instructions to generate test coverage measurement


### Removed documents

- The documents in the `doc/abc` folder have been moved to the upgrade
  specifications document repository (<https://upgradespecs.bitcoincashnode.org>)


### Notable commits grouped by functionality

#### Security or consensus relevant fixes

- 1a79646efa3bca9bd9ad1cc93670900f5f5e573a Integer ASERT difficulty algorithm with 2-day half-life and MTP activation (aserti3-2d)
- 4f2478d89dafe66ec208323eb3b619ac9d811fdb BanManager: Reduce costly linear scans & modernize code


#### Interfaces / RPC

- 453795b727518ef64af20ebf4ea111527f6a0bef Warn in RPC, Qt, and log as node approaches tachyon, disable RPC after tachyon
- 2fbd749ef267bfc76e2c5fc33e22ab8294d44086 Remove legacy medianfeerate from getblockstats RPC
- c920a58664b3797b885b38ecb852011ed7995594 Remove softforks field from getblockchaininfo RPC
- 52442c9d7ad506766cc236efce38e6e2abca479b Remove -datacarrier CLI option
- 8ecbd3cc86deb6793fab489fad2b6282be900650 Change -usecashaddr default to 1 in bitcoin-tx
- b7c02a66176df7b8d5690acd497b837c3401d96c [backport] bitcoin-cli: Eliminate "Error parsing JSON" errors
- 5eb88756f3a787a9e57464181df785b46d72a2b3 Make getblockheader work with block height or block hash.
- 7de4551c3507800a3dcc44e3ddb1529d9dbadb2b Return hex encoding block header if verbose is set to false
- 7f0ad9350192b071d5905702f77a3772e9bff87f Unhide Axion (November) activation time parameter
- 9873ac4ee693a07823260b8d8584239bebfa9a00 UniValue fix: Serialize floats properly, irrespective of locale
- fcf0ba55b10cbc1693e4ab9d43e03e22c768447f Remove tr() calls and fix KB -> kB
- 83039f3c93e6ddd3ed14f9a5c0ea09bd33f7b4d1 Fix CLI help text regressions


#### Peformance optimizations

- 4bdff706abcefd49557d355758543496d586baa5 Performance adjustments from review of backport of D5715
- 00e460913bfa9e73f9b3978637e6fa89496d2558 Split UniValue::getValues() into getObjectValues() and getArrayValues()
- b0edc7dadde37c4122aa9f3620be331de43ae913 Replace UniValue::exists() with find(), eliminate redundant object searches
- b4662502e4964ec6548290fa9ab5701ec278eef5 Remove UniValue global function find_value
- a58b4fbc21f01f1a1eecce558c5d6dc25f531c43 Performance: Optimized HexStr in util/strencodings.h
- e23697d45a37acd2e8b0b5d5d66025813758c38f Store UniValue object keys and values together (#51 item 4)
- 69d0189e2ce0a8c103e236773671590be4478e2b Nit to timedata.cpp: break out of loop when we get an answer
- 29b3ecae452019d0a9cf2e7a4f8510117a263e33 uint256: Add an explicit "Uninitialized" constructor for performance
- 74bbc6815a3f56a609286b3aa3867bf91883cb05 Base UniValue::setInt buffer size on maximum integer length


#### GUI

- b48c870c175ea9ae4014f35edcf96217eff61941 [Qt] Fix debug screen size calculation


#### Code quality

- 77dee980f6b7d75e61f91cdeb2a81db92198341c Remove incorrect right indentation from CLI help text
- 5687ff3ece82849b012592710fcac35e54f0da67 [qa] Fix issue 151 (code quality warning about undefined name)
- 3fa525a138ee14d024650d44348f116f69241eef This is not experimental software
- 8f92174d1f8e507eb3758fbcd218d890393b003b Increase setexcessiveblock rpc example value to > current max blocksize
- 6d59b99d7a52f4cd55a2d598f251bc1a6304c978 [lint] Adjust circular dependency expected list to our current baseline (removed 6 cycles)
- e738a04281ff79d80f07d507a2591010debc6dde [lint] Break circular dependency between gbtlight and rpc/mining
- 048d0618110cc523f10001b9ac024da822199db1 Nits from review of D5756 backport
- 95d244b85da8329274f1d6334a36bb9fcd764b45 Remove unused UniValue::getObjMap()
- 79c307b7128d1e3862dfbcca98eff09a7a414a72 Remove barely used UniValue::checkObject()
- 2db3bbe953239f89cd0ecd4dad4c692367daf24d Modernized the code in the generated univalue_escapes.h file
- e276c510ee8c9669c2e9de56b9d6e293b0311b81 UniValue: removed superfluous `inline` keywords
- 1f41bbc28cc55e479e4e8db90e7fe7651587a496 Made `UniValue::indentStr` have a consistent declaration
- 24a611640091fd5626211e1810a3dcbc6f5dc3d2 UniValue: Fix GCC compile warnings introduced by !464
- 017b6cfab3f68a7a4d28a665ffafdb465ced51da UniValue API additions: takeArrayValues(), front(), back(), operator== and more
- 9975aff525de253f415b7bd00f04ba01e673337b [lint] Fix two Python linting issues in test/ which remained after MR485
- 9d298e85075f83293906eafc20b68877df333750 GBTLight: Trivial fix to simplify the code in the unordered_map hasher
- 03df11e4becd1d3ca4c7606b72012e7ddc06377c Code quality: Removed unused BEGIN, END, UBEGIN, and UEND macros
- 7de5ba64cabf69dd220782834c13ea3c4aceaeee Follow-up to MR !529 -- added better comments/naming
- 42d434468c0a90d5b6cebd8ddf9b66e69811b6f5 Begin properly documenting the UniValue API
- 701faa5dd5a920fa75d5b0c9f7ab0bb4ca288d1c Remove private method UniValue::findKey()
- aeb6640373fcb34cc6e1e26109ddbf775df8c08d Expand MurmurHash3 API to accept any data type, not just std::vector
- 035bc17646bcc0e55c9a52ad53d8b222dd5896ea Improve CRollingBloomFilter API to avoid double copies
- a88ec3faf99cb09c4d19d8a695a24288ce93409e UniValue: Fixed 2 small bugs, plus small performance improvement
- d06c9d41b8a8fc936b8f3091ddbac1dbfba15a71 UniValue: Use std::snprintf in favor of ostringstream
- d11532aa86e4b04808816cf40246f3b728e7d3b5 Remove never used bool return values of UniValue methods
- e2da2bd103cb538d617ea1bb3c3aa3105b1b9f1f timedata.cpp nits: avoid extra copies, use thread safety macro
- 24c92ab0090ec15db370a7828ab894dd3426cdc6 wallet rpc: Fix to unused parameter caused by not passing coinControl down
- 6acd0006196caf61a29d34c20929a437e9b1f599 Fix missing `#include <stdexcept>` in univalue.cpp
- 39a455036957019264948ea8f55317651b149cbb Remove UniValue::push_backV() and UniValue::pushKVs()
- af68aef9c1d7af83ac011f0dc2c963daff9ecde5 Fix double-copy and other minor nits seen in !591
- 0fbe779c378702e3f96359a24d35e43d7fcd8a74 Remove UniValue::clear()
- 813568de42918e0adddb3b08b1bf101489684698 [rpc] Fix a few nits, unused parameters, and use std::move in rawtransaction.cpp
- d8f717219548c587397b9efd3308894406f141ae Simplify UniValue::write logic
- c4281fbceb59e02bfda605f19655dcb4c50c2d44 Fix unused function warning for `GetPubKey` in `script/sign.cpp`


#### Documentation updates

- 4dd54a7494b89b2ce337b7fbbd978cc05704f4be Document implementation of November 2020 Bitcoin Cash Network Upgrade
- 490d710450f984fd6a6b879341144598fdd7badc Upgrade documentation of BIPs and BCH upgrades implementation history (#68)
- 64e2bf4d2b9f25658bdafc2707389f4813b18dce Update doc/ninja_targets.md
- f841f99d748e4629315f1fe5d89c1b6de676fd44 [doc] Add lines before and after lists, and other Markdown doc improvements
- 504a3c1dff88d0d6117fea24cf7e57a68385cae0 Remove trailing spaces from generated Markdown documentation
- e799876fcd242c6ede3a63e4246853574824e5aa [doc,lint] Remove trailing space in non-generated docs
- c1d4225e136c4aeea526d8965985ac4a1253b293 [doc] Misc documentation fixes
- 4f336447796738ad032260c7915674e68b05b9fa [doc] Document coverage targets
- 41ae1b7358addfd582122a21e2b1a31fb8dfa988 [doc] Document tag 'gitian'
- 01e63bad7292004791604d63e42c7e8aaaa105c8 [doc] Update documentation and 'pages' deployment to get rid of dead links
- c649ee1b316f3819fda86a50c12ed345a22b400c Adds part about building with WSL 2 (which has recently been released) and Ubuntu 20.04.
- bbf6b193c71b3ac7acdcd40b187cf145b515b6c1 [doc] Add git-lfs installation instructions
- 4ab5419238f3706f8098fa5e77a8c046fd65a513 [doc] Add python dependency to OSX build
- 8ba2423083d3b5e44d9d609459bc90c2c1525442 Restructure mkdocs navigation menu
- 4396c577b4516107248eedf447e350ae172adf3e [doc] Update build-osx build guide
- d1d9e161dc2779eef04572bbf44429a6bcd65c4f Various Markdown fixes for proper display on docs.bitcoincashnode.org
- 9070d42f9e4c7c4ff1f3921171fef25aaeb443df Fix Markdown in release notes too
- 652635a4823002dfad18df090142784af4002295 Added missing install in the dnf install command
- e245c7c867661bb074919fb4aad9ce9232df2e2e [doc] Add deprecation note for Win32 build and support
- 65da4134d231e2acba5b68e54412df98364127bc [Doc] How to run functional tests in an emulator
- ddcfb45ecc14b850b010b43c88f3f5d1887b54ec [doc] Document AArch64 build


#### Build / general

- 8e6f6adf8f05bc8d61da65bebe185043de7f503b Use a versioned release notes link in the debian changelog file
- 7130d304e148e35e5c233323d895e676df231248 Update manpage generator for !540
- e92388e9d57b22c0d2c2dd375f399b52572fe2a1 [build] Improve error on sanitizer check failure


#### Build / Linux

- b11ea179a3e594d53e3f8197986b3e18278d1db7 [qa] Remove relocated Debian packaging scripts


#### Build / MacOSX

No changes.


#### Tests / test framework

- b2d40a9a8f3f643ef813babf0c050a4930a33e73 [tests] A few more tests for ASERT
- 7844d55ada92133dfde4cbe802b94021a2427fc0 Improve UniValue reading/writing tests
- 95d2b0cbc7cc07771bd342b4044af66d6854cc44 Adapt bchn-no-minerfund-activation test to use Axion time
- 28281c82fe72a8c58782c1d3807076f66be28f18 Better unit tests for UniValue setInt/setFloat
- 1187e295894497a158a18121f2cbbcabee0f7544 Add some unit tests for arith_uint256::bits() method


#### Benchmarks

- 3285d52b3f6ea63b922b47d1777d4cf448e23cfe Added BanMan benchmarks
- 6971887cdb0a6cb122610052b6b950ba4f9ed549 [qa] Add benchmark comparator tool
- 73b549f845a508ce2e588ec25cec7015a79edb5d Split JSON/RPC benchmarks for more targeted measurements


#### Seeds / seeder software

- f07f1842658d3087dc33e6927f5bf85c12916120 Add IP-seed feed 'seed.flowee.cash'


#### Maintainer tools

- df24a4a467fad579d835ed34603ff0e628f6bb4c Adapt debian-packages.sh to work with BCHN infrastructure (take #2)
- 23f0627270705a17bf2eb7723121ce93f55a573e Adapt debian-packags.sh to the BCHN infrastructure


#### Infrastructure

- 8cdf690870520c08a09002a294a480a756c649e1 Configure Git LFS


#### Cleanup

- bfc1f85c71cd7e0975857a371164c088bec6bd4d Remove Automatic Replay Protection
- 4f6af3c7b2a18f57cedeae5c24be2becc9fa137b Remove Automatic Replay Protection
- 5c222ec36ed3a634c582e176dc32be99a8349d70 [qa] Remove avalanche prototype from code pending proper specification and design
- 9859cc4f705cdf87e03d15e52b8f8c5b9d47fd3a Remove BIP9 support
- 8eeb4d58824feea9043e35074693db833b940811 Add timestamp for tentative May 2021 upgrade


#### Continuous Integration (GitLab CI)

- cee29e6fd6a0393e97a01300cd21f0813cdf1a6d [ci] Transition to from only/except to 'rules' syntax
- 6e97236512e9cdde5da617ca48514dbc1598f32e [ci] Remove post-phonon tests
- 3a28c856ee6f4d3610b7a69dd23fb5a6e276335a [doc] Run mkdocs on everything
- df08bc40efabb9c5752bb3af28156aa6ef248163 [doc] Publish documents outside doc folder
- bc10e3b85442836ffcb5b7252edc62a9ae58b041 Add fuzzing to CI
- ac841e1431f1e7b2a4bc95d28c7c8b04948845e8 mkdocs: Return to default plugins and site_url
- 4c2de7ed1cd9e776b4221885f6bd2897fbbf1cc8 [ci] Enforce RPC coverage in CI
- 1e273d171bec9304e39e4e462dda969709cb67c2 [ci] Add AArch64 CI jobs

#### Backports

- 1353e328dfb3773963cda11dbec599583eb9db49 ABC: D6567 Always repport proper sigcheck count
- 07dca8fe1632b2e38a303c7de4f0ebe42a6adc69 ABC: D6113 Remove legacy per transaction sigops accounting
- 9d42b5da79fa37aacc1b0aa65fad6b8b1c76ad26 ABC: D6093 Report updated sigops count in mining RPC
- 774500a4214ee1f1196ca2d5e5c08e7090c9e1d5 ABC: D6111 Remove legacy per block sigops accounting
- e9e1605aa0aba4dd073695f99678d604072ff8e8 ABC: D6106 Remove legacy sigops support from miner
- cca9ced4c592e2e3c27b77c6e62a19144d20ef59 ABC: D6105 Kill GetSigOpCount
- f22ba2cbc5acb69fa2d88d64924da93863e96b54 ABC: D6101 Do not count sigops at all anymore
- 266625abcb91ad5936a26b0bafe781a13affee34 ABC: D6576 Always enable sigcheck in the mempool admission
- 5d94abc3eb50cdf0505ec66027c8fa88c4463cf5 ABC: D6566 Remove activation logic for chained transaction limit
- 98dec0e76a0fb22a977b84c36588acf766868146 ABC: D6173 Removed activation logic for OP_REVERSEBYTES to pretend it was always enabled
- d81bb39ec6ecc50276f074edd520c0b0e4ae68fc ABC: D7177 (partial) Remove last vestiges of phononActiationTime: use height-based activation
- f6b5dd59c108da5031a058ed12e440998161b481 ABC: D6797 Cleanup unused --with-phononactivation from test_framework
- cc6075db9007ea818a4da4defc3fac9c83e9e5e5 ABC: D6796 Cleanup phonon activation in functional tests
- 384c7eea3e71edea8dd3505a37dcfd994d559c5e ABC: D6805 Cleanup leftover phononactivationtime option
- eb406532dcfa648eac23f790c846c9fa66b82a01 ABC: D6454 Merge #13096: [Policy] Fix MAX_STANDARD_TX_WEIGHT check
- db8211206dd68cda8f720af4ebfcc9b93d32a64a ABC: D5612 Remove Windows 32 bit build
- fc95a88b01836d22e2f42d63f664c5243f0ac109 ABC: D5750 Core: PR#11796 [tests] Functional test naming convention
- 6c7f2cb601bed2602155dd7205b320eceec631e4 ABC: D6782 Enable Axion upgrades in functional tests
- 0c369a963db3d52fb7a541d0225f3077a8d9a5d7 ABC: D6781 Enable Axion upgrades in unit tests
- edda65d356083ec69de505980336d75770d85613 ABC: D6780 Add facility and test for checking if Axion upgrade is enabled
- 807811743ea2cc17c9805b5d9c870bdcacf3d057 ABC: 5683 Core: PR#14711 Remove uses of chainActive and mapBlockIndex in wallet code
- c25bfb8318bb518040c815439e2d6ecf916149a2 ABC: D6511 Core: PR#15305 [backport#15305] [validation] Crash if disconnecting a block fails
- 41f7f4a62ff47aa93d4a4b3651f943f4e5e27cea ABC: D6500 Core: PR#18037 unit test for new MockForward scheduler method
- f5c49684a09b3e5709355a37393ce99ddf37503a ABC: 6572 [Qt] Remove unused WindowFlags parameters
- 04c3baeb048bb3aa447ae3fdf30939a59eebd54a ABC: D6335 Core: PR#14121 blockfilter: Functions to translate filter types to/from names.
- 3c4140e109dd34dda8546982084f1ede67671a33 ABC: D5641 Also track dependencies of native targets
- a26e46bb6b9026a9d2c491adf0303d791bd3d197 ABC: D5665 Core: PR#18004  build: don't embed a build-id when building libdmg-hfsplus
- ca3223e4480be09bcfb709fb361c76e80ededf7f ABC: D5738 Core: PR#14978 Remove op== on PSBTs; check compatibility in Merge
- c093a26551a0c578ada4bd57465efb1df94ffea7 ABC: D5883 Fix the emulator with autotools
- 7e2978c733a754c013d29de1dc20b7512152f80a ABC: D5878 Allow for using an emulator for the functional test framework
- 73ea836545ebac6cac407d7504a0b5746a67ff74 ABC: D6036 Bump misbehaving factor for unexpected version message behavior
- 469258bf73de9ffa795d35b7151f7036dbedcd96 ABC: D6081 Core: PR#14886 [tests] tidy up imports in wallet_importmulti.py
- 716225bf90ca65ac744092ab5366680be77bc26e ABC: D6124 Core: PR#14477 (partial) Add support for inferring descriptors from scripts
- 46d315877924afb08b5c88b52eefb62bb6a653e8 ABC: D6134 Core: PR#12119 [testonly] [wallet] use P2WPKH change output if any destination is P2WPKH or P2WSH
- ab6e90f06754f752e8007d182c067223fe9de639 ABC: D6202 Core: PR#17469 Merge #17469: test: Remove fragile assert_memory_usage_stable
- 6ac852fb6ff8a5251d0feb3031c8709254cda90f ABC: D6219 [refactor] change orphan txs std::map member to use TxId instead of uint256
- 7e5daea9ee3ef8646fee12afd4b48183295eb537 ABC: D6240 Core: PR#17265 random: stop feeding RNG output back into OpenSSL
- bdb21915e767be69475c720c2b69dc15ff51506c ABC: D6237 [build] set _FORTIFY_SOURCE=2 for -O* builds only
- e607d4c308f80755113f266fb2768b889a9a90ca ABC: D6251 [CMAKE] Move the OpenSSL symbol detection to Qt rather than config
- d1de9214733f169c9be62d55448c9a8cf17b4e77 ABC: D6249 Core: PR#14453 [backport#14453] rpc: Fix wallet unload during walletpassphrase timeout
- 18e8d2748a433144938a452c86ef563f0a50c60a ABC: D6250 [refactor] make ArgsManager& parameter in IsDeprecatedRPCEnabled const
- 59d0bf1e6c02cf13a4d97be20217be4450c4adcc ABC: D6310 [CMAKE] Allow for checking support for several flags at the same time
- c41e8ad213eee4d4db594b690180629e323225ec ABC: D6309 [libsecp256k1: PR700] Allow overriding default flags
- 1b902d1c1eb5c16dd9e856cf723c0a91f7700af2 ABC: D6303 Wrap nChainTx into GetChainTxCount
- 25bd4ebb15adad3178e3d585ff06b910747b1b04 ABC: D6304 Core: PR#15623 [backport#15623] refactor: Expose UndoReadFromDisk in header
- 7a036b91b59ddfdba9484011077a8b962bda9d18 ABC: D6317 Core: PR#13116 Merge #13116: Add Clang thread safety annotations for variables guarded by cs_{rpcWarmup,nTimeOffset,warnings}
- d6a0ac2672fe57e9f484486bc39f65126591caa5 ABC: D6313 [CMAKE] Rename secp256k1 test targets
- 968218eb490360982374dda04c95ddd6f53284ce ABC: D6312 [CMAKE] BOOST_TEST_DYN_LINK is defined twice
- 5e11f6b934f53978cc078e15eed6027f99e7c32c ABC: D6321 Core: PR#13160 Merge #13160: wallet: Unlock spent outputs
- 3cc62139d6d25314817403c73328fede00002b40 ABC: D6319 Core: PR#13535 Merge #13535: [qa] wallet_basic: Specify minimum required amount for listunspent
- 4213baa169b20895f1b6bbcb01d1593c7c846830 ABC: D6320 Core: PR#13545 Merge #13545: tests: Fix test case streams_serializedata_xor. Remove Boost dependency.
- b68a87fb283e6a1f106840794b4f11212c9de0c2 ABC: D6323 [test] add a couple test cases to uint256_tests.cpp
- 81b4653948da786bcc54dd430b1075a3a526076e ABC: D6327 Fix a comment in validation.cpp
- d06d0bea75c11809808c1fee93ae59f4b33c1c3e ABC: D6332 Core: PR#14121 index: Allow atomic commits of index state to be extended.
- 3572e8a1db9e6ed615d0f399d746e810a05a7bdf ABC: D6336 Use BlockHash and TxId in zmq
- 42f5ae192135bed4c55f5edd52a98aa237d63fbc ABC: D6338 Use BlockHash in BlockFilter
- 0be3b725b977db1326c5f1688349911699a75e22 ABC: D6344 Core: PR#15280 gui: Fix shutdown order
- e75ea52d1fb7233af1d0d3e8708155639bdfdc5e ABC: D6367 Core: PR#13756 [refactor] add const CCoinControl& param to SendMoney
- 2711cccc710930c62b7162568c780b3f27a88f2c ABC: D6353 Core: PR#12856 Merge #12856: Tests: Add Metaclass for BitcoinTestFramework
- e5d21947976cb7bf2fd59d53ec1137cfeeeff910 ABC: D6381 Core: PR#13491 Improve handling of INVALID in IsMine
- 0689ae02e91e895a3027424ed54249babd6f9594 ABC: D6378 [devtools] Use a trap to cleanup bitcoind instead of a background process
- 243cb91ba3c8764d64614a020f97fec62897e968 ABC: D6386 Core: PR#16898 (partial) [backport#16898] test: Reformat python imports to aid scripted diff
- 61b9a601505558114d791ae499647af7d7ffcc9d ABC: D6394 Core: PR#15246 Merge #15246: qa: Add tests for invalid message headers
- 3edb8f08fb34a11bb8da2569635f5ae81ebece41 ABC: D6398 Use BlockHash for vInventoryBlockToSend
- 131e4f8f5da0a9f2ced9f5c7ea15bddcbcc1ec58 ABC: D6399 Core: PR#15759 (partial) Remove unused variable
- 8849147fe16568aa7d17b9c5ce8fb1b69df73a2e ABC: D6417 Core: PR#15654 net: Remove unused unsanitized user agent string CNode::strSubVer
- ea75a9a6de2efce77fb3bd1462b37e9dd4333f75 ABC: D6452 Core: PR#14027 Skip stale tip checking if outbound connections are off or if reindexing.
- e7d4fee9501b7a37a546cb8c06d7efb2f3a0a356 ABC: D6456 Core: PR#16898 [bugfix] prevent nodes from banning other nodes in ABC tests
- e84f3ec5b5b0eb51dfd099a57bd110395dea42e5 ABC: D6457 Core: PR#14436 Merge #14436: doc: add comment explaining recentRejects-DoS behavior
- add9abcee04c7126c9527702cb991c0d701761aa ABC: D6481 Core: PR#13503 Merge #13503: Document FreeBSD quirk. Fix FreeBSD build: Use std::min<int>(...) to allow for compilation under certain FreeBSD versions.
- 5cdb9fe6502fc27588773e657697dbf2b2358e6b ABC: D6475 Core: PR#15254 Merge #15254: Trivial: fixup a few doxygen comments
- 4d055e0a7de460f0cfdfe708e933175b67973d5b ABC: D6485 Core: PR#16073 Merge #16073: refactor: Improve CRollingBloomFilter::reset by using std::fill
- ace2fdc6e50fab0d32d9651c61ff36c5f2ca8c05 ABC: D6476 Core: PR#15343 Merge #15343: [doc] netaddress: Make IPv4 loopback comment more descriptive
- cd1ea2923b7c5c9e55a379e72393dfb2062b00c6 ABC: D6491 Core: PR#15597 Merge #15597: net: Generate log entry when blocks messages are received unexpectedly
- f21f90f58805c91b7fb1a2918ce431533041b258 ABC: D6499 Core: PR#18037 [util] allow scheduler to be mocked
- a8748fce7c25679e3a2700bcff76a92d2ed3a32d ABC: D6517 Core: PR#16117 [backport#16117] util: Add UnintrruptibleSleep
- 9233f98e766475d43438dcc2ad44ce878a75b491 ABC: D6515 Core: PR#14931 Use std::condition_variable and sync.h instead of boost in scheduler_tests.cpp
- f726eebe0c109957c0294a6f8b9de0695535578a ABC: D6522 Core: PR#14931 [backport#14931] test: mempool_persist: Verify prioritization is dumped correctly
- 60f8ce946ac8faba466c1fda47fb03402ce91e18 ABC: D6538 Core: PR#13531 [backport#13531] doc: Clarify that mempool txiter is const_iterator
- e927c69798f799d2a091eb42d4a1403ca6e780b4 ABC: D6550 Core: PR#15831 [backport#15831] test: Add test that addmultisigaddress fails for watchonly addresses
- 078f55b7449cdd562256ff3180462abb8ac7e4de ABC: D6553 Core: PR#16227 [backport#16227 1/8]Add HaveKey and HaveCScript to SigningProvider
- b637a9b04e0d46e7e44f055d1d20e668067ca4d3 ABC: D5900 Core: PR#14632 Merge #14632: Tests: Fix a comment
- 4cb4c8337848b0bf2037f8507d9384ff468f948f ABC: D6564 CBlockTreeDB::ReadReindexing => CBlockTreeDB::IsReindexing
- f87c20e84fdf1652370f02f844516c60eb5ee997 ABC: D6565 Make CLIENT_VERSION constexpr
- f623cb891b3e7687aefc6dc4194265d8946e701a ABC: D6575 [Qt] Fix deprecated QDateTime(const QDate &)
- cc158f396cdb1f61db00621a421288bd276d9a86 ABC: D6573 [Qt] Fix deprecated pixmap() return by pointer with Qt 5.15
- fad5d8f467cc51ce0878a3e1a107fe4f5f7da4db ABC: D6590 Core: PR#15337 [backport#15337] rpc: Fix for segfault if combinepsbt called with empty inputs
- 11530f4f5d336908e7b5df551369fc468a45c514 ABC: D6606 [Qt] Fix deprecated QButtonGroup::buttonClicked event
- d12bbf14245a6b0df5ba0e7bd9e665c336298c32 ABC: D6605 [Qt] Fix deprecated QString::SplitBehavior (now Qt::SplitBehavior)
- a2c09f364c159f668096e3eb3e63a650a5bdb901 ABC: D6489 Core: PR#15486 Merge #15486: [addrman, net] Ensure tried collisions resolve, and allow feeler connections to existing outbound netgroups
- 659385f552886bae6595f7a76939a5dc0b24b4a8 ABC: D6625 Core: PR#16188 Merge #16188: net: Document what happens to getdata of unknown type
- 9b09266ea4ced2f4fe61f4370e5562143d7b8c16 ABC: D6632 Core: PR#12401 Merge #12401: Reset pblocktree before deleting LevelDB file
- d225244b90d42b48e6b5e26b6fbee3f685bb551b ABC: D6631 Core: PR#15999 Merge #15999: init: Remove dead code in LoadChainTip
- b75c8518e9fa15ebb38e87d3b6f7fa054baa9d86 ABC: D6671 Core: PR#13457 Merge #13457: tests: Drop variadic macro
- 8d76a0ce6d13bf1a5fa1f7ab11cbad53afe3d3d8 ABC: D6669 Core: PR#14051 Merge #14051: [Tests] Make combine_logs.py handle multi-line logs
- eb4b91b2ccc670bfc409169222dc9f604d0a366e ABC: D6682 Remove double if in tx_verify.cpp
- 42c4c5c5095d3270da266d3ee801d397864bf590 ABC: D6694 Core: PR#18412 Merge #18412: script: fix SCRIPT_ERR_SIG_PUSHONLY error string
- e5455dc6b9062bab53dd225595ff479084597f96 ABC: D6697 Core: PR#11418 Merge #11418: Add error string for CLEANSTACK script violation
- 9b59864b984ca2cd8a0deb709864623e76a383fa ABC: D6713 Core: PR#14816 Merge #14816: Add CScriptNum decode python implementation in functional suite
- ef5643ce5104190b9c68e42b4683052d6badca59 ABC: D6709 Core: PR#14658 Merge #14658: qa: Add test to ensure node can generate all rpc help texts at runtime
- 074f238ffab6a0c47b1d0d57ba4080461d6dd63b ABC: D5513 Core: PR#16049 depends: switch to secure download of all dependencies
- b637c0710f21b9e83d7cdff5ec644467eab84a73 ABC: D5499 Make the fuzzer test runner compatible with cmake
- 895297060a8d65ed355303b002c359fe1572941f ABC: D5758 Core: PR#15335 Fix lack of warning of unrecognized section names
- f0d275e75ab7bccba0a589d38609688c9d997d66 ABC: D5743 Core: PR#15943 Merge #15943: tests: Fail if RPC has been added without tests
- 82f232469f39c69f420915662b06216ac976d4af ABC: D5562 Core: PR#13076 Return a status enum from ScanForWalletTransactions
- a9e47e79703d653e30b87ed4670aebf2ff4ff997 ABC: D6212 Core: PR#15617,PR19219 [backport] Do not relay banned or discouraged IP addresses
- 5e53599497106f6ef5b9bc957b6e3f14a467aeb5 ABC: D6506 Core: PR#1928 Banman: Replace automatic bans with discouragement filter
- af39c4200627e77edcdc2f403120e600d4aea8c3 ABC: D5342 [CMAKE] Fix the check-bitcoin-* targets when running with Xcode
- 1142351fc235d71f2e02bb16e384b8ea0e432830 ABC: D5872 Fix the build with ZMQ disabled
- 0fe9f61b01747c4174cef4da5ccd389c2eaad17c ABC: D5431 Request --enable-experimental for the multiset module
- 2043fee4b2eb94e0ecd4b5039fbe71d13fe63dae ABC: D5394 Core: PR#14264,PR16051 [DOC] Update the depends README with dependencies and cmake instructions
- 026120297189dbb91c6c24fbcb91fcda87fee62d ABC: D5395 [DOC] Update developer notes
- 706d3038541aed5d74ff070f0c4fadca67f4542f ABC: D5360 Make gen-manpages.sh return non-zero if the script fails at any point
- 50ff9909d95a335f56b182218e0a3c6a9f7b6afe ABC: D6362 Fix the build with Qt 5.15
- e518ec62f0ba6cefb1d24625785c3e30d52b6adf ABC: D5932 Core: PR#16248 [backport] Replace the use of fWhitelisted by permission checks
- f842a9205316086e733331b89c0c4e5e78012099 ABC: D5761 [CMAKE] Use a cmake template for config.ini
- cdabaddb864b46ac33b5cf37efcb5025bafe10f5 ABC: D5753 Core: PR#16097 (partial) refactoring: Check IsArgKnown() early
- 799eeb67e8744dda4945c4dfdc27d5653bc38ac0 ABC: D5764 Core: PR#15891 [backport#15891] test: Require standard txs in regtest by default
- 417258880d62228517b23b25b824f5242776810c ABC: D5936 Core: PR#16656 QA: fix rpc_setban.py race
- 16863995670b8e7b036ad4267756b4de7cb7acb1 ABC: D6302 Core: PR#12330 Merge #12330: Reduce scope of cs_wallet locks in listtransactions
- a5226ac3c43817f2a745da7ccfc5b4794330ff35 ABC: D6301 Core: PR#15345 Merge #15345: net: Correct comparison of addr count
- e1e0d255e1c9e7c39f650a47ab4b60f32cb2218e ABC: D6299 Core: PR#18700 Fix WSL file locking by using flock instead of fcntl
- 8f46164d2538c8595158efe2449edf31b8992b43 ABC: D6294 Core: PR#14599 [backport#14599] Use functions guaranteed to be locale independent
- 069add0f676bd4996b94f805d7ed5c437cbf6d13 ABC: D6290 Remove CBlockIndex::SetNull
- 49e78f335e21d953a196561545da1140b3624f04 ABC: D6288 Core: PR#15139 (partial) [backport#15139] Replace use of BEGIN and END macros on uint256
- 0e809fed354cb095452193604feeee97bf8a16e7 ABC: D6285 Disable some more leveldb warnings
- 2c886b50a12b8818b36544bff84d7a38c9bd99c3 ABC: D6284 The -Wredundant-move warning is C++ only
- 634e40cf828c1d3415c4d8ae9fabba99e42a8659 ABC: D6281 Fix unused -pie flag for libs
- d64712114283ebbb5a7519b94f459d59dec05e19 ABC: D6213 Fix code alignement in rpc/misc.cpp
- 93fee1cfbb54aa0de707f4ed6f8818544cd976be ABC: D6148 Core: PR#15308 [backport#15308] Piecewise construct to avoid invalid construction
- 5c30cc665c6a99be6007cba31c68463d502becf2 ABC: D5954 [trivial] comment correction on wallet_balance.py
- cad767a4ac8ada8ed14597d8f2a68db2ceeba0b5 ABC: D5935 Core: PR#16618 [Fix] Allow connection of a noban banned peer
- d4090662cae0f1f11d01f062caf1e5a9b9634700 ABC: D5929 Core: PR#16248 (partial) Do not disconnect peer for asking mempool if it has NO_BAN permission
- 7fbd7c38da2fcbc6d33ac717d944600a36f91e9c ABC: D5925 Remove config managed RPC user/pass
- 8908015742dd1c1213bc3914aa049daf44e51956 ABC: D5842 Core: PR#17604 util: make ScheduleBatchPriority advisory only
- cb31f4509d5dac097d2dba4dcf8b80ff64bfdb15 ABC: D5620 Core: PR#16089 depends: add ability to skip building zeromq
- e534c245cfedd460fbe286388a4b973592505f1c ABC: D6006 Core: PR#14150 Merge #14150: Add key origin support to descriptors
- 6b6ca640941937f2fc1b3848265386f4064ca0da ABC: D5776 Core: PR#15456 Enable PID file creation on WIN
- f0d5817d7675e9376e8ffffe1c11e92e87ee446a ABC: D5757 Core: PR#15087 [backport#15087] Error if rpcpassword contains hash in conf sections
- e37bdbcc0628e98594abbf60f22bba00e7052671 ABC: D5735 Core: PR#11630 Simplify Base32 and Base64 conversions
- 53d01afd0025f0dffb5251e97ec0e927531064fa ABC: D5718 Core: PR#14978 Move PSBT definitions and code to separate files
- 1d281a05c7505957596f1b03e086c1ff4037fc0a ABC: D5677 Pass CChainParams down to DisconnectTip
- 212022bdad2b2072b7bfcf1470876c5dda58af7d ABC: D5654 Core: PR#17057 build: switch to upstream libdmg-hfsplus
- f7cdfc542ddaf265726be9b40493082fde0fef4c ABC: D5650 Core: PR#16879 build: remove redundant sed patching
- 14af614d2df3dad6228b25ef0e0146beec021115 ABC: D5628 Use ninja to generate dep files for the native build
- b101a83b9a43bff9729d0987d872134dee183b00 ABC: D5610 Core: PR#13764 contrib: Fix test-security-check fail in Ubuntu 18.04
- 56e2aa125216c88e2798f70e56c5cfe1cff079a3 ABC: D5608 Core:PR15446 Improve depends debuggability
- 3c4e16221dea2920563c5fac120bdcd2d86cb87b ABC: D5584 [test_runner] Fix result collector variable shadowing
- fdf4d05c279f2bc1f031fa80ec4daea4a25ebfde ABC: D5576 [CMAKE] Pass the interface linked libraries to find_component
- a5954b4a3f385e2e4052c7df0f6106b8fe81367b ABC: D5525 [CMAKE] Fix the bench build for windows
- 2181f174f88c7c07e0e3df7faf481c8143feb9f1 ABC: D6226 Core: PR#14129 Merge #14129: Trivial: update clang thread-safety docs url
- 4aee4fb22d740caa245788c0a89703372004085e ABC: D6210 Core: PR#15689 netaddress: Update CNetAddr for ORCHIDv2
- 969027e3c016ff224e9ac008985c420920296737 ABC: D6178 Core: PR#14522,PR14672 Merge #14522: tests: add invalid P2P message tests
- ca57954955a10911a1760de66c90b1ae30ad0571 ABC: D6176 Recategorize seeder connections as not manual
- bda511cc0dcd8925afd62dd7c130bbd8aa77145c ABC: D6164 Core: PR#16995 (partial) [backport#16995] net: Fail instead of truncate command name in CMessageHeader
- 088155a5d64978d08646c4a7781fc57d0ec06dee ABC: D6161 Core: PR#17270 (partial) [MOVEONLY] Move cpuid code from random & sha256 to compat/cpuid
- 5510da5d813d486034e21cb3256620aa4bc90db5 ABC: D6156 Core: PR#17151 gui: remove OpenSSL PRNG seeding (Windows, Qt only)
- 42a58571aba8296d7dda7cbd9ba5d8ec1e712e1b ABC: D6155 doc: correct function name in ReportHardwareRand()
- 6ade6a2f5131899f6ca85806646a15c21756b8f7 ABC: D6149 Core: PR#14820 [backport#14820] test: Fix descriptor_tests not checking ToString output of public descriptors
- f3a0c25c99d95998d69d39ceb1a84f75babfb002 ABC: D6131 Core: PR#11403 Add address_types test
- bc0d97cf6c36e8d488e426e9117cb9fa4d5f02e3 ABC: D6125 Core: PR#14477 (partial) Add Descriptor::IsSolvable() to distinguish addr/raw from others
- d6a9096368f4edf5152c15fb28e80b8cf4468921 ABC: D6117 Fix Flake8 E741 errors
- a0a0d66c14ca2227c7adc0f519f0dce8d8346b31 ABC: D6116 Fix dbcrash spurious failures
- 5c751b8271686dc693431a69de459e001196aa23 ABC: D6097 Add OP_REVERSEBYTES test case
- 7a160850ae445f4aec2c7912900b516a26ab4a6a ABC: D6075 Core: PR#16918 Merge #16918: test: Make PORT_MIN in test runner configurable
- 8320077dd5aeb75655089b5ee5e226d426708d8e ABC: D6072 Core: PR#13769 [backport#13769] Mark single-argument constructors "explicit"
- 223ac15a24cc6fda5aa8cac9b2c322db8b3612e0 ABC: D6061 Core: PR#9332 Merge #9332: Let wallet importmulti RPC accept labels for standard scriptPubKeys
- a5ead6cfd97e41ab2fafd88f74404096eb3b85be ABC: D6060 [doc] since D5764, regtest requires standard txns by default
- 5ac574978d2e819948e17a3e820934aadf80192d ABC: D5966 Core: PR#14275 tests: write the notification to different files to avoid race condition
- b416a217c98aa73264cf3c36f9fc669ae475e693 ABC: D5824 Add a deprecation notice for the autotools build system
- 46628f6099a000260a6166f9f0267e2ff154339e ABC: D5321 [CMAKE] Add support for generating test coverage reports
- 7a64e55a8f369268a87364190b6ca2ffa8f5560b ABC: D5313 [CMAKE] Move the upgrade activated tests out of the TestSuite module
- 131362c315478ad812d69416b5204dba718b44cb ABC: D4629 Core: PR#15399 fuzz: Script validation flags
- 7e281c57e26dbf79b6a9a8dfb55cdf1cdf9818a6 ABC: D5640 Core: PR#16871 build: make building protobuf optional in depends
- 79e8301ea057b561766ec7d1669ab75676b1d786 ABC: D5991 More include fixes
- f34dd08adedc1fef2b78cc0353f919287794d63c ABC: D5383 [libsecp256k1 PR703] Overhaul README.md
- 920435d434256cd6c642fb5306940eded79e6b01 ABC: D5902 [CMAKE] Fix missing linker wrap for fcntl64
- c004eb7d2e6ed1bb14404bb50259bed6e23e7189 ABC: D5881 [CMAKE] Propagate the LFS support flags to the libraries
- d4479779e3de4d3c10366911f1b284dc17f2c876 ABC: D4816 Core: PR#17118 depends macOS: point --sysroot to SDK
- 3fb97c444d678ccfa5328369aea543f2a93583e8 ABC: D6278 Core:PR18553 Avoid non-trivial global constants in SHA-NI code
- 5bb31e9981abc8669a5c71536bf39ca57ee4a33a ABC: D6135 Core: PR#11196 Switch memory_cleanse implementation to BoringSSL's
- def73e3596ba40e9eb81350a3362079911c311bd ABC: D5623 Core: PR#15461 [backport] [depends] boost: update to 1.70
- 26b780aa22ad658f024ee78bacf166578608e9b2 ABC: D6008 Core: PR#15463 Merge #15463: rpc: Speedup getaddressesbylabel
- 2cc34da8d7a5ae0983e57b8218faf1b3aa590a4f ABC: D5843 Core: PR#10271 Use std::thread::hardware_concurrency, instead of Boost, to determine available cores
- 02f9523f9a56dea1b8bdefd2d6cff4ff61af9e36 ABC: D5756 Core: PR#14708 [backport#14708] Warn unrecognised sections in the config file
- f66417876f1ffa7f5b09b1540637c7c4e75a7245 ABC: D5715 Core: PR#14588 Refactor PSBT signing logic to enforce invariant
- ee8d07e0ac56e807b7feb869c7014a4eeea86096 ABC: D5803 Build the deb package with cmake
- 2593c34eae74e576ac1b14ded9e20bb1223fe90f ABC: D5802 Update the PPA to support Ubuntu 20.04, drop 16.04
- a03451742eb92aec2ba288325b397cf8dd108515 ABC: D5730 [release-process] Update Ubuntu PPA instruction
- 23ff2ff4e471430545c359937f60e43f7fa325fb ABC: D5552 [debian release] Fetch signer string from GPG rather than requiring the user to enter a perfectly formatted one
- 742fe13c449d414b35564dd2f5c5feb80c8a536b ABC: D5482 Use a sane default version for PPA releases
- c947e31090b251273da2c646ecc84853363b0718 ABC: D5472 Added a script for building and deploying Debian packages to launchpad.net
- 85fea76aa78163b585d4dd201b5b91c5679f330c ABC: D6053 Core: PR#16830 refactor: Cleanup walletinitinterface.h
- 062494875447ccc886b838c9c18c19841977561e ABC: D6025 Fix potential timedata overflow
- 0db527a3a67e57ce9a8a92b79a09b3a725bc8731 ABC: D6023 [tests] Remove ctime() call which may be unreliable on some systems
- 8c6822576652b2703870c59f878de93a18e3352a ABC: D6021 Remove last vestige of the alert system
- c43aaff8768c7c3e4514e67c1976ded1635dacba ABC: D6020 Properly handle LONG_MIN in timedata.cpp
- 0caa89dacf1111491764233eb12d015983cd2ab5 ABC: D6004 Core: PR#14021 Refactor keymetadata writing to a separate method
- 35dd499bea499bc18d8007071cd359f6df420ff8 ABC: D5992 Remove dead code in core_memusage.h
- c0e5a017c20a22ef9757c556e19c715571d4d7a7 ABC: D5990 Add missing includes
- 105817426e9d9415d08d3ccdea5f3d93b9068f66 ABC: D5963 [lint-circular-dependencies] changed expected dep list to establish baseline
- d2f013ba4e6547a87f9ddde71d95adc48e6ed2c1 ABC: D5934 Core: PR#16248 Add functional tests for flexible whitebind/list
- aa371a8b08d5dfc03afe83fef7e3fd46f1bdc00e ABC: D5986 Core: PR#17708 prevector: avoid misaligned member accesses
- 7025e91ee1ce77fdb3a3e0f7bd4d0313048c3668 ABC: D5965 Core: PR#15826 Pure python EC
- 8a676ac858dc35cb970b908241067f202005fe7b ABC: D5961 Core: PR#15638 (partial) [backport#15638] [build] Move CheckTransaction from lib_server to lib_consensus
- 083b84b026ba81edfbd5217b4aef3a04e118b403 ABC: D5959 Core: PR#12627 qa: Fix some tests to work on native windows
- f86747f7a1a411343d8f939ec94dcfd18347d8ac ABC: D5946 Update confusing names in rpc_blockchain.py
- ffd3e982baaff0dc68139818a9d41a4420250c61 ABC: D5950 Core: PR#14845 [backport#14845] [tests] Add wallet_balance.py
- fb950428204f0ae86cc546fa10f3edff783374ce ABC: D5889 Core: PR#13734 gui: Drop boost::scoped_array and use wchar_t API explicitly on Windows
- 5a0b5039bd049fd5293463104367ce46ba3829de ABC: D5884 Core: PR#15934 (partial) Clarify emptyIncludeConf logic
- c4cdf215b7bc862901d48077d1eed816745d2072 ABC: D5882 [CMAKE] Increase the unit test verbosity to test_suite
- c3c81351dc18ca56ee0e3bf31363b29d7c970c85 ABC: D5891 Reorder univalue include
- 86e45f07fa108d9df14b52db1ffe4fee7b37c38c ABC: D5896 Link univalue in the seeder
- d9dae9dd35a56b3ae8495905548a2d045b6250f8 ABC: D5844 Core: PR#16563 Add test for AddTimeData
- 565c83057db16c1fd3670e9d632915e8690ce7f4 ABC: D5847 Use BlockHash for CheckProofOfWork
- ea69809695cacf168c0f9d5434f24081584e595a ABC: D5841 Fix declaration order in util/system.h
- 30e7ad4ca0fa63908ba9c8b7ed5c04b84258ec2e ABC: D5829 Core: PR#15069 Merge #15069: test: Fix rpc_net.py "pong" race condition
- 2ba86745f123f05adfa02fdff750773d3ed44b56 ABC: D5821 Core: PR#14456 Merge #14456: test: forward timeouts properly in send_blocks_and_test
- 1cfb750b182132be60ea110e6e9d6c3274ebbabb ABC: D5811 Core: PR#14057 Only log "Using PATH_TO_bitcoin.conf" message on startup if conf file exists.
- 07c3a4da1a4a24701f85ac86be59af9990ac0f39 ABC: D5830 Rename IsGood() to IsReliable()
- ebf3d99335b2fa672dbc061539ee8a18c482ebda ABC: D5806 refactor: test/bench: dedup Build{Crediting,Spending}Transaction()
- 83f042c6bd24991620fc444457e93df84de5cd55 ABC: D5804 Remove CheckFinalTx
- ce6edaacdf235fd6661a4187d3810b816591b8dc ABC: D5799 Core: PR#12916 [backport#12916] Introduce BigEndian wrapper and use it for netaddress ports
- cf3bdb59331f25e43da876574346caa22338e7b8 ABC: D5794 Core: PR#14783 [backport#14783] qt: Call noui_connect to prevent boost::signals2::no_slots_error in early calls to InitWarning
- cb7cdd5f825b4810ee2e4e092649d004917cf811 ABC: D5783 Core: PR#14298 Merge #14298: [REST] improve performance for JSON calls
- 31f67a7547e4ac45bdb0d29b2c24259a75dae0b7 ABC: D5788 Fix a bug where running test_runner.py --usecli would fail when built without bitcoin-cli
- 5a274a8d54e1cf65adf3f27b7903863e666893fa ABC: D5780 Core: PR#14097 Merge #14097: validation: Log FormatStateMessage on ConnectBlock error in ConnectTip
- 815e3ad7351a346a78e2f7a9746f79d88cb9050b ABC: D5774 util: Explain why the path is cached
- 657f9dc3cfc1966769ac07f456332c2ad6151646 ABC: D5747 Core: PR#14618 [backport#14618] rpc: Make HTTP RPC debug logging more informative
- 1dca7767b159ca25e18f6ced3c5bc5cbd6511401 ABC: D5742 Core: PR#13105 Merge #13105: [qa] Add --failfast option to functional test runner
- b8af70ae811965a0dee87b9a008bd3f9e559eb9e ABC: D5748 Core: PR#13216 implements different disk sizes for different networks on intro
- 3a81a244a1b3284cd15b3805573ee0f51b486d7d ABC: D5745 Core: PR#14628 [backport#14628] Rename misleading 'defaultPort' to 'http_port'
- 923bd22ab11e4c91aed35bf66ac54acba26ee4a2 ABC: D5731 Core: PR#17121 Merge #17121: test: speedup wallet_backup by whitelisting peers (immediate tx relay)
- 844c8bb7707737813816811fcba6e0ccf7717547 ABC: D5709 Core: PR#13647 [backport] Scripts and tools: Fix BIND_NOW check in security-check.py
- 28d5fc9a71c2d8ed65f1f086df4ce4f9b404bb7d ABC: D5699 Core: PR#13565 [backport] test: Fix AreInputsStandard test to reference the proper scriptPubKey
- a3a5c178a4eae2b8ed7355bad61e3df0d1b01efb ABC: D5706 Core: PR#14978 Factor BroadcastTransaction out of sendrawtransaction
- bdc8d9b69c52f19b8447d96da7efbdebbdc9a737 ABC: D5707 Core: PR#13664 [backport] Trivial: fix references to share/rpcuser (now share/rpcauth)
- 8ea7cd296c5be99daee4036c970e3457c17c0040 ABC: D5672 Core: PR#17231 depends: fix boost mac cross build with clang 9+
- 7c13da4b1adb17d5ed3be799cd281aad5fa9588e ABC: D5680 Core: PR#17521 depends: only use D-Bus with Qt on linux
- 7d1f461f60796abe8318f66812ebe81e38a4c0b7 ABC: D5688 Core: PR#13118 [backport] RPCAuth Detection in Logs
- 6bb0a1c062d4672b48345c861760a2a207927e5c ABC: D5682 Make use of ADDR_SOFT_CAP outside just the seeder test suite
- b5115f74672902c5c0fcd535c76fd5ffce6406a1 ABC: D5681 Clean cache and tmp directory for instegration tests
- dcc9d7dfaecbe94d54bc80bf457591bb064ae0d7 ABC: D5676 Pass CChainParams down to UpdateTip
- 1860e16c95b31960df4d100308d6f00639b283c5 ABC: D5668 Core: PR#17928 depends: Consistent use of package variable
- 81cd07a71e9ff9b0ab885e7f9688d27439678f4b ABC: D5655 Core: PR#16809 depends: zlib: Move toolchain options to configure
- c7ef86affb1a2343e199dba4f35ba230cfb9d441 ABC: D5651 Core: PR#16926 Add OpenSSL termios fix for musl libc
- 4945fff20cb211aa466cad761755978c66365387 ABC: D5659 Reword confusing warning message in RPC linter
- e2f7f29c6467c22ba8b16a93597bc59ef1c9d849 ABC: D5661 Add setexcessiveblock to vRPCConvertParams
- feabdecacd5047de5ae03e16afe252021de1da09 ABC: D5652 Core: PR#17087 build: Add variable printing target to Makefiles
- ec6ea1ef06b2e7444931d751abeee63049664d65 ABC: D5666 Core: PR#17676 build: pass -dead_strip_dylibs to ld on macOS
- 77b834936d20b188bc44c8d50be9e354a5577d6c ABC: D5658 Remove trailing whitespaces in old release notes
- 1df43591469df94d19ab9c42d79b052695477ba8 ABC: D5614 Core: PR#15581 depends: Make less assumptions about build env
- 7983ddf8257c4b6f87c2660b7a929d97c35667c0 ABC: D5613 Clean the native directory when using the clean target
- 379678399378cf8f7b2004869fef7bfcc3a8253b ABC: D5626 Core: PR#15485 Merge #15485: add rpc_misc.py, mv test getmemoryinfo, add test mallocinfo
- 386860e1b75d1f7e806b9fa3188792890967e6c1 ABC: D5605 Core: PR#15580 depends: native_protobuf: avoid system zlib
- 8f8654fd409bf52e83118c39655f6b96a0c805a7 ABC: D5602 Core: PR#14647 build: Remove illegal spacing in darwin.mk
- d11c3943e64e92aecb2ecbb8d7a3b501ab006851 ABC: D5604 Core: PR#13884 depends: Enable unicode support on dbd for Windows
- 9e9ab30786c681903bc539dc6003022d22f84a33 ABC: D5560 Core: PR#15039 [depends] Don't build libevent sample code
- 25ace521c13cd827e7056d823d10efa20cc8fe89 ABC: D5569 Core: PR#13061 Merge #13061: Make tests pass after 2020
- 44315a398337cdd1bc2a570ca42743fe38baa2a6 ABC: D5455 [CMAKE] Silent git error output when running from cmake
- e1224ac194e95b4d65cd74122a98d13a206fe14a ABC: D5393 [CMAKE] Improve FindEvent
- f3397b6c29ea52cab0697c1c8df58b26fb435863 ABC: D5384 [libsecp256k1 PR709] Remove secret-dependant non-constant time operation in ecmult_const.
- 0c00f742d6d5ad811f599ea060bd1ed91f765c58 ABC: D5358 [libsecp256k1 PR661] Make ./configure string consistent
- bfebabb32812e05f0b0c6586f898713023a25e41 ABC: D5355 [libsecp256k1 PR654] Fix typo
- 21f4f731f398cca51d1fd0101547b7ca69d617f3 ABC: D5354 [libsecp256k1 PR656] Fix typo in docs for _context_set_illegal_callback
- f144ff56d63d6c5954d231fc05fe8146c04b3d47 ABC: D5348 [libsecp256k1 PR631] typo in comment for secp256k1_ec_pubkey_tweak_mul ()
- 73dc2619c19d5992df287c343fb95faa1ac1ee4d ABC: D4628 Core: PR#15399 fuzz: Move deserialize tests to test/fuzz/deserialize.cpp
- a039f77235e92d29dbcba507c26c2a656db1b63a ABC: D5825 Core: PR#17891 [backport] scripted-diff: Replace CCriticalSection with RecursiveMutex
- d7dda0e063c75b1a1923a06bafa6a6bdf74f9c80 ABC: D5849 Core: PR#15788 Backport leftovers from 15788
- db6ebe7f65b566b346888525841779291effca8d ABC: D5848 Core: PR#13219,PR13806,PR15413,PR15788 bench: Add block assemble benchmark
- d110c08a9d10a600b75e3eeae2cb3171df99228f ABC: D5493 Core: PR#15788 (partial) test: Use test_bitcoin setup in bench
- 6eea2b040bc3f6787beae498dc8051bc4509feb6 ABC: D5690 Core: PR#15201 Merge #15201: net: Add missing locking annotation for vNodes. vNodes is guarded by cs_vNodes.
- 936228fb8aa95ffb647fe5b85b2894fee4cdd576 ABC: D5547 Core: PR#14561 Merge #14561: Remove fs::relative call and fix listwalletdir tests
- 046cf057ddbab6d91956203fa52e629af666fde8 ABC: D5546 Fixup paths in wallet_multiwallet
- ae28a40a0179d7b3b708956e67dc5c71382208ce Core: PR#13918 [backport] Replace median fee rate with feerate percentiles
- 1ef830ae6c57aae3c3aa2e2dcfeaecf693730b4a Core: PR#15412,PR#15488 [tests] Add simple test of getblockstats call via bitcoin-cli
