# Release Notes for Bitcoin Cash Node version 24.1.0

Bitcoin Cash Node version 24.1.0 is now available from:

  <https://bitcoincashnode.org>

## Overview

This is a minor release of Bitcoin Cash Node (BCHN), containing:

- Upgrade of TOR network support from v2 to v3
- Upgrade checkpoints for May 15, 2022 upgrade

This version contains many further corrections and improvements
and modifies the storage format of the internal peer database to accommodate
new network address formats.


## Usage recommendations

Users who are running v24.0.0 are encouraged to upgrade to v24.1.0.
It offers up to date TOR network support, improves synching performance and
fixes minor bugs.

MacOSX users who are running on OS versions prior Mojave (10.14), such
as 10.12 or 10.13, and who are running 24.0.0 release binaries, are
advised to keep running 24.0.0 until they can upgrade to Mojave.


## Network changes

- The Tor onion service that is automatically created by setting the
  `-listenonion` configuration parameter will now be created as a Tor v3 service
  instead of Tor v2. The private key that was used for Tor v2 (if any) will be
  left untouched in the `onion_private_key` file in the data directory (see
  `-datadir`) and can be removed if not needed. Bitcoin Cash Node will no longer
  attempt to read it. The private key for the Tor v3 service will be saved in a
  file named `onion_v3_private_key`. To use the deprecated Tor v2 service (not
  recommended), then `onion_private_key` can be copied over
  `onion_v3_private_key`, e.g.
  `cp -f onion_private_key onion_v3_private_key`.

- If using the `-listenonion=1` option (default: 1 if unspecified), then an
  additional new bind `address:port` will be used for hidden-service-only incoming
  .onion connections. On mainnet, this will be 127.0.0.1:8334. This bind address
  is in **addition** to any `-bind=` options specified on the CLI and/or in the
  config file.
    - To specify the local onion port to bind to explicitly, use the new syntax,
      `-bind=<HOST>:<PORT>=onion`. See `bitcoind -help` for more information on
      the new `=onion` syntax which is used to specify local tor listening ports.
    - To not create an additional bind endpoint for tor, and/or to disable tor
      hidden service support, use `-listenonion=0`.

  Note: As before, tor hidden services are always advertised publicly using a
  "generic" port for maximal anonymity (such as 8333 on mainnet, 18333 on
  testnet3, and so on). The `-bind=<HOST>:<PORT>=onion` syntax is to simply
  specify the local bind address which is connected-to privately by the
  local `tor` process when a remote node connects to your .onion hidden
  service.

## Added functionality

- Added wallet-tool

- Added a new logging option, `-debug=httptrace` which logs all HTTP data
  to/from the internal JSON-RPC and REST server, including HTTP content.
    - This is an advanced debugging option intended for troubleshooting the
      low-level JSON-RPC and/or REST protocol, primarily aimed at developers.
    - This option is not enabled by default, even if using `-debug=all`, and
      must be explicitly enabled using `-debug=httptrace`.
    - Unlike the regular `-debug=http` debug option, incoming strings and data
      are *not* sanitized in any way in the log file, and are simply logged
      verbatim as they come in off the network.

## Deprecated functionality

The `setexcessiveblock` RPC method has been deprecated.
Please use the `excessiveblocksize` configuration option together with a
restart of the node if you want to adapt this parameter.

An upgrade to Qt version 5.15.3 is planned for our next release.  As a result,
compatibility of the release binary with some older Linux platforms will be
affected:

- Support for glibc versions older than 2.27 is now deprecated
  and may no longer be supported in a future release. This will impact older
  platforms like CentOS 7, Debian 9, Mint 19, and Ubuntu 14 & 16.
- Support for platforms that lack the X protocol C-language Binding library
  (libxcb) is deprecated, and future releases may require this library.
    - This library seems available on most major Linux distributions but we urge you
      to check your node platform and notify us via a GitLab issue or via a comment on [MR 1524](https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/merge_requests/1523)
      if you do not have this library.

If you are presently running on such older platforms, please upgrade to a newer OS
version ahead of our next release.

## Modified functionality

- Netmasks that contain 1-bits after 0-bits (the 1-bits are not contiguous
  on the left side, e.g. 255.0.255.255) are no longer accepted.
  They are invalid according to RFC 4632.

- The `-whitelistrelay` default has been restored to enabled. The help text
  indicated the default being enabled, despite the default actually being
  disabled. This has been broken since v22.0.0.

### peers.dat file format

The node's known peers are persisted to disk in a file called `peers.dat`.
The format of this file has been changed in a backwards-incompatible way in
order to accommodate the storage of Tor v3 and other BIP155 addresses. This
means that if the file is modified by this version or newer then older
versions will not be able to read it. Those old versions, in the event of a
downgrade, will log an error message that deserialization has failed and will
continue normal operation as if the file was missing, creating a new empty
one.


## Removed functionality

TORv2 support is replaced by TORv3.

## New RPC methods

None.

## User interface changes

- `peers.dat` file has changed format due to BIP155 / TORv3 support
- `-blocksonly` option has been unhidden on bitcoind / bitcoin-qt command line help
- `walletlock`, `walletpassphrase` and `walletpassphrasechange` RPC methods
   were lacking documentation, which has been added.

## Regressions

Bitcoin Cash Node 24.1.0 does not introduce any known regressions as compared to 24.0.0.

## Known Issues

Some issues could not be closed in time for release, but we are tracking all of them on our GitLab repository.

- MacOS versions earlier than 10.14 are no longer supported. Additionally,
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

- On Mac platforms with current Qt, the splash screen can be maximized,
  but it cannot be unmaximized again (see #255). This issue will be resolved
  by a Qt library upgrade in a future release.

- Race condition in one of the `p2p_invalid_messages.py` tests (see Issue #409).

- Occasional failure in bchn-txbroadcastinterval.py (see Issue #403).

- wallet_keypool.py test failure when run as part of suite on certain many-core
  platforms (see Issue #380).

- Spurious 'insufficient funds' failure during p2p_stresstest.py benchmark
  (see Issue #377).

- `bitcoin-tx` tool does not have BIP69 support (optional or enforced) yet.
  (see Issue #383).

- secp256k1 now no longer works with latest openssl3.x series. There are
  workarounds (see Issue #364).

- Spurious `AssertionError: Mempool sync timed out` in several tests
  (see Issue #357).

---

## Changes since Bitcoin Cash Node 24.0.0

### New documents

- `doc/bitcoin-conf.md`: restored and updated bitcoin.conf documentation

### Removed documents

None.

### Requirement for MacOSX 10.15 SDK for OSX dependency builders

Developers who want to build the dependencies for MacOSX or do
Gitian builds, should follow documented instructions to replace
the 10.14 SDK with the 10.15 version. See `depends/README.md`.

### Notable commits grouped by functionality

#### Security or consensus relevant fixes

None.

#### Interfaces / RPC

- e7db72fbf11ed371891dd9e207729f3ef2f01c33 [backport] net: don't accept non-left-contiguous netmasks

### Data directory changes

- backwards incompatible peers.dat file format as part of various backports

#### Performance optimizations

- 434868e23c72536c17c13e75bc83a32ce40acb0a Abort app if `-conf=` explicitly specified, but it doesn't exist
- 36e91bc2eb4df8d603272d49512091c360fd9ab7 Add checkpoints for May 15 2022 upgrade for main and testnet chains
- f10a2f5ae3dad8edd57456eb446ba11e3edc6528 Bump protocol version to 70016 + only send sendaddrv2 if peer is >= 70016
- 285398060dd71a6f44debb6de0e3c2ad6d6ff6cf Hardcode height for May 15, 2022 consensus upgrade
- 09aca4542e28af36ba97960f99133406ac260bf4 Simplify and speed up string utilities
- a58bdb54306859c3d359cb35c21ebaaef71c697b Small performance and style nits in asmap.cpp, asmap.h, etc
- b6ad03a8d4f1fd756277bd1b7115b549a162dee4 Update chain params (assumed valid and minimum chain work)
- 3d5042024894619f7551a4156e6756e44fa751c9 Update chainTxData for main, test3, and test4 chains.
- cb76df2719f28e7f1bc7be93974da6da7514378e Update checkpoints for main, test, test4

#### GUI

None.

#### Code quality

- 40144dc29bbf6bdd1fd333c909f43eed9c114c1b Add NonCopyable util base class, replace boost::noncopyable
- 74724bc358cb95a52eed3a2303c5c594e0967aab Add a follow-up note assumptions made in CAddress w.r.t. extversion
- dffc50c8073258d0ea3ca4ade4f6d8a4cf485a5d Add internal string split function
- c6aa3a474ac13c61e03953e89d8d9217d3c5ea90 Add new Amount::ToString implementation
- 3e32cd822e2daf2256bd2ae6984d246733463ba3 Add safe reset functionality for signature cache
- fdfe72acc49ca722315db72bc637e079eaef7379 Added SharedMutex lock to sync.h, plus fixed deadlock detector
- 493e7d6de0c2dbee3c92c32642cfee20a34bcc73 Cleaned up backport PR19628, made more idiomatic and safer
- 74fb105f90bb237d4cb39ccf44b1e2d7fc2d9482 Code quality and other suggestions for backport Core#19845
- 3f9cb24af86289f54d0d436580bed542978758f5 Eliminate boost/cstdlib dependency
- 337cb8026972ac0555df2789a5efc64c7d531fff Fix `net_processing.cpp` to no longer rely on C++ unspecified behavior
- 09c67eb0b889198db99a06db9924d2004ed3fb06 Fix bash script shebang
- 6805f9ac4009c6a17ff394ee961f5529794173be Fix inappropriate C-style usage of class uint256 in base58.cpp
- 9075d07e6541a77b0866fdf10663da0a441509da Fix intermittent failure in `cuckoocache_tests`
- 28900ea18965d6adf9139d75766355d1ea3be955 Fix minor formatting inconsistency in script.h
- 18364167bdb6a8ff76aa31e545c15ccfc5d97aea Fix to GetRandomDuration
- 3899d9838503189a809f22403406384e44da341c Fix up `ConvertBits` function to always have well-specified behavior
- e6d63562d80eb4978b84665ae5841dcb76babc92 Follow-up for core backport PR 19628
- 1e5893329298bb93be7d04c6d089d8e01c176433 Follow-up to: Restore compatibility with old CSubNet serialization
- adee8e9ada7629d346111d3b290d0d7ed1418257 Ignore unknown messages before VERACK
- 64cabd5b7b22e22f89510ac835fc4e181927c9a4 Impose sane limits on excessive block size and txn relay params
- a61aa0aaead2e020f5eb887f9a59987b3e591b11 Locale independence in net.h getSubVersionEB
- 7dc7262c0b5e28b048a7b44140e7234aabc8ac2e Locale independence in tinyformat
- 78a9e09f483b0fd81ff3e56b62cdc3adfb764524 Refactor serialize.h: Simplify and remove duplicated code in (Un)Serialize_impl
- 889b8a106948763f99a9a8c0079c3ca25c86d438 Rename GetAddresses(Network) to GetAddressesUntrusted(Network)
- 202333715cab0e7fc82f0122b7e3ed277eeffd75 Replace `boost::split` with a custom implementation in `util/string.h`
- 17eabcaa228e054afba5ebd30fdcad7613a25ad6 Replace boost split algorithm with internal Split function, ditto for trim
- 7365b00e6396304e5ba103bef806a14155c539d5 Replace boost::replace_all with internal ReplaceAll and std::string functions
- d4028fe6abd6ebcb716d974bba9cf6f3d68b18a4 Replace include header guards with #pragma once
- 73a8cf8e73d5a94ce105a7a7d3c488b9a7365ac3 Safe file list expansion in doc generation scripts
- f9613c96bf3cedd6f8a6ae236ca7acf08ef9f793 Safe file list expansion in lint scripts
- 19962171f6bd4f882c4210732a87c96f8761bca4 Safe file list expansion in translation scripts
- 1f03347491c3546c958007c6685170144106ebfc Shell code quality in git-subtree-check.sh
- e5ae41063574f2db73900a5fbf8a70f74b5222cf Shell script code quality improvements
- ebf2d003352706f447b4f442490f8731c9a0b104 Simplify safe reset functionality for the signature cache
- 0fcaae0e6f4c360aa6f68bf3adfd2672d4e961d7 Suppress spurious maybe-uninitialized warning for ScriptExecutionContext class
- cb35373487c0bb2847641bd33784234f3cea954d Thread-safety fix to address cache in CConnman
- bac667cc8485d94b28b1ea70b339df77fc3aeb73 Trivial: Fix whitespace on recently-merged MR 1355
- c0be9a2147809a0c0b81ab8b5db8e1755cfe406c Update copyright year to 2022
- 787896c7f0a3b300d3d9236d3d602de0a4fe0a46 Zero-initialise members of CExtPubKey
- 691f1d84699f675dcfc61f35636e766ed3c0567c [qa] Bump version to 24.0.1
- a2360e6aa46f16ab24d2b997cb66201b005011b9 [qa] Correct the checkpoint for first post-UAHF block
- da74edc6b93d306abd0efdf08b3f696d36709c6c [qa] Correct the checkpoint for first post-UAHF block for testnet3
- 223983f21d8a7f62e0d10534da7accbb4a7d89b9 [qa] Fix checkpoints for the DAA activation block
- de97d3956bf0060116e25e5ababc6abc2e82f86d [qa] Fix silently failing SignSignature call in denialofservice_tests
- ad342e62418fe6e5c8787e4d575f62e8377b588c [qa] Fix spurious error in gbtl-bg-cleaner test
- 907a71b99fb683a07e6fd4000b6547c80a39b75d [qa] Fix testlib_tests failing when using GCC with ASAN and/or TSAN
- c615bb8706680ebcb67ffe71d64d4c00352176e3 [qa] Lint test/ folder
- f9417f4120c3e3da4938d258d4e9e933b959d0a8 [qa] Move activation tests upgrade checks from Axion to upgrade8 (May 2022)
- 5bf0020fd94afaf88f7ae0138e39ef970fff7f47 [qa] Move the v24.0.0 Release Notes to archive, clean out current RN after release
- da88f7a258e103e97848591821d3c97cac391f9f [qa] Remove obsolete miner fund activation test
- d495b38a8f9a21f5d353d61b3f6dbf6e5c7c18d0 [qa] Remove unused imports
- a4d9a446a076eda8ba53fad20dff5d2ceea60ca5 [qa] Suppress spurious maybe-uninitialized warning with GCC 11.1
- 31c1decaf3ee61f229af4478dacc7f9c883d7002 [qa] suppress leveldb TSAN warnings
- 70905b8d2bbbcbb62b69cdfcb03f6f7335dd9ca3 [qa] use self.sync_* methods everywhere
- efe9813c52a8311e98136bfcfea82dae484f70eb [qt] remove deprecated Qt::DefaultLocaleShortDate
- fb9e6eee216b626a62913e00a4e7086ee772c1b6 [serialization] Change all Ser/Unser methods to be static
- d0f3bfa992ee0b3c98af3096988d2caa4418d761 [serialization] Convert the rest of the old style serialization code
- 34f8f0fcf3a3b5b695479a446fcf23bf4f529de9 [serialization] Improve type safety of AmountCompression
- 2ae3bb29ea7a41bc09c780e49cec48fcde49c935 [serialization] Improve type safety of DifferenceFormatter
- 3e38cb2b138f306ade650767865433c6cd345566 [serialization] Make CustomUintFormatter and CompactSizeFormatter safer
- b9cf9c31e8322413f242b5e07bac3218daca4238 [serialization] fix GCC variable shadowing warning
- 322c1d0bab16b9662bfedc53382aa7af1c522e2f avoid signed integer overflow
- ce791d22a578cf89b73117fcd665fef40f3a0373 net: Add `CSubNet::GetCIDR()`
- 30b8804cf7fd0d2cfd293ddd9b5d882ac1ee33ce net: Add thread safety annotation for CNode::setInventoryTxToSend
- 4962ef4f582191444296b57b5e5889293f5bef76 net: Return early when poll or select return zero and use MillisToTimeval
- 3736b0e3a10202fb2d4d53f206b2610c5228a945 net_processing: Clarify vInv nMaxBroadcasts expression; fix reserve of vInv to be correct
- 1d39a84f384be0fae3a4da7d40cbbc56534c23cc net_processing: Fix overflow and limit vInv reserve size to MAX_INV_SZ
- e3b648f83ea3e01cd22eac46244ab69731733b0c rephrase conditional to avoid false static analysis missing return warning
- 9238df7dbae44cae6caa6000ff4aabe6584b8fae replace fallthrough comments with c++17 [[fallthrough]] attribute
- 86e0d978ee2313d0f07eaeac279e593feadc13c8 scripted-diff: More command to message type renames

#### Documentation updates

- 80fe2ff155ae7cb4d2b062d93c6a74b072cf87bb Add release note links for v23.1.0 and v24.0.0
- 585bf27b1d43f886b7f09c128d9e155e5dcdef6c Change recommended draft MR title prefix from "WIP" to "Draft"
- c95c9c602d897a9a92d0a876e88978e6e9f33ecf Fix broken URLs
- 98c87672448789c2384c07624118143882d2745a Fix walletpassphrase, walletpassphrasechange and walletlock RPC doc
- f5d7b0adccb6ad1ba49c6bbe09eb6e5091b2df6e Markdown code quality, 1 of 5 (enable markdownlint in codeclimate config)
- 88c55b094c41c1cb789b4bf00fa905d084a100a7 Markdown code quality, 2 of 5 (whitespace related improvements)
- 307c9363d547b17bb18fc210bda8fbbf272c29d7 Markdown code quality, 3 of 5
- 997af1ac0d87961fe93391fbf2c79a3b79643858 Markdown code quality, 4 of 5
- 26ddfccab031194b76546e574dcfdf30e9abb3a3 Markdown code quality, 5 of 5
- 071234e94e9205d0a9f85572cbe5190f95e40bcd [doc] Add back a link to benchmarking instructions
- d10dd6d4f3eaeb2545bcd9e10f055ba4a3fdb238 [doc] Include missing dependency install step
- be3bc5400635c4c6406f8558a79f914f91336e61 [doc] Include section on Merge Requests
- 3bca219ca25026757f68a49fea0c1ae5163e5dd6 [doc] Remove outdated and misleading leveldb docs
- c73be96adadde087c5e3d39a7fbdcb0066e7ae27 [doc] Restore and update bitcoin.conf documentation
- 2eca96cbea53413cbebccb5f5b7855559dea6fe0 [doc] Update doc/bips.md to mention that we implemented BIP155
- 2a6030d999206837a24b63068048e92da39bd61c [doc] Update im_uname public key
- daa431e008068c9456c70202885a253fdea94069 [doc] Update relaese-notes to talk about changes to `-bind=`
- df6fde4be0a5fcf6c771145bf4dbb3035ca82c34 [doc] Update release notes with whitelistrelay change
- 2b85f6d6f01e8936d4add6b03b036c4205c7903f [doc] Update the REST API ports list to cover testnet4 and scalenet
- e2c6689018dd0ffaa058f565c22c652449fdf962 [rpc] Deprecate setexcessiveblock RPC

#### Build / general

- 127c9d4422c4ddf809e1f3c77ddb724c8799fabc Add linting of include header guards
- 5f633539d081e6f7bffd54c282c7b01240139042 Add unicode linter to `check`, `check-lint` ninja targets
- af0d90da6aaaf74a2baa92642fa9ba0573b0da9f File permissions
- e8836d9ddce587f0668d66eb558959bce3a9a191 Improve compiler warning configuration, enable additional warnings
- 1c8edfadeb41f58d00d810a9b9b8e43a3a05c21f Remove install target definition for bench_bitcoin
- a936586bdf28459b87063f9a14247f9a06be483b Resolve CMake policy CMP0071 OLD warning
- ca12639397724cb749512a545b7b9e7e8045869c Set explicit cmake policy for CMP0116
- fae3ead512dab5d163ac75d78096ee0d4e686558 Test build config cleanup
- 9e93ffea5938ca349ae17fd3307cc1a9ffc66af1 Update depends/packages URLs (some have gone stale)
- a272a2c679a3ad004d79b6a74bab9eaa3ab21c89 [build] Add missing dependency for bitcoin-wallet to functional test build target
- a941359a02fa5df48a92a0dd2aa4e1bbb9e87c87 depends: Fix compile error for Qt 5.9.7 when using newer GCC 11+

#### Build / Linux

- 18ac18d845b41473f408f628d56044044ea3e758 Fix bitcoin-seeder compile error seen on IBM S/390x
- 662114a7f7dacd1ffbd08cba6e4652ec706936dd [build] Suppress ABI change build warnings when using GCC >= 7 on ARM
- fbd6c3e6494681a784507383d4036ce0c69ffdab build: Fix boost depends build with glibc >= 2.34

#### Build / Windows

- 79b84ab0c96bca786d66277a732cf86fcbb58f72 Windows: Fix compile warning related to wrong type for `fprintf` format string

#### Build / MacOSX

- b0f242764997b66e5aff55034c4ed17516ab62d5 [OSX] Update to clang-8.0.0, MacOSX SDK 10.15 and set minimum sysver=10.14

#### Tests / test framework

- e440c8568123663e056f6889f9d3a2ebfa89d6d3 Add basic functional test for the new =onion bind option
- bdf1fe656eeda621656158d55a82ee8c57520748 Add logging category `httptrace` to log all RPC requests/responses
- 07b4c80ee9262ac98aac6cac6e99f9053bb1a854 Add serialization test for compact blocks with 10m transactions
- c31eeb2aa69031fbb0248a6f4e01ec57d1dc0f68 Add string util tests
- 93b0af33e227f55bb04b9dfcba6ff3b1f41931fc Add test for no-wallet condition
- 5a2ac38bb57e46a60f3f02eb43272e87174777af Add tests for ToString() functions
- 6e4ee17750699092fe86e0e03a3c4a314f207187 Added a test that the node doesn't add to banscore on unknown message
- f6d5813ee8e72bc9156a902d229234c0807029f5 Additional locale tests
- f9b4dd4c231bae3db21ab2c619262d6b62908810 Don't start node twice
- 5327b7b10168db7f168a3b2d257f5b2af5f83c0d Fix `gbtlight_tests` failing on Windows in `test_bitcoin.exe`
- f576370cd9db280bab770838524e1b0c4e4e2732 Fix broken call to sendmany in p2p_stresstest
- 084724c32ad5877e1fa86f33795de49e7980dfb6 Fix check assert tests
- 724ab45fae5d7fdd0ddebbef4744fc2edf8d5a9b Fix test_bitcoin to not collide with instances from different users
- 4c6a48678b20e79188d7bcc3e859d95c165b3c10 Locale tests
- 92c25e29d4636e49118ff54371892e9ef33fbe4f Run tests with eatmydata if it's available
- 1df51732262ba24deee5b3587e3a5a1c9c32a664 Windows: Fix `test_bitcoin.exe` failure in `util_tests`
- 052beaaa98eecdd0ef3e3ddb5851c9a7876d0732 [test] Find emulator on path if it does not exist
- a2e06855ff4a3ed047c79e35690685ccbd2071b3 [test] Pass the correct chain config argument in the tool_wallet test
- 1c35876da8fea9c640bad58601e6c7362d7709e4 [test] close the socket in test_ipv6_local
- b68991ef399ef05016c9a772e696dc09b2718e1c test: Add banlist deserialization test
- 7a22a721fe922808871a3bbb53fca76770bd9b00 test: Add extra constraints to a p2p_filter.py test
- 410dca3c60ad90142304a495ef761603f2471441 test: Check that calling walletpasshprase does not freeze the node
- 3658d6938d7c289bc6820183e79653489be61cb9 test: Fix race condition in p2p_addrv2_relay.py test
- e2a48f72470c5b8979cb7b0b938a7be72f9d7fec tests: Add more "Split" unit tests to util_tests.cpp

#### Benchmarks

- 02e12e0dfcbe312b06fc037c8442807aa714a562 Add benchmarks for CheckBlock, CheckProofOfWork and GetHash
- 9f9dfb7f539bef641e174db1345098c2627916cf Correct median calculation in benchmarks
- caf5fda7ed19017fa7f6b5862784e75490f3e41d Remove boost preprocessor cat and stringize dependencies
- 399aec35e67f1f4a8bc094969ff3853552bbf986 Remove dependency on git-lfs; generate .cpp data files as part of build
- fd86938edbdfb760154f268e22957d095f3a60e9 Speed up benchmark list output and benchmark filtering
- f0fd622a47c9adefdf8ba2dd2be6b5ab153102f4 [bench] Add benchmark for CWallet::TopUpKeyPool
- 0d010d68491f36f99a25894f401f28e41315e97a bench: Add `Split` benchmark, also add `benchmark::NoOptimize`
- 516fd2025e6fa02c5610408a3861b2514626efde bench: Make CCheckQueue_RealBlock.\* benchmarks use real coin data

#### Seeds / seeder software

- 5c4143225a75ecfe0655ca2365e62e417a480f00 Restore seeder: bch.bitjson.com
- afaa033c26fb37c46fdb10f7302940914848745b remove vSeeds entries for which lookups fail to resolve
- 80f23dc2337e3acd3143ec808fae9c5f8b7b47e0 seeder: Add support for `addrv2` message + TorV3 addresses
- 3979891a1d42ed1948982d959f5f49b3b97cc50a seeder: Use poll() instead of select(), if supported

#### Maintainer tools

- 1122bcf517be972042caf85bddbc58e87dec588e Add script to poll bitcoind for MTP to elapse and broadcast a transaction
- 1a5f6c8010d72b1ec9c49770d2b304786dfdcb77 Contrib script to compare benchmark results
- 5726c664a49b066d4ddcbcb76f907e0a29b40798 Update .clang-format: column with to 120 & break template declarations
- 36cefcd26c34b9b4d20ddef21e877021d99b444f clang-format: increase the ColumnLimit to 132 characters

#### Infrastructure

None.

#### Cleanup

- 8db49986925f1610c43985d0e0f52444c1d59d74 Unused preprocessor definitions

#### Continuous Integration (GitLab CI)

- d494157e392a6ea40640231e0288bfa7ee4969bc Fix codeclimate depends/SDKs exclusion path
- a7802d4be0d6a61416ec70d77eac704a72ecc0fe Gitlab code quality configuration
- ac7f925d2bbf01b00c6106d228cf279275c8a0e6 Lint format strings fix
- 9405d4428357ead9d47e1c256413ed3d52e94640 Remove redundant boost dependency linter
- f3f89e67e7f298644e29d1e0e00edc3559531c6d Update to latest CI image, use Clang 11
- 60f03ed1ab7197bae61ac48a0f7995e8a0ac65b8 [ci] Fix for recent breakage of CI due to a jinja2 update
- 715ddd83a22c87c61df96a5a775d3ba33324d13f lint: Add shell shebang linter

#### Backports

- 717ec52af7b5d578c5e1c4ebe8bd1b107d104baa [backport] Add CustomUintFormatter
- 97b37e0344a04123db12bc3e8a6465b08f08d456 [backport] Add DifferenceFormatter
- 621dc83b57673c30ae22cbf6f56facfc75bbae03 [backport] Add FORMATTER_METHODS, similar to SERIALIZE_METHODS, but for formatters
- 3f16760e85c1ddc3c79b38e133d6d02fdff30ebf [backport] Add MakeUInt8Span, to help constructing Span<[const] uint8_t>
- 0cbb1c0f945aac18af13facc1fc5d5c403dbe36c [backport] Add SER_READ and SER_WRITE for read/write-dependent statements
- 63345f3099eee2dfad25d20bbd865ea55c2cbfd5 [backport] Add SHA3 benchmark
- 3edbf6ae8ce47540e375bd3645cf3f38cc745758 [backport] Add Span constructors for arrays and vectors
- 960548d6bdeeb8ed9e6e7a8ede3698d9f7c5d46d [backport] Add a constant for the maximum vector allocation (5 Mbyte)
- f38f1f13acbc9a21eaef99248e424dc474cbe2e5 [backport] Add a generic approach for (de)serialization of objects using code in other classes
- b34f46c0060b9973287779c1bedd82db9ac69828 [backport] Add additional effiency checks to sanity checker
- 652e21e6417bc6255e5928edfc4868629777a2e7 [backport] Add addr permission flag enabling non-cached addr sharing
- 65dee6594c403bb0fe2bbb30b40d8c36f78b55c0 [backport] Add asmap sanity checker
- a43471e8bb99c39f0792ffb93c7403b47b0b356f [backport] Add asmap utility which queries a mapping
- b442fbee0758e1c3cd1934ecbb3d961f7563bb1a [backport] Add bounds checks in key_io before DecodeBase58Check
- db20f51f13b4bc7ce9f01ad51375852dc83e5985 [backport] Add comments to CustomUintFormatter
- d8f8bab1631c4bda5e32efb18db1ca0d7b865174 [backport] Add custom vector-element formatter
- e4eabc3caaf8790d6b88ddc321b6d2f7dfa233b6 [backport] Add extra logging of asmap use and bucketing
- 4b694245c01fe410f9c2c348eae33067dc55b350 [backport] Add indexing ADDR cache by local socket addr
- e864db3725dbb306eda27ab666541a9ac01a9fb6 [backport] Add missing typeinfo includes
- 78f55d9430ceb8012bc69a999385ada3c71e7a0d [backport] Add sanity check asserts to span when -DDEBUG
- 958a6fb5f67507f1f7f4f7a59ef84c9e5519c322 [backport] Add some general std::vector utility functions
- de48f74970ac47e7d5151e4b3996f5afd81c313e [backport] Add templated GetRandomDuration<>
- 8e82bfa84a8475a393b8c39a782954d07a688cea [backport] Add test for serialization of std::vector<bool>
- 275b496bad97f18745a4f2a9408edc2deab1bd6c [backport] Add tests for util/vector.h's Cat and Vector
- 285b670a273def6ee9d14022e032a28816d0a68b [backport] Address nits in ADDR caching
- 55d9c066f89e87ffc57a5b9fc62332a5b2069b8a [backport] Avoid asmap copies in initialization
- fce06cbe18f616e1a0d0ec318cd568d21db81ea4 [backport] Cache responses to addr requests
- 9bc9c239d990d333101052da9cf12fc527ce6930 [backport] Convert CCompactSize to proper formatter
- 50e9d531ea88c58ed8a73fafc6eb6f2d6f94f9f6 [backport] Convert LimitedString to formatter
- 9636c1712342428419a707b13504e52a86fa1c8a [backport] Convert Qt to new serialization
- 27960c7ce442dfd23d917c771c58dc0f8b653cd3 [backport] Convert VARINT to the formatter/Using approach
- a30876661493e55d72f488504bb4b0d0f0d8deaa [backport] Convert addrdb/addrman to new serialization
- dff81a926bd24802f96757726099163e47255349 [backport] Convert blockencodings.h to new serialization framework
- 56ed73ffb0c607f90ecebfdf216b186f3765e26f [backport] Convert blockencodings_tests to new serialization
- 42a74eeb0b897204989857dcc48f290151ad4a7f [backport] Convert chain to new serialization
- d61173edf7a96557e299f847275a609cd5c10aaa [backport] Convert compression.h to new serialization framework
- 0f96fb347b62aad625331fd574345b253e0e1941 [backport] Convert everything except wallet/qt to new serialization
- 5eea2a3a18f3e034a618a06fa3a476364adfb864 [backport] Convert merkleblock to new serialization
- 641f1b4930f1b6710a99770c348a5604a1c6c031 [backport] Convert undo.h to new serialization framework
- b97476046760c07ee0e7b46cdc05ca1b9a8aece4 [backport] Convert wallet to new serialization
- c086b31a86f936b192864bfb9720905c5bf54002 [backport] Deal with decoding failures explicitly in asmap Interpret
- e1b2ccd95b36a86979a21d9600774016ec0bcbc6 [backport] Drop CADDR_TIME_VERSION checks now that MIN_PEER_PROTO_VERSION is greater
- 8fadb5b1183faf376acf23d009bc3fa42837ed90 [backport] Drop defunct Windows compat fixes
- 7047215418e2e794e48f9c41dd80a2bd2502e41d [backport] Extend CustomUintFormatter to support enums
- b0a13b62f82907996452479213ac118a181a91ec [backport] Fix "invalid message size" test
- e579ddb3f02e6b946f940c6aec5b78f1baf412e6 [backport] Get rid of VARINT default argument
- e3714551df41377ac68004e80184652fe87624a9 [backport] Ignore incorrectly-serialized banlist.dat entries
- d73a178b7b76349329533eaba499e57649fce5b8 [backport] Implement keccak-f[1600] and SHA3-256
- d8db1c462dfcba6c74423bbfc2d3942f15e2c86a [backport] Implement poll() on systems which support it properly.
- 15ff575f77425d1ae09f784ee350267f5544a3cb [backport] Improve asmap Interpret checks and document failures
- 4c061d80628c5c30cab056f539e10cfbb509588f [backport] Increase maxconnections limit when using poll.
- ed252045dfe85367787eb27e532365dea2a5342d [backport] Integrate ASN bucketing in Addrman and add tests
- 74ef6e8e7f9f52fdc22448324de9a3412afc094f [backport] Introduce Instruction enum in asmap
- ea3de55b97b07effa42f00db5a2c8748768f3c3f [backport] Introduce and use constant SELECT_TIMEOUT_MILLISECONDS.
- 0c47fc740db6ba93b1de18c0774ce1f11a2d6d77 [backport] Introduce new serialization macros without casts
- 166282c8b1c96b1ab05747142f51071f99b21e9a [backport] Justify the choice of ADDR cache lifetime
- ae36bfbaf52e99c822e78d5f5129d600bb2b0254 [backport] Make CHash256 and CHash160 consume Spans
- bc4e5a0f36f97789989f93a3a48efa36475fc018 [backport] Make CHash256/CHash160 output to Span
- 6554122dc2af1660fb46106845530f80a0ec5fd1 [backport] Make Hash[160] consume range-like objects
- f53d373cc635886d394db573f69cf257429a341a [backport] Make MurmurHash3 consume Spans
- 2d7d88559798111d33fd9450dc3f9b60ea99a41c [backport] Make VectorFormatter support stateful formatters
- bdaa644f9c072e3d5e504a1fed30796d25480d9c [backport] Make asmap Interpret tolerant of malicious map data
- b60fcbedf0e3e03c6638306934feb21b4f6a785b [backport] Make asmap Interpreter errors fatal
- 5451ea3dae5d07a9d08fec55dc8d30c3d567788a [backport] Make pointer-based Span construction safer
- 76977461709fc32ff1bf09132354f1ccded8faee [backport] Make std::vector and prevector reuse the VectorFormatter logic
- 2bc5fd30c1c7d357bc32ee78050730c6e66518e5 [backport] Make uint256 Span-convertible by adding ::data()
- c2b87da9c08d1b1897cb03ab1df2e3902d36edb9 [backport] Mark asmap const in statistics code
- e8ff6b5429c0a516749ddcf50c2468079ea56dc3 [backport] Merge BigEndian functionality into CustomUintFormatter
- 1095205429d30c769757abed4c472f8dcc076e3e [backport] Move GenerateSelectSet logic to private method.
- 1f7977d0d09dad70f3dfa6a451351076584257f2 [backport] Move SocketEvents logic to private method.
- 18f807eb6ea84811826808ba30d8afae26e8157d [backport] Move filtering banned addrs inside GetAddresses()
- 5d395f4d492d1e0b9a3232da2fe5dc40b8a2c165 [backport] Move size limits to module-global
- 84696de136c7937b4653138aebac4faaa2a51b99 [backport] Pass a maximum output length to DecodeBase58 and DecodeBase58Check
- 66cc37bf8126d6f50887257f7301ed00b8153cc4 [backport] Refactor resource exhaustion test
- 2eaba3f663d560489a24c8525d72eeeb898b31a7 [backport] Refactor the functional test
- 0182ba6b83ce01459eb35adf4b24ca5d9557ecdd [backport] Remove old serialization primitives
- 9ed38baf03c3fb808707b1c5f9b0ad390e011234 [backport] Remove two unneeded tests
- e867af3d56bcd31b9d70c65dae0b723f8bd2b106 [backport] Remove useless 2500 limit on AddrMan queries
- ccc1140247a566832df87836d6e84b711ac27857 [backport] Replace `hidden service` with `onion service`
- 4d96bc551477450eff970990da729ddd030d44c3 [backport] Restore compatibility with old CSubNet serialization
- b0f11d45fda78fcbb71e0458b468a1519f0ad286 [backport] Return mapped AS in RPC call getpeerinfo
- 22065c07afdb4d6e543729b6579fde0257832649 [backport] Send and require SENDADDRV2 before VERACK
- 26633ad6162dbbf137d85ced056be8237bc5f7d3 [backport] Simplify usage of Span in several places
- 424299a40e255450637dc9e74ad111074b423b24 [backport] Support bypassing range check in ReadCompactSize
- b51ee68bcd3e6609f9e283a84dedbbac97df21d1 [backport] Test addr response caching
- 6d1f199f3d711fa60571eb85b5f03b823e6db20d [backport] Test buffered valid message
- fe97ba222957b95c5055c8a0a5c8d8510919c61b [backport] Unroll Keccak-f implementation
- d15b41fa1ee1d9502433800dbf66f4af21502873 [backport] Use ASNs for mapped IPv4 addresses correctly
- 8c8c1b7458e0fe1e36191a3cc9bc47248d06bd9b [backport] Use generate* from TestFramework
- eb14755c3bf6c4f31e13c93cef13689e21e06249 [backport] [Fix] The default whitelistrelay should be true
- 7eaa206aa1c2c023c99e5a182394256582226607 [backport] [addrman] Specify max addresses and pct when calling GetAddresses()
- adf9fcaef3e8908d3c603c06cda95b93104c82d8 [backport] [net] Add addpeeraddress RPC method
- 29df90edb040d8d858c19f7a2622ebccdceaf4a2 [backport] [protocol] Remove unused CADDR_TIME_VERSION
- 26ea57e92f14e7cf41e8347ff092def91e9d1aca [backport] [protocol] Remove unused GETHEADERS_VERSION
- fd98e6d86f2263d7d93bc5a60318e9cdb062c74d [backport] [qa] Add settings merge test to prevent regresssions
- cd3250e4fa0b74297e54bfe7244f06b18488c720 [backport] [qt] Fix deprecated QCharRef usage
- 2632ae732275a5c0258deaf64df7a16accc556da [backport] [test] Remove final references to mininode
- a4238b39cd8015c898f02bdf579e8daa0c31177e [backport] [test] Test that getnodeaddresses() can return all known addresses
- 213c0e0805d2260ac7976cdf60e4f922e7a7a0fd [backport] [tests] Don't import asyncio to test magic bytes
- 6480eef327e14199b6750b63871c6b48685fc12e [backport] [tools] Add wallet inspection and modification tool
- 0d8111fdd7b0ee7b002cf672f30459b873f9e51b [backport] [tools] add PoissonNextSend method that returns mockable time
- dd6fc3a2c8abaad6dcca3f0d08cc72f0fa85aab5 [backport] [tools] update nNextInvSend to use mockable time
- cf93df351b7854864260c5e2d86dfe347417e62f [backport] build: Remove WINVER pre define in leveldb CMakeLists.txt
- c2c9a8923927e6717dcae45513a2450abf8ce5e2 [backport] config: enable passing -asmap an absolute file path
- 3c346670d2923f7dff975dfa2754f0254a850f11 [backport] config: separate the asmap finding and parsing checks and update the tests
- ab5748a863349ec56108478c2bb10fab9e8c4960 [backport] config: use default value in -asmap config
- fa8f4cea6c64438346d44e11aeda4b4a1b11226c [backport] doc: Document Span pitfalls
- a0279d2266ef91aebb35cea9c588ccb0626f7893 [backport] doc: Mention Span in developer-notes.md
- ad9fd000ac8da1ea475e35f7a3a58af9f39478fd [backport] doc: Mention blocksonly in reduce-traffic.md, unhide option
- df1e140b08a1f3b1cd7a3c33f08c6e17dce11474 [backport] doc: Update onion service target port numbers in tor.md
- f934f1dd35e1f89354fe7546aadad10e14d77334 [backport] docs: Improve netaddress comments
- 291326110bb98d46c490d49feeaf432a80b08c6e [backport] docs: Improve netbase comments
- a87675bcc7203f053c82527951e4ad60161838ac [backport] gui: display Mapped AS in peers info window
- 114709d1c6f7cb345023b263dc0a8cb45f0f8535 [backport] init: move asmap code earlier in init process
- d74da61e8b07d0f8d57bb7a67fd433c5cfa1a21d [backport] logging: asmap logging and #include fixups
- ad2e96e63e4621f0c3fe7ff19a2fd9d8a4b47c00 [backport] macOS deploy: use the new plistlib API
- 0594ca43a813ff12bf3c4953755730371a20cd91 [backport] net, refactor: Move AddLocal call one level up
- 925a51f71fbe5d44eb056ea112f948e85786d367 [backport] net, refactor: Refactor CBaseChainParams::RPCPort function
- f277c7c83398c6d2ed3e731903ad1d03b41e7a55 [backport] net: Add IPv4ToString (we already have IPv6ToString)
- 89fc531a8e0a3272a48ac79a5a4d05781638e192 [backport] test: Add test for GetRandMillis and GetRandMicros
- 286e2f826442272d494f5719dfb92da2e45219d4 [backport] net: Add alternative port for onion service
- 5c315e1db39afe5e83627848a6baa99364815574 [backport] net: Avoid calling getnameinfo when formatting IPv4 addresses in CNetAddr::ToStringIP
- 05cd5130982fdcbb66366200f8eeaa263d801497 [backport] net: Avoid using C-style NUL-terminated strings as arguments in the netbase interface
- 4a40c67cc2333ea620bccdc849d08f3d337d7e6c [backport] net: CAddress & CAddrMan: (un)serialize as ADDRv2
- df94bc5e0f5ebb5955fae77c298bad741f179fcf [backport] net: CNetAddr: add support to (un)serialize as ADDRv2
- 805813dfad9b479d1badea2ff99da5b5aa2748c4 [backport] net: Extend -bind config option with optional network type
- c9fc939dfa438cb28883eee541648bc0945da986 [backport] net: Log to net category for exceptions in ProcessMessages
- 803de3453fec830f76acc1f7157d5e33e4870931 [backport] net: Make addr relay mockable
- e53499e16c564a84df36b72e56a9819da05b067d [backport] net: Make poll in InterruptibleRecv only filter for POLLIN events.
- fc41d41db886ccd2b5ee5b91eef40d10252d810e [backport] net: Pass connman const when relaying address
- 857806c4e3c970108581550ce6e6f6925e6d1a8f [backport] net: Pass onion service target to Tor controller
- 2e813d191b2017c7626f1af0026b563f425b853d [backport] net: Remove un-actionable TODO
- 5a78a9960d9b788ff1d74101dd6efc53aa1117f6 [backport] net: Rename ::fRelayTxes to ::g_relay_txes
- 8c2244dfe9a1f58c96d02f0cafa82e21d246246a [backport] net: Use C++11 member initialization in protocol
- c79dde923a5e8c81917e33e368fb9faca587b465 [backport] net: Use network byte order for in_addr.s_addr
- 52109b7158fa56e9e576b3d31092a96fed9f80d3 [backport] net: advertise support for ADDRv2 via new message
- 084265a60d79740d7ee8fa04b4d315ef71c1c21f [backport] net: change CNetAddr::ip to have flexible size
- 500ec7aa5c219f92a7f1900904b17adb6f3551ee [backport] net: document `enum Network`
- e7db72fbf11ed371891dd9e207729f3ef2f01c33 [backport] net: don't accept non-left-contiguous netmasks
- 98fce0a518628c70753bd3a1ae72aad337b651f2 [backport] net: extract conditional to bool CNetAddr::IsHeNet and remove redundant public declaration
- efe217152a3e160517c71eafd99f29306fe92900 [backport] net: improve encapsulation of CNetAddr
- 26f2466e5e58a6617db714cdeb09b2dcd58d32a4 [backport] net: recognize TORv3/I2P/CJDNS networks
- 38edd5c4d5c5cef7eef21d1c96afd0b83f1f830e [backport] net: save the network type explicitly in CNetAddr
- 560ac1c44a52d903b754c9358bd4b9c8424b5662 [backport] refactor: Avoid sign-compare compiler warning in util/asmap
- 807359930fc5c3f4eec18202b73da39fc7e4dde0 [backport] refactor: Make HexStr take a span
- d5352dc1afee4cfd8ef38d9ea169d302d71e41aa [backport] refactor: Rename TorController::target to m_tor_control_center
- 9ea57d2bac55ed8c64c8322d75ada8f33ef4f4f5 [backport] refactor: s/command/msg_type/ in CNetMsgMaker and CSerializedNetMsg
- 2eec70d1ddfb57ce0b2d9557606e4c0598811b90 [backport] refactor: test: improve wait_for{header,merkleblock} interface
- 6bab76d36935ce02b7735d061a8826b9b0f5fbaf [backport] rpc: Use Join helper in rpc/util
- 29aded8c196a7280b11d0cd46be7233e2eebb5d8 [backport] rpc: mention getpeerinfo `mapped_as` only available when asmap config flag is set
- b26b1d0a25f513475d6a13b0dd1cfcf88f6cc06a [backport] scripted-diff: Rename mininode to p2p
- 464106a914dfc7bdcba068abafa8c4efce69c732 [backport] scripted-diff: Rename mininode_lock to p2p_lock
- 5677b4daf36d388fff503da1a2746c8fcc091f9d [backport] scripted-diff: Rename sync_blocks to send_blocks to avoid name collisions and confusion
- c15b2ed34db0053802e84543771b344ce0be8b98 [backport] scripted-diff: Replace strCommand with msg_type
- 967577b2e205bf7a5897acf4d840608ff09beac3 [backport] scripted-diff: rename base_blob::data to m_data
- d1301b451a18fa5d9ea1fea68396d2129cfefddc [backport] scripted-diff: test: replace command with msgtype
- e0083a3990b12f34540d7dfa80528602b303982e [backport] scripted-diff: use self.sync_* methods
- 276995620e6a30af524020845c419f36e50aefa5 [backport] test: Adapt test framework for chains other than "regtest"
- c3ea8823c0bec5e437a33404db6b7ba84d4c3596 [backport] test: Add BitcoinTestFramework::sync_* methods
- b73b19af80445dcf6b51c9c0179cdf1cdd5e6204 [backport] test: Add basic addr relay test
- 2aa9e2af8a26df26956567d76d38db73b7753ca8 [backport] test: Add basic test for BIP 37
- 811d14ff1d26486d5280a1d72d9f7888c267dbbe [backport] test: Add generate* calls to test framework
- d24511dc9aea8e74e0afb8044814323658dfb0d6 [backport] test: Add rpc_bind test to default-run tests
- 1652868e81a65bf3db4430cefdb19b20b73949e5 [backport] test: Add test for p2p_blocksonly
- a8615a3ef4617dc39eecc7c45e595cd841085f9e [backport] test: Add various low-level p2p tests
- 40a76217c8360d51ca4c57e1df81a964da13632a [backport] test: Avoid hardcoding the chain name in combine_logs
- 9368cb70ef44fca3a1eea5f250829c6811b54f11 [backport] test: Check that invalid peer traffic is accounted for
- ee649da36af90a0ee5a73d0dac1ae570fb9da0aa [backport] test: Format predicate source as multiline on error
- d6978ffc03d9ef0e1a826317468bf4ea6be994f8 [backport] test: Pass at most one node group to sync_all
- cda8cd80dd6483a2e55024f04cd8e01f6e8ea737 [backport] test: Pass down correct chain name in tests
- e7b1a668b9472f72b38e662a56b3d8738f5e693e [backport] test: Remove confusing cast to same type (int to int)
- d0d1ad7082fd523f1713f2d8e24f98bba9910a5f [backport] test: Remove redundant sync_with_ping after add_p2p_connection
- 0f3df72e4e2739fc9da1dfa105e278a32eef4962 [backport] test: Test that low difficulty chain fork is rejected
- d81d6349e63c197d2b12ff265cd0072797c5f20b [backport] test: Wait for both veracks in add_p2p_connection
- 7fead8eba41c7771b89b3dbbe98f82ea2114da5d [backport] test: add BIP37 'filterclear' test to p2p_filter.py
- 4d76dd59fd6562371a0daaeffe922a21304e5e87 [backport] test: add BIP37 remote crash bug [CVE-2013-5700] test to p2p_filter.py
- 0e2ccea5d75daaa0dc7c67e53b3bb695d6e30a98 [backport] test: add feature_asmap functional tests
- fba2375e155063872b613c0e576e089d92e092a6 [backport] test: add functional test for an empty, unparsable asmap
- 4a2155bb1823ece3eedb415fe5a765b1fc302fc9 [backport] test: add inventory type constant MSG_CMPCT_BLOCK
- 685deb843bb8f467aebcbbab3eedd73ace694be1 [backport] test: add p2p_invalid_messages logging
- 187b323cffdb7a9c41bdda81b9154d406bf77269 [backport] test: add two edge case tests for CSubNet
- 2161040f27e59256f2b1ffff14f831deb02f7d0b [backport] test: check that peer is connected when calling sync_*
- ff8e7bd360ddcea213a90fbdf946adece0b41f84 [backport] test: complete impl. of msg_merkleblock and wait_for_merkleblock
- ab2b8b60526165ff4d2d46e02419a690e3e15f53 [backport] test: explicit imports from test_framework.messages in p2p_invalid_messages.py
- dafdc7e1f8ae4f7086f3d3d7a2c51071d0c8848e [backport] test: hoist p2p values to test framework constants
- 136d0390b837c717a677b89a378f4369eeb29370 [backport] test: improve msg sends and p2p disconnections in p2p_invalid_messages
- 7c011e25c016c6b61e03dc54b2ea8ad3393fbceb [backport] test: move HasReason so it can be reused
- aba3b9f91fbf59e2fb07f1ddb4dadb39180c1436 [backport] test: move sync_blocks and sync_mempool functions to test_framework.py
- fccf3b3f87e1e7b507a18df3ea7e0f7762c103d0 [backport] test: refactor test_large_inv() into 3 tests with common method
- fc209e9131078e7aef3d82a353b129216b305dc7 [backport] test: replace (send_message + sync_with_ping) with send_and_ping
- e7b8c6951bf74f463a31df0bd7d13daeb2e32b74 [backport] test: replace inv type magic numbers by constants
- 493b0abb1fb8488c4d4b133ec806d9f22bad798f [backport] tests: Add tests for base58-decoding of std::string:s containing non-base58 characters
- 95ac5fd1626af914955ba50ba5c3c3729886526f [backport] tests: Add tests to make sure lookup methods fail on std::string parameters with embedded NUL characters
- 96d144ef2218cf50455a5e042b601b6f3fd3025a [backport] tests: Avoid using C-style NUL-terminated strings as arguments
- cc420b95e686b415f32304631c033539855220ec [backport] tests: Test for expected return values when calling functions returning a success code
- dff60d4f14c703fdeb9406e523ff2f11a3195930 [backport] tor: make a TORv3 hidden service instead of TORv2
- 9ecef01166f359028c2ddce124df612d20c753ce [backport] torcontrol: Use the default/standard network port for Tor hidden services, even if the internal port is set differently
- 059b6ce7c5fcaf9b2e7a0de9c2bb254987da170e [backport] util: Add Join helper to join a list of strings
- 6d5e87d6551ba42acdbb3438cef867680cd294ef [backport] util: Don't allow base58-decoding of std::string:s containing non-base58 characters
- 67e2556e50121f5c144d65ac869f9b45d6f2c887 [backport] util: Move TrimString(...). Introduce default pattern (trims whitespace). Add [[nodiscard]].
- 0a67fd5b36b0b30dc987b1712982642bfb0ef65b [backport] util: make EncodeBase32 consume Spans
- 024dc7d5d7909f1bbdc61814ff7fbaccf8399b6c [backport] util: make EncodeBase64 consume Spans
- fb84f5eefb361972c3a39bc96b996d367b35be5d [backport] util: move HasPrefix() so it can be reused
- b0b0d4baed27ebef1dbca1e515ebd8a6ac8c7a08 [backport] util: refactor upper/lowercase functions
- 8dfee2a3524f063909a454c27c7ff9d71c2ade5f [backport] windows: Call SetProcessDEPPolicy directly
- 6ecb3a3fbc2e43b24edd5bd05166dd315a53d13d [backport] windows: Set _WIN32_WINNT to 0x0601 (Windows 7)
- 1f07788b57e9faced3a4b53413dac26ccaeb75d8 backport: rpc: Fix rpcRunLater race in walletpassphrase
- 3482c57f042e3aeb9e5b8bb43f49877d9ca0d9e4 backport: rpc: Relock wallet only if most recent callback
