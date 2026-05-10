Test Networks
=============

This document describes the Bitcoin Cash test networks supported by the
BCHN software.

There are currently three test networks that you can access with BCHN:

- testnet3 (historical testnet)
- testnet4
- scalenet
- chipnet

These test network are maintained and supported by the wider community
of protocol developers. They can be accessed by running the software
(daemon, GUI and CLI) with `-testnet`, `-testnet4`, `-scalenet` and
`-chipnet` arguments, respectively.

Other software clients may have additional test network definitions compiled
into them but these are not currently supported by BCHN and could not be
accessed without further modifications to the software. If you wish BCHN
to access a test network not listed above, please raise a support request.

Below, we give a brief description and an overview table for these networks.

Testnet3
--------

This is the historical testnet in Bitcoin Cash, maintained as a fork from
BTC's testnet3 since 2017. It has grown substantially in size
(2023/Dec/11: 45GB), in part due to scaling tests that deposited a number
of 32MB blocks, and due to the resulting time to sync a test node from
scratch, has become inconvenient for quick tests.

The historical role is as a test network where application builders can
test their apps against the currently deployed consensus rules (as much
as possible) and at minimal expense without disrupting the main network.

After the upgrade to Adaptive Blocksize Limit Algorithm for Bitcoin Cash
in May 2024, the maximum blocksize of this network will remain capped to
32MB.

Testnet4
--------

Testnet4 is a testnet3 replacement (starting from a fresh genesis block)
intended to be kept light-weight and quick to sync, in other words free of
big block 'spam'.

It continues the role of a test network where application builders can
test their apps against most of the currently deployed mainnet consensus
at minimal expense without disrupting the main network.

Testnet4 has a reduced default blocksize to discourage high throughput and
difficulty algorithm settings adjusted to make sure it recovers to be
CPU-mineable quickly after someone has used an ASIC on it.

Scaling tests should use 'scalenet' instead (see next section).

After the upgrade to Adaptive Blocksize Limit Algorithm for Bitcoin Cash
in May 2024, the maximum blocksize of this network will remain capped to
2MB.

Scalenet
--------

Scalenet is intended as a place to test application performance in
high-throughput situations (bigger blocks, more transactions etc).

Scalenet will have a default blocksize limit a few times higher than
mainnet's limit, to serve as a proving ground for future scaling.

ASIC mining on scalenet will be encouraged and the mining difficulty will
adjust slower to allow accurate exploration of mining strategies.

Every 6 months or so, scalenet's block 10,000 will be invalidated and a new
block will be checkpointed in its place, clearing out the previous high volume
history and keeping scalenet semi-affordable to synchronize.

Scalenet is intended to target the performance level of a ~$40/month VPS
or a $500 desktop computer for the near future. Any tests that target higher
performance levels are encouraged to do so by forking off of scalenet or
creating their own private testnets or regtest networks.

Chipnet
-------

Chipnet is intended as a place to test against upcoming Cash Improvement
Proposals (CHIPs) which are intended to be activated in the next main network
consensus upgrade.

It therefore deploys these CHIPs (and updates to them) as much in advance as
possible (optimally 6 months ahead of the main network upgrades).

After the upgrade to Adaptive Blocksize Limit Algorithm for Bitcoin Cash
on this network in November 2023, the maximum blocksize of this network will
vary dynamically with a floor capacity of 2MB.

Overview Table for BCHN-supported Test Networks
-----------------------------------------------

| Attribute/Network            |  testnet3   |   testnet4   |  scalenet   |   chipnet   |
|------------------------------|-------------|--------------|-------------|-------------|
| Default p2p port             |  18333      |  28333       |  38333      |  48333      |
| Network magic bytes          |  0xf4e5f3f4 |  0xe2b7daaf  |  0xc3afe1a2 |  0xe2b7daaf |
| CashAddr prefix              |  bchtest    |  bchtest     |  bchtest    |  bchtest    |
| Default excessive block size |  32MB       |  2MB         |  256MB      |  2MB        |
| Block cap after ABLA activ.  |  fixed      |  fixed       |  dynamic    |  dynamic    |
| Block Target spacing         |  10 min     |  10 min      |  10 min     |  10 min     |
| POW limit                    |  2^224      |  2^224       |  2^224      |  2^224      |
| ASERT half-life              |  1 hour     |  1 hour      |  2 days     |  1 hour     |
| Allow min diff blocks        |  yes        |  yes         |  yes        |  yes        |
| Require standard txs         |  no         |  yes         |  no         |  yes        |
| Default consist. chks.       |  no         |  no          |  no         |  no         |
| Halving interval (blks)      |  210000     |  210000      |  210000     |  210000     |
| BIP16 height                 |  514        |  1           |  1          |  1          |
| BIP34 height                 |  21111      |  2           |  2          |  2          |
| BIP65 height                 |  581885     |  3           |  3          |  3          |
| BIP66 height                 |  330776     |  4           |  4          |  4          |
| CSV height                   |  770112     |  5           |  5          |  5          |
| UAHF (BCH fork) height       |  1155875    |  6           |  6          |  6          |
| Nov 13 2017 HF height        |  1188697    |  3000        |  3000       |  3000       |
| Nov 15 2018 HF height        |  1267996    |  4000        |  4000       |  4000       |
| Nov 15 2019 HF height        |  1341711    |  5000        |  5000       |  5000       |
| May 15 2020 HF height        |  1378460    |  0 (Note 1)  |  0 (Note 1) |  0 (Note 1) |
| Nov 15 2020 HF height        |  1421482    |  16845       |  variable (Note 2) |  16845      |
| May 15 2021 HF height        |  1447364    |  42946       |  34071      |  42946      |
| May 15 2022 HF height        |  1500206    |  95465       |  36060      |  95465      |
| May 15 2023 HF height        |  1552788    |  148044      |  37624      |  121957 (Note 3)    |
| Base58 prefix: pubkey        |  1, 111     |  1, 111      |  1, 111     |  1, 111     |
| Base58 prefix: script        |  1, 196     |  1, 196      |  1, 196     |  1, 196     |
| Base58 prefix: seckey        |  1, 239     |  1, 239      |  1, 239     |  1, 239     |
| Base58 p: ext. pubkey        |  0x043587cf |  0x043587cf  |  0x043587cf |  0x043587cf |
| Base58 p: ext. seckey        |  0x04358394 |  0x04358394  |  0x04358394 |  0x04358394 |

Note 1: set to 0 because historical sigop code has been removed from BCHN
        See chainparams.cpp for more detailed comments.

Note 2: scalenet is intended to be periodically reorganized down to a
        height of 10000 whose earlier than the November 2020 MTP activation
        time. The height at which the Axion upgrade takes effect is thus
        variable (it is block 16869 now, but may be different once the
        network is reset).

Note 3: Chipnet upgrades forked 6-months ahead of other networks, i.e. previous November

Further references
------------------

1. <https://bitcoincashresearch.org/t/testnet4-and-scalenet/148>
2. <https://bitcoincashresearch.org/t/staging-chips-on-testnet/573>
3. <https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/master/src/chainparams.cpp>
