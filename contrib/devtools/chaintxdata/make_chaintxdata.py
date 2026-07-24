#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Generate ChainTxData C++ code from live RPC data."""

import argparse
import os.path
import sys

sys.path.append("../../../test/functional/test_framework")
from authproxy import AuthServiceProxy  # noqa: E402

DEFAULT_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "chaintxdata.cpp.tmpl")


def main(rpc, height, last_height, template_path=DEFAULT_TEMPLATE_PATH):
    if last_height >= height:
        raise ValueError("--last-block must be less than --block")
    if last_height < 1:
        raise ValueError("--last-block must be greater than 0")

    block_hash = rpc.getblockhash(height)

    # getchaintxstats(block_count, block_hash) query from genesis to target block
    txstats = rpc.getchaintxstats(height - 1, block_hash)
    total_transactions = txstats["txcount"]
    timestamp = int(txstats["time"])

    # Compute tx_rate from difference between current and previous snapshot
    last_hash = rpc.getblockhash(last_height)
    last_stats = rpc.getchaintxstats(last_height - 1, last_hash)

    # Get actual block timestamps via getblock
    block_info = rpc.getblock(block_hash)
    last_block_info = rpc.getblock(last_hash)
    time_diff = block_info["time"] - last_block_info["time"]

    tx_diff = total_transactions - last_stats["txcount"]
    if tx_diff <= 0:
        raise ValueError("txcount decreased: current {} < last {}".format(total_transactions, last_stats["txcount"]))
    tx_rate = tx_diff / time_diff

    with open(template_path, "r", encoding="utf8") as f:
        template = f.read()

    return template.format(
        block_hash=block_hash,
        height=height,
        timestamp=timestamp,
        total_transactions=total_transactions,
        tx_rate=tx_rate,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate ChainTxData C++ code from RPC data.\n" "Prerequisites: RPC access to a bitcoind node.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--address", "-a", default="127.0.0.1:8332", help="Node address for RPC calls.\n" "Default: '127.0.0.1:8332'"
    )
    parser.add_argument("--block", "-b", type=int, required=True, help="Block height to use.")
    parser.add_argument(
        "--last-block",
        "-l",
        type=int,
        required=True,
        help="Previous snapshot block height. tx_rate is computed as "
        "(txcount - last_txcount) / (block_time - last_block_time).",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="~/.bitcoin/bitcoin.conf",
        help="Path to bitcoin.conf for RPC authentication.\n" "Default: ~/.bitcoin/bitcoin.conf",
    )
    parser.add_argument(
        "--template",
        "-t",
        default=DEFAULT_TEMPLATE_PATH,
        help="Path to C++ template file.\n"
        "Default: chaintxdata.cpp.tmpl (mainnet format).\n"
        "Use chaintxdata-testnet.cpp.tmpl for testnet format.",
    )
    args = parser.parse_args()
    args.config = os.path.expanduser(args.config)
    if not os.path.isabs(args.template):
        args.template = os.path.join(os.path.dirname(__file__), args.template)

    # Read RPC credentials from config
    user = None
    password = None
    if os.path.isfile(args.config):
        with open(args.config, "r", encoding="utf8") as f:
            for line in f:
                if line.startswith("rpcuser="):
                    assert user is None
                    user = line.split("=")[1].strip("\n")
                if line.startswith("rpcpassword="):
                    assert password is None
                    password = line.split("=")[1].strip("\n")
    else:
        raise FileNotFoundError("Missing bitcoin.conf")
    if user is None:
        raise ValueError("Config is missing rpcuser")
    if password is None:
        raise ValueError("Config is missing rpcpassword")

    rpc = AuthServiceProxy("http://{}:{}@{}".format(user, password, args.address))
    output = main(rpc, args.block, args.last_block, args.template)
    if output:
        print(output)
