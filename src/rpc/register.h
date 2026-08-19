// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class Config;
class CRPCTable;
class RPCServer;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable &tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable &tableRPC);
/** Register mining RPC commands */
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
/** Register DSProof RPC commands */
void RegisterDSProofRPCCommands(CRPCTable &tableRPC);

/**
 * Register all context-free (legacy) RPC commands, except for wallet and dump
 * RPC commands.
 */
static inline void RegisterAllContextFreeRPCCommands(CRPCTable &t) {
    RegisterBlockchainRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterMiscRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterDSProofRPCCommands(t);
}

/**
 * Register all context-sensitive RPC commands.
 */
static inline void RegisterAllRPCCommands(const Config &,
                                          RPCServer &,
                                          CRPCTable &rpcTable) {
    // TODO Register context-sensitive RPC commands using rpcServer

    RegisterAllContextFreeRPCCommands(rpcTable);
}
