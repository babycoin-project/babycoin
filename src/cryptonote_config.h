// Copyright (c) 2020, The Evolution Project
// Copyright (c) 2018-2020, The Arqma Network
// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <stdexcept>
#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_GETBLOCKTEMPLATE_MAX_BLOCK_SIZE      196608 //size of block (bytes) that is the maximum that miners will produce
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2           300*2
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V3           100*3
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V4           CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V3
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2            11
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V9            BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2

// MONEY_SUPPLY - total number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)55000000000000000)
#define MONEY_PREMINE                                   ((uint64_t)100000000000000)
#define EMISSION_SPEED_FACTOR_PER_MINUTE                (22)
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)300000000)


#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                9
// COIN - number of smallest units in one coin
#define COIN                                            ((uint64_t)1000000000)

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000)
#define FEE_PER_KB                                      ((uint64_t)20000)
#define FEE_PER_BYTE                                    ((uint64_t)3)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)20000)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)20000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_PER_BYTE_BASE_FEE_V13               ((uint64_t)(DYNAMIC_FEE_PER_KB_BASE_FEE_V5) * 50 / 1000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT        ((uint64_t)750)

#define ORPHANED_BLOCKS_MAX_COUNT                       100


#define DIFFICULTY_TARGET_V3                            DIFFICULTY_TARGET_V2
#define DIFFICULTY_TARGET_V2                            240  // seconds
#define DIFFICULTY_TARGET_V1                            120  // seconds - before first fork
#define DIFFICULTY_WINDOW                               720 // blocks
#define DIFFICULTY_WINDOW_V2                            30
#define DIFFICULTY_WINDOW_V3                            17
#define DIFFICULTY_LAG                                  15  // !!!
#define DIFFICULTY_CUT                                  60  // timestamps to cut after sorting

#define DIFFICULTY_TARGET_V10                           120
#define DIFFICULTY_BLOCKS_COUNT_V10                     (DIFFICULTY_WINDOW_V10 + 1)
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V10           11
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V10          360
#define DIFFICULTY_WINDOW_V10                           90

#define DIFFICULTY_TARGET_V11                           120
#define DIFFICULTY_BLOCKS_COUNT_V11                     (DIFFICULTY_WINDOW_V11 + 1)
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V11           11
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V11          360
#define DIFFICULTY_WINDOW_V11                           90

#define DIFFICULTY_BLOCKS_COUNT_V3                      (DIFFICULTY_WINDOW_V3 + 1)
#define DIFFICULTY_BLOCKS_COUNT_V2                      (DIFFICULTY_WINDOW_V2 + 1) // added to make N=N
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1

#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V2 //just alias; used by tests

#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing

#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048 //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                  (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME   604800 //seconds, one week

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT           100

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   8
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60         // secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000   // 50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       // 5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       // 2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  // 2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       // 5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2

#define P2P_DEFAULT_LIMIT_RATE_UP                       4096       // Kbps
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     16384      // Kbps

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)    // 1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24) // 24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60)     // 5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define ALLOW_DEBUG_COMMANDS

#define CRYPTONOTE_NAME                                 "babycoin"
#define CRYPTONOTE_POOLDATA_FILENAME                    "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME              "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME         "lock.mdb"
#define P2P_NET_DATA_FILENAME                           "p2pstate.bin"
#define RPC_PAYMENTS_DATA_FILENAME                      "rpcpayments.bin"
#define MINER_CONFIG_FILE_NAME                          "miner_conf.json"

#define THREAD_STACK_SIZE                               5 * 1024 * 1024

#define HF_VERSION_DYNAMIC_FEE                          4
#define HF_VERSION_MIN_MIXIN_4                          6
#define HF_VERSION_MIN_MIXIN_6                          7
#define HF_VERSION_ENFORCE_RCT                          6

#define HF_VERSION_MIN_MIXIN_10                         13

#define HF_VERSION_LOWER_FEE                            10
#define HF_VERSION_PER_BYTE_FEE                         13
#define HF_FORBID_BORROMEAN                             13
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT               14

#define PER_KB_FEE_QUANTIZATION_DECIMALS                8

#define HASH_OF_HASHES_STEP                             256

#define DEFAULT_TXPOOL_MAX_WEIGHT                       648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                         16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE                  4096         // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES                  3            // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS                   5500         // the smaller, the more space saved
//#define CRYPTONOTE_PRUNING_DEBUG_SPOOF_SEED

#define RPC_CREDITS_PER_HASH_SCALE                      ((float)(1<<24))

static constexpr uint64_t POISSON_CHECK_TRIGGER = 5;  // Reorg size that triggers poisson timestamp check
static constexpr uint64_t POISSON_CHECK_DEPTH = 128;  // Main-chain depth of the poisson check. The attacker will have to tamper 50% of those blocks
static constexpr double POISSON_LOG_P_REJECT = -75.0; // Reject reorg if the probablity that the timestamps are genuine is below e^x, -75 = 10^-33

// New constants are intended to go here
namespace config
{
   uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)0); // Deprecated
   uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000);
   std::string const P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

   uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x231e4e; // Wallet prefix: baby... // decimal prefix: ......
   uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x1c31e4e; // Wallet prefix: babyx... // decimal prefix: .....
   uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x4031e4e; // Wallet prefix: babyz... // decimal prefix: ......
   uint16_t const P2P_DEFAULT_PORT = 51021;
   uint16_t const RPC_DEFAULT_PORT = 51022;
   uint16_t const ZMQ_DEFAULT_PORT = 51023;
   boost::uuids::uuid const NETWORK_ID = { {
       0x10, 0x11, 0x00, 0x11, 0xFF, 0x01, 0x11, 0xFF, 0x66, 0x11, 0xFF, 0xFF, 0xFF, 0x84, 0x00, 0x1F
     } }; // Bender's nightmare
   std::string const GENESIS_TX = "011201ff00011e026bc5c7db8a664f652d78adb587ac4d759c6757258b64ef9cba3c0354e64fb2e42101abca6a39c561d0897be183eb0143990eba201aa7d2c652ab0555d28bb4b70728";
   uint32_t const GENESIS_NONCE = 110100;

   namespace testnet
   {
     uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x239e4e; // Wallet prefix:
     uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x2039e4e; // Wallet prefix:
     uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x3239e4e; // Wallet prefix: ett... // decimal prefix: 21066
     uint16_t const P2P_DEFAULT_PORT = 51121;
     uint16_t const RPC_DEFAULT_PORT = 51122;
     uint16_t const ZMQ_DEFAULT_PORT = 51123;
     boost::uuids::uuid const NETWORK_ID = { {
       0x10, 0x11, 0x00, 0x11, 0xFF, 0x01, 0x11, 0xFF, 0x66, 0x00, 0xFF, 0xFF, 0xFF, 0x84, 0x11, 0x1B
       } }; // Bender's daydream
   }

   namespace stagenet
   {
     uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x1b5e4e; // Wallet prefix:
     uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x229e4e; // Wallet prefix:
     uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x239e4e; // Wallet prefix:
     uint16_t const P2P_DEFAULT_PORT = 51221;
     uint16_t const RPC_DEFAULT_PORT = 51222;
     uint16_t const ZMQ_DEFAULT_PORT = 51223;
     boost::uuids::uuid const NETWORK_ID = { {
       0x10, 0x11, 0x00, 0x11, 0xFF, 0x01, 0x11, 0xFF, 0x66, 0x00, 0xFF, 0xFF, 0xFF, 0x84, 0x11, 0x1C
       } }; // Bender's daydream
   }

   namespace blockchain_settings
   {
     static constexpr uint64_t PREMINE_BURN = 0; // Will need to be set after knowing exact amount.
     static constexpr uint64_t MAXIMUM_BLOCK_SIZE_LIMIT = 2 * 1024 * 1024; // It is set to 2048kB (2MB)
     static constexpr uint64_t MINIMUM_BLOCK_SIZE_LIMIT = 1 * 1024 * 1024; // It is set to 1024kB (1MB)
     static constexpr uint8_t EVOLUTION_GENESIS_BLOCK_MAJOR_VERSION = 1;
     static constexpr uint8_t EVOLUTION_GENESIS_BLOCK_MINOR_VERSION = 1;
     static constexpr uint8_t EVOLUTION_BLOCK_UNLOCK_CONFIRMATIONS = 18; // How many blocks mined are needed to unlock block_reward.
   }

   namespace tx_settings
   {
     static constexpr uint8_t EVOLUTION_TX_CONFIRMATIONS_REQUIRED = 4; // How many blocks are needed to confirm transaction sent.
     static constexpr uint8_t CURRENT_TX_VERSION = 2; // Current Transaction Version Valid on Arq-Net
     static constexpr uint64_t TRANSACTION_SIZE_LIMIT = 48 * 1024; // I did set it to 48kB for now but it need to be verified.
     static constexpr uint64_t MAX_TRANSACTIONS_IN_BLOCK = 1024; // Maximum allowed transactions in One Block
   }

   namespace sync
   {
     static constexpr size_t NORMAL_SYNC = 20; // Amount of Blocks to download and Validate at ones while Synchronizung with Evolution Network.
     static constexpr size_t RAPID_SYNC = 250; // Amount of Blocks to download at ones from already known by Evolution Daemon and Checkpoint are hardcoded into codebase
   }
}

namespace cryptonote
{
  enum network_type : uint8_t
    {
      MAINNET = 0,
      TESTNET,
      STAGENET,
      FAKECHAIN,
      UNDEFINED = 255
    };
    struct config_t
    {
      uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
      uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
      uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
      uint16_t const P2P_DEFAULT_PORT;
      uint16_t const RPC_DEFAULT_PORT;
      uint16_t const ZMQ_DEFAULT_PORT;
      boost::uuids::uuid const NETWORK_ID;
      std::string const GENESIS_TX;
      uint32_t const GENESIS_NONCE;
    };
    inline const config_t& get_config(network_type nettype)
    {
      static const config_t mainnet = {
        ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
        ::config::P2P_DEFAULT_PORT,
        ::config::RPC_DEFAULT_PORT,
        ::config::ZMQ_DEFAULT_PORT,
        ::config::NETWORK_ID,
        ::config::GENESIS_TX,
        ::config::GENESIS_NONCE
      };
      static const config_t testnet = {
        ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
        ::config::testnet::P2P_DEFAULT_PORT,
        ::config::testnet::RPC_DEFAULT_PORT,
        ::config::testnet::ZMQ_DEFAULT_PORT,
        ::config::testnet::NETWORK_ID,
        ::config::GENESIS_TX,
        ::config::GENESIS_NONCE
      };
      static const config_t stagenet = {
        ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
        ::config::stagenet::P2P_DEFAULT_PORT,
        ::config::stagenet::RPC_DEFAULT_PORT,
        ::config::stagenet::ZMQ_DEFAULT_PORT,
        ::config::stagenet::NETWORK_ID,
        ::config::GENESIS_TX,
        ::config::GENESIS_NONCE
      };
      switch (nettype)
      {
        case MAINNET: return mainnet;
        case TESTNET: return testnet;
        case STAGENET: return stagenet;
        case FAKECHAIN: return mainnet;
        default: throw std::runtime_error("Invalid network type");
      }
   };
}
