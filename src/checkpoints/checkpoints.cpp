// Copyright (c) 2020, The Evolution Network
// Copyright (c) 2018-2019, The Arqma Network
// Copyright (c) 2014-2018, The Monero Project
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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <vector>

using namespace epee;

#undef EVOLUTION_DEFAULT_LOG_CATEGORY
#define EVOLUTION_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest =
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) <
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

   bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {

      return true;
    }
    if (nettype == STAGENET)
    {
      return true;
    }

//checkpoints here
   ADD_CHECKPOINT(0, "20c1047c2411b076855977031bf8ccaed4bf544cd03cbc7dbebfef95891248a5");
   ADD_CHECKPOINT(50, "5a7bb4a58ad188148e8e5dc110475abf86e09a1254edbc644231029ea59bd0c6");
   ADD_CHECKPOINT(100, "5cce2e92c09a7c8a4a2a4100b94259046fce320115b20de5bb160697885b8c64");
   ADD_CHECKPOINT(150, "dbbc6a9baf6e2606212d9614333062fa9ea70a2ac1e14541e4c46869f348f5d4");
   ADD_CHECKPOINT(250, "85c8f58992e53465e3b7ec2155bdb02ac33b4526189aef488bc5aaf07dfca75c");
   ADD_CHECKPOINT(300, "242fba325963ffd574ade9021a32884b88c7096ec34a405f74bcd229eed463cf");
   ADD_CHECKPOINT(350, "acf50beec7cce988a751aeb3d275703b3f4b7dc3686df5d1752255aa965fac12");
   ADD_CHECKPOINT(400, "9e0d9c8beb40720be43c5e51d357b70b9b03d9f4883fc983000b6c06480fa89a");
   ADD_CHECKPOINT(450, "af0af9938079213bf9691e7cfe3d63f7f79caf9486d92e770fb9346bb9c92b5d");
   ADD_CHECKPOINT(500, "62534533a6a66ba2357f327b2fdb584a8d9d860fb136c1a6303cfe9ff89c2d37");
   ADD_CHECKPOINT(550, "9ba57f848f685a0cfc6c8d26ca1c30677cf2e468514df431d803eee2cd043762");
   ADD_CHECKPOINT(600, "333feca60e428be7f0b693f7037e0c49f82dab3d6cd4f3f9f188a089852cb215");
   ADD_CHECKPOINT(650, "54e84a960462461bfd5be1ab7a40ed413033ccfe37b6cf9e72c781958962bf15");
   ADD_CHECKPOINT(700, "5f6f97b29e9a76e3b5b3c6d554fb0130ee30d238db4f9673017e5735f8f6b906");
   ADD_CHECKPOINT(750, "fa6691927c34e6d51739e5777cab2de7a8d2f9f6ae824d51f836cbb189b72c0d");
   ADD_CHECKPOINT(800, "78803f7183211fc863cf80ecc28f233f46a4276082ce1ada7a87c55d8e6830a6");
   ADD_CHECKPOINT(850, "689704a9d9acf1c35cfea016a5c461674426b682634deac15da392e248c1c659");
   ADD_CHECKPOINT(900, "21d8e9b81188861512ddb81a726f2e5e187e2e2056b62060c320ac8dffb65cee");
   ADD_CHECKPOINT(950, "bbb7ba481d857d11d00904b25030e5911d1ef3adec2da19c7a604fdfdbcce349");
   ADD_CHECKPOINT(1000, "09ed61ccdfdd16fdca5f9135a713992b54f8b75b67bb18464168129f3017b9df");
   ADD_CHECKPOINT(1050, "178c1cc2142859e57ee12e6ee609d6859a3c2d12a58772dea7948a7a7402db22");
   ADD_CHECKPOINT(1100, "e46cdc377f9178b26a20b7b34c70eb14d403a495e94538a3fd2c8fc913a23fd8");
   ADD_CHECKPOINT(1150, "51570c2743934430142b73c3173ed47a12757c965b7f9e7ae2cfc1dde70a4c4e");
   ADD_CHECKPOINT(1200, "ff3c506d482f6b44077255c8e9c680e5a10fb6689e6ec2933e580804e1f306c9");
   ADD_CHECKPOINT(1250, "0496da938b48a75f31d47a2d36b78e26246ce0fdf84f83bb0470607933b8ead2");
   ADD_CHECKPOINT(1300, "61c0c8a792b5d10b913f956235fcbb80dced65bc7ab0d426e2d61ff419fa4a02");
   return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four ArQ-Net domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
        "evolution-project.go.ro/checkpoints"
	};

    static const std::vector<std::string> testnet_dns_urls = {
    };

    static const std::vector<std::string> stagenet_dns_urls = {
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
