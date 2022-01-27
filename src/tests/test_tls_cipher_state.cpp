/*
* (C) 2021 Jack Lloyd
* (C) 2021 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

#include <botan/internal/tls_cipher_state.h>

namespace {

namespace TLS = Botan::TLS;
using Test = Botan_Tests::Test;

// TODO: move elsewhere
template<typename FunT>
Test::Result CHECK(const char* name, FunT check_fun)
   {
   Botan_Tests::Test::Result r(name);
   try
      {
      check_fun(r);
      }
   catch(const Botan_Tests::Test_Aborted&)
      {
      // pass, failure was already noted in the responsible `require`
      }
   catch(const std::exception& ex)
      {
      r.test_failure(std::string("failed with exception: ") + ex.what());
      }
   return r;
   }

std::vector<Test::Result> test_cs()
   {
   return
      {
      CHECK("interface", [](auto& )
         {
         Botan::secure_vector<uint8_t> early_secret;

         Cipher_State cs();

         cs.set_psk();

         cs.set_transcript_hash_until_client_hello();

         cs.set_dh_output();

         cs.set_transcript_hash_until_server_hello();
         cs.set_transcript_hash_until_server_finished();
         cs.set_transcript_hash_until_client_finished();

         })
      };
   }
}

namespace Botan_Tests {
BOTAN_REGISTER_TEST_FN("tls", "tls_cipher_state", test_cs);
}

#endif
