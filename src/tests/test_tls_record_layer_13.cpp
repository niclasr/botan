/*
* (C) 2021 Jack Lloyd
* (C) 2021 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

#include <botan/tls_magic.h>
#include <botan/internal/stl_util.h>

#include <botan/internal/tls_record_layer_13.h>

namespace {

namespace TLS = Botan::TLS;
using Test = Botan_Tests::Test;

template<typename FunT>
Test::Result CHECK(const char* name, FunT check_fun)
   {
   Botan_Tests::Test::Result r(name);
   check_fun(r);
   return r;
   }

std::vector<Test::Result> read_full_records()
   {
   const auto client_hello_record = Botan::hex_decode(  // from RFC 8448
      "16 03 01 00 c4 01 00 00 c0 03 03 cb"
      "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
      "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
      "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
      "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
      "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
      "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
      "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
      "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
      "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");
   const auto ccs_record = Botan::hex_decode("14 03 03 00 01 01");

   return
      {
      CHECK("change cipher spec", [&](auto& result)
         {
         auto read = TLS::Record_Layer().received_data(ccs_record);
         if(result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(read)))
            {
            auto record = std::get<std::vector<TLS::Record>>(read);
            result.test_eq("received 1 record", record.size(), 1);
            result.confirm("received CCS", record.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", record.front().fragment.empty());
            }
         }),

      CHECK("two CCS messages", [&](auto& result)
         {
         const auto two_ccs_records = Botan::concat(ccs_record, ccs_record);

         auto read = TLS::Record_Layer().received_data(two_ccs_records);
         if(result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(read)))
            {
            auto record = std::get<std::vector<TLS::Record>>(read);
            result.test_eq("received 2 records", record.size(), 2);
            result.confirm("received CCS 1", record.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("received CCS 2", record.back().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", record.front().fragment.empty());
            result.confirm("CCS bears no data", record.back().fragment.empty());
            }
         }),

      CHECK("read full handshake message", [&](auto& result)
         {
         auto read = TLS::Record_Layer().received_data(client_hello_record);
         if(result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(read)))
            {
            auto rec = std::get<std::vector<TLS::Record>>(read);
            result.test_eq("received 1 record", rec.size(), 1);
            result.confirm("received handshake record", rec.front().type == TLS::Record_Type::HANDSHAKE);
            result.test_eq("contains the full handshake message",
                           Botan::secure_vector<uint8_t>(client_hello_record.begin()+TLS::TLS_HEADER_SIZE,
                                 client_hello_record.end()), rec.front().fragment);
            }
         }),

      CHECK("read full handshake message followed by CCS", [&](auto& result)
         {
         const auto payload = Botan::concat(client_hello_record, ccs_record);
         auto read = TLS::Record_Layer().received_data(payload);
         if(result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(read)))
            {
            auto rec = std::get<std::vector<TLS::Record>>(read);
            result.test_eq("received 2 records", rec.size(), 2);
            result.confirm("received handshake record", rec.front().type == TLS::Record_Type::HANDSHAKE);
            result.test_eq("contains the full handshake message",
                           Botan::secure_vector<uint8_t>(client_hello_record.begin()+TLS::TLS_HEADER_SIZE,
                                 client_hello_record.end()), rec.front().fragment);
            result.confirm("received CCS record", rec.back().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", rec.back().fragment.empty());
            }
         })
      };
   }

std::vector<Test::Result> basic_sanitization()
   {
   return
      {
      CHECK("incomplete header asks for more data", [](auto& result)
         {
         std::vector<uint8_t> partial_header{'\x23', '\x03', '\x03'};
         auto read = TLS::Record_Layer().received_data(partial_header);
         if(result.confirm("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read)))
            {
            result.test_eq("asks for some more bytes", std::get<TLS::BytesNeeded>(read),
                           Botan::TLS::TLS_HEADER_SIZE - partial_header.size());
            }
         }),

      CHECK("complete header asks for enough data to finish processing the record", [](auto& result)
         {
         std::vector<uint8_t> full_header{'\x17', '\x03', '\x03', '\x00', '\x42'};
         auto read = TLS::Record_Layer().received_data(full_header);
         if(result.confirm("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(read)))
            {
            result.test_eq("asks for many more bytes", std::get<TLS::BytesNeeded>(read), 0x42);
            }
         }),

      CHECK("received an empty record (that is not application data)", [](auto& result)
         {
         std::vector<uint8_t> empty_record{'\x16', '\x03', '\x03', '\x00', '\x00'};
         result.test_throws("record empty", "empty record received", [&]
            {
            TLS::Record_Layer().received_data(empty_record);
            });
         }),

      CHECK("received the maximum size of a default record", [](auto& result)
         {
         std::vector<uint8_t> full_record{'\x17', '\x03', '\x03', '\x41', '\x00'};
         full_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE);
         auto read = TLS::Record_Layer().received_data(full_record);
         result.confirm("returned 'record'", !std::holds_alternative<TLS::BytesNeeded>(read));
         }),

      CHECK("received too many bytes in one record", [](auto& result)
         {
         std::vector<uint8_t> huge_record{'\x17', '\x03', '\x03', '\x41', '\x01'};
         huge_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE + 1);
         result.test_throws("record too big", "overflowing record received", [&]
            {
            TLS::Record_Layer().received_data(huge_record);
            });
         }),

      CHECK("invalid record type", [](auto& result)
         {
         std::vector<uint8_t> invalid_record_type{'\x42', '\x03', '\x03', '\x41', '\x01'};
         result.test_throws("invalid record type", "unexpected message received", [&]
            {
            TLS::Record_Layer().received_data(invalid_record_type);
            });
         }),

      CHECK("invalid record version", [](auto& result)
         {
         std::vector<uint8_t> invalid_record_version{'\x17', '\x03', '\x02', '\x00', '\x01', '\x42'};
         result.test_throws("invalid record version", "invalid record version", [&]
            {
            TLS::Record_Layer().received_data(invalid_record_version);
            });
         }),

      CHECK("unexpected change cipher spec", [](auto& result)
         {
         std::vector<uint8_t> invalid_ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x02'};
         result.test_throws("invalid CCS record", "unexpected change cipher spec record received", [&]
            {
            TLS::Record_Layer().received_data(invalid_ccs_record);
            });
         })

      };
   }

std::vector<Test::Result> read_fragmented_records()
   {
   TLS::Record_Layer rl;

   auto wait_for_more_bytes = [](Botan::TLS::BytesNeeded bytes_needed, auto rlr, auto& result)
      {
      if(result.confirm("waiting for bytes", std::holds_alternative<TLS::BytesNeeded>(rlr)))
         { result.test_eq("right amount", std::get<TLS::BytesNeeded>(rlr), bytes_needed); }
      };

   return
      {
      CHECK("change cipher spec in many small pieces", [&](auto& result)
         {
         std::vector<uint8_t> ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};

         wait_for_more_bytes(4, rl.received_data({'\x14'}), result);
         wait_for_more_bytes(3, rl.received_data({'\x03'}), result);
         wait_for_more_bytes(2, rl.received_data({'\x03'}), result);
         wait_for_more_bytes(1, rl.received_data({'\x00'}), result);
         wait_for_more_bytes(1, rl.received_data({'\x01'}), result);

         auto res1 = rl.received_data({'\x01'});
         if(result.confirm("received something 1", std::holds_alternative<std::vector<TLS::Record>>(res1)))
            {
            auto rec1 = std::get<std::vector<TLS::Record>>(res1);
            result.test_eq("received 1 record", rec1.size(), 1);
            result.confirm("received CCS", rec1.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", rec1.front().fragment.empty());
            }
         }),


      CHECK("two change cipher specs in several pieces", [&](auto& result)
         {
         wait_for_more_bytes(1, rl.received_data({'\x14', '\x03', '\x03', '\x00'}), result);

         auto res2 = rl.received_data({'\x01', '\x01', /* second CCS starts here */ '\x14', '\x03'});
         if(result.confirm("received something 2", std::holds_alternative<std::vector<TLS::Record>>(res2)))
            {
            auto rec2 = std::get<std::vector<TLS::Record>>(res2);
            result.test_eq("received 1 record", rec2.size(), 1);
            result.confirm("received CCS", rec2.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            }

         wait_for_more_bytes(2, rl.received_data({'\x03'}), result);

         auto res3 = rl.received_data({'\x00', '\x01', '\x01'});
         if(result.confirm("received something 3", std::holds_alternative<std::vector<TLS::Record>>(res3)))
            {
            auto rec3 = std::get<std::vector<TLS::Record>>(res3);
            result.test_eq("received 1 record", rec3.size(), 1);
            result.confirm("received CCS", rec3.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            }
         })
      };
   }
}

namespace Botan_Tests {
BOTAN_REGISTER_TEST_FN("tls", "tls_record_layer_13", read_full_records, read_fragmented_records, basic_sanitization);
}

#endif
