/*
* (C) 2021 Jack Lloyd
* (C) 2021 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

#include <botan/tls_magic.h>

#include <botan/internal/tls_record_layer_13.h>

namespace Botan_Tests {

namespace TLS = Botan::TLS;

class Test_TLS_Record_Layer_13 final : public Test
   {
   private:
      Test::Result basic_sanitization()
         {
         Test::Result result("basic sanitization");

         // incomplete header asks for more data
         std::vector<uint8_t> partial_header{'\x23', '\x03', '\x03'};
         auto res1 = TLS::Record_Layer().received_data(partial_header);
         if (result.confirm("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(res1)))
            {
            result.test_eq("asks for some more bytes", std::get<TLS::BytesNeeded>(res1), Botan::TLS::TLS_HEADER_SIZE - partial_header.size());
            }

         // complete header asks for enough data to finish processing the record
         std::vector<uint8_t> full_header{'\x17', '\x03', '\x03', '\x00', '\x42'};
         auto res2 = TLS::Record_Layer().received_data(full_header);
         if (result.confirm("returned 'bytes needed'", std::holds_alternative<TLS::BytesNeeded>(res2)))
            {
            result.test_eq("asks for many more bytes", std::get<TLS::BytesNeeded>(res2), 0x42);
            }

         // received an empty record (that is not application data)
         std::vector<uint8_t> empty_record{'\x16', '\x03', '\x03', '\x00', '\x00'};
         result.test_throws("record empty", "empty record received", [&] {
            TLS::Record_Layer().received_data(empty_record);
         });

         // received the maximum size of a default record
         std::vector<uint8_t> full_record{'\x17', '\x03', '\x03', '\x41', '\x00'};
         full_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE);
         auto res3 = TLS::Record_Layer().received_data(full_record);
         result.confirm("returned 'record'", !std::holds_alternative<TLS::BytesNeeded>(res3));

         // received too many bytes in one record
         std::vector<uint8_t> huge_record{'\x17', '\x03', '\x03', '\x41', '\x01'};
         huge_record.resize(TLS::MAX_CIPHERTEXT_SIZE_TLS13 + TLS::TLS_HEADER_SIZE + 1);
         result.test_throws("record too big", "overflowing record received", [&] {
            TLS::Record_Layer().received_data(huge_record);
         });

         // invalid record type
         std::vector<uint8_t> invalid_record_type{'\x42', '\x03', '\x03', '\x41', '\x01'};
         result.test_throws("invalid record type", "unexpected message received", [&] {
            TLS::Record_Layer().received_data(invalid_record_type);
         });

         // invalid record version
         std::vector<uint8_t> invalid_record_version{'\x17', '\x03', '\x02', '\x00', '\x01', '\x42'};
         result.test_throws("invalid record version", "invalid record version", [&] {
            TLS::Record_Layer().received_data(invalid_record_version);
         });

         // unexpected change cipher spec
         std::vector<uint8_t> invalid_ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x02'};
         result.test_throws("invalid CCS record", "unexpected change cipher spec record received", [&] {
            TLS::Record_Layer().received_data(invalid_ccs_record);
         });

         return result;
         }

      Test::Result read_full_records()
         {
         Test::Result result("reading full records");

         // change cipher spec
         std::vector<uint8_t> ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};
         auto res1 = TLS::Record_Layer().received_data(ccs_record);
         if (result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(res1)))
            {
            auto rec1 = std::get<std::vector<TLS::Record>>(res1);
            result.test_eq("received 1 record", rec1.size(), 1);
            result.confirm("received CCS", rec1.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", rec1.front().fragment.empty());
            }

         // change cipher spec
         std::vector<uint8_t> two_ccs_records{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01',
                                              '\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};
         auto res2 = TLS::Record_Layer().received_data(two_ccs_records);
         if (result.confirm("received something", std::holds_alternative<std::vector<TLS::Record>>(res2)))
            {
            auto rec2 = std::get<std::vector<TLS::Record>>(res2);
            result.test_eq("received 2 records", rec2.size(), 2);
            result.confirm("received CCS 1", rec2.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("received CCS 2", rec2.back().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", rec2.front().fragment.empty());
            result.confirm("CCS bears no data", rec2.back().fragment.empty());
            }

         return result;
         }

      Test::Result read_fragmented_records()
         {
         Test::Result result("reading fragmented records");

         TLS::Record_Layer rl;

         // change cipher spec in many small pieces
         std::vector<uint8_t> ccs_record{'\x14', '\x03', '\x03', '\x00', '\x01', '\x01'};

         auto wait_for_more_bytes = [&result] (Botan::TLS::BytesNeeded bytes_needed, auto rlr) {
            if (result.confirm("waiting for bytes", std::holds_alternative<TLS::BytesNeeded>(rlr)))
               result.test_eq("right amount", std::get<TLS::BytesNeeded>(rlr), bytes_needed);
         };

         wait_for_more_bytes(4, rl.received_data({'\x14'}));
         wait_for_more_bytes(3, rl.received_data({'\x03'}));
         wait_for_more_bytes(2, rl.received_data({'\x03'}));
         wait_for_more_bytes(1, rl.received_data({'\x00'}));
         wait_for_more_bytes(1, rl.received_data({'\x01'}));

         auto res1 = rl.received_data({'\x01'});
         if (result.confirm("received something 1", std::holds_alternative<std::vector<TLS::Record>>(res1)))
            {
            auto rec1 = std::get<std::vector<TLS::Record>>(res1);
            result.test_eq("received 1 record", rec1.size(), 1);
            result.confirm("received CCS", rec1.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            result.confirm("CCS bears no data", rec1.front().fragment.empty());
            }

         // two change cipher specs in several pieces
         wait_for_more_bytes(1, rl.received_data({'\x14', '\x03', '\x03', '\x00'}));

         auto res2 = rl.received_data({'\x01', '\x01', /* second CCS starts here */ '\x14', '\x03'});
         if (result.confirm("received something 2", std::holds_alternative<std::vector<TLS::Record>>(res2)))
            {
            auto rec2 = std::get<std::vector<TLS::Record>>(res2);
            result.test_eq("received 1 record", rec2.size(), 1);
            result.confirm("received CCS", rec2.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            }

         wait_for_more_bytes(2, rl.received_data({'\x03'}));

         auto res3 = rl.received_data({'\x00', '\x01', '\x01'});
         if (result.confirm("received something 3", std::holds_alternative<std::vector<TLS::Record>>(res3)))
            {
            auto rec3 = std::get<std::vector<TLS::Record>>(res3);
            result.test_eq("received 1 record", rec3.size(), 1);
            result.confirm("received CCS", rec3.front().type == TLS::Record_Type::CHANGE_CIPHER_SPEC);
            }

         return result;
         }

   public:
      std::vector<Test::Result> run() override
         {
         return 
            {
            basic_sanitization(),
            read_full_records(),
            read_fragmented_records()
            };
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_record_layer_13", Test_TLS_Record_Layer_13);

#endif

}
