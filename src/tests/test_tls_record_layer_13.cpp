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

         return result;
         }

   public:
      std::vector<Test::Result> run() override
         {
         return 
            {
            basic_sanitization()
            };
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_record_layer_13", Test_TLS_Record_Layer_13);

#endif

}
