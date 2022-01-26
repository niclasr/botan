/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_LAYER_13_H_
#define BOTAN_TLS_RECORD_LAYER_13_H_

#include <variant>
#include <vector>

#include <botan/secmem.h>
#include <botan/tls_magic.h>

namespace Botan::TLS {

/**
 * Resembles the `TLSPlaintext` structure in RFC 8446 5.1
 * minus the record protocol specifics and ossified bytes.
 */
struct Record {
   Record_Type            type;
   secure_vector<uint8_t> fragment;

   Record(Record_Type type, secure_vector<uint8_t> fragment)
      : type(type)
      , fragment(std::move(fragment)) {}
};

using BytesNeeded = size_t;

/**
 * Implementation of the TLS 1.3 record protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS messages and vice versa.
 */
class Record_Layer
{
public:
   Record_Layer() = default;

   template <typename ResT>
   using ReadResult = std::variant<BytesNeeded, ResT>;

   /**
    * Reads data that was received by the peer.
    *
    * Return value contains either the number of bytes (`size_t`) needed to proceed
    * with processing TLS records or a list of plaintext TLS record contents
    * containing higher level protocol or application data.
    */
   ReadResult<std::vector<Record>> parse_records(const std::vector<uint8_t>& data_from_peer);

   std::vector<uint8_t> prepare_records(const Record_Type type,
                                        const uint8_t data[], size_t size);

   std::vector<uint8_t> prepare_protected_records(const Record_Type type,
                                                  const uint8_t data[], size_t size);

   std::vector<uint8_t> prepare_dummy_ccs_record();

private:
   ReadResult<Record> read_record();
   void decrypt(Record& record);
   void encrypt(secure_vector<uint8_t>& data);

private:
   std::vector<uint8_t> m_read_buffer;
};

}

#endif
