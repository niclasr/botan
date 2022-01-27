/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_version.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>

#include <botan/hex.h>  // TODO: remove
#include <botan/aead.h> // TODO: remove

#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

class Cipher_State {
public:
   void encrypt(const std::vector<uint8_t>& header, secure_vector<uint8_t> &fragment)
   {
      const auto key = Botan::hex_decode("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");
      const auto iv  = Botan::hex_decode("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");

      m_encrypt->set_key(key);
      m_encrypt->set_associated_data_vec(header);
      m_encrypt->start(iv);
      m_encrypt->finish(fragment);
   }

   void decrypt(const std::vector<uint8_t>& header, secure_vector<uint8_t> &encrypted_fragment)
   {
      const auto key = Botan::hex_decode("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");
      const auto iv  = Botan::hex_decode("5d 31 3e b2 67 12 76 ee 13 00 0b 30");

      m_decrypt->set_key(key);
      m_decrypt->set_associated_data_vec(header);
      m_decrypt->start(iv);

      try
         {
         m_decrypt->finish(encrypted_fragment);
         }
      catch (const Decoding_Error &ex)
         {
         // Decoding_Error is thrown by AEADs if the provided cipher text was
         // too short to hold an authentication tag. We are treating this as
         // an Invalid_Authentication_Tag so that the TLS channel will react
         // with an BAD_RECORD_MAC alert as specified in RFC 8446 5.2.
         throw Invalid_Authentication_Tag(ex.what());
         }
   }

   Cipher_State()
      : m_encrypt(AEAD_Mode::create("AES-128/GCM", ENCRYPTION))
      , m_decrypt(AEAD_Mode::create("AES-128/GCM", DECRYPTION)) {}

   size_t encrypt_output_length(const size_t input_length) const
   {
      return m_encrypt->output_length(input_length);
   }

private:
   std::unique_ptr<AEAD_Mode> m_encrypt;
   std::unique_ptr<AEAD_Mode> m_decrypt;
};

namespace {

template <typename IteratorT>
bool verify_change_cipher_spec(const IteratorT data, const size_t size)
{
   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type
   //    change_cipher_spec consisting of the single byte value 0x01
   //    at any time [...]. An implementation which receives any other
   //    change_cipher_spec value or which receives a protected
   //    change_cipher_spec record MUST abort the handshake [...].
   const size_t expected_fragment_length = 1;
   const uint8_t expected_fragment_byte = 0x01;
   return (size == expected_fragment_length &&
          *data == expected_fragment_byte);
}

Record_Type read_record_type(const uint8_t type_byte)
   {
   // RFC 8446 5.
   //    If a TLS implementation receives an unexpected record type,
   //    it MUST terminate the connection with an "unexpected_message" alert.
   if (type_byte != Record_Type::APPLICATION_DATA &&
       type_byte != Record_Type::HANDSHAKE        &&
       type_byte != Record_Type::ALERT            &&
       type_byte != Record_Type::CHANGE_CIPHER_SPEC)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "unexpected message received");
      }

   return static_cast<Record_Type>(type_byte);
}

/**
 * RFC 8446 5.1 `TLSPlaintext` without the `fragment` payload data
 */
struct TLSPlaintext_Header
{
   TLSPlaintext_Header(std::vector<uint8_t>::const_iterator b)
      {
      type            = read_record_type(*(b + 0));
      legacy_version  = Protocol_Version(make_uint16(*(b + 1), *(b + 2)));
      fragment_length = make_uint16(*(b + 3), *(b + 4));

      // RFC 8446 5.1
      //    MUST be set to 0x0303 for all records generated by a TLS 1.3
      //    implementation other than an initial ClientHello [...], where
      //    it MAY also be 0x0301 for compatibility purposes.
      if (legacy_version.version_code() != 0x0303 &&
          legacy_version.version_code() != 0x0301)
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "invalid record version");

      // RFC 8446 5.1
      //    Implementations MUST NOT send zero-length fragments of Handshake
      //    types, even if those fragments contain padding.
      //
      //    Zero-length fragments of Application Data MAY be sent, as they are
      //    potentially useful as a traffic analysis countermeasure.
      if (fragment_length == 0 && type != Record_Type::APPLICATION_DATA)
         throw TLS_Exception(Alert::DECODE_ERROR, "empty record received");

      // RFC 8446 5.2
      //    The length [...] is the sum of the lengths of the content and the
      //    padding, plus one for the inner content type, plus any expansion
      //    added by the AEAD algorithm. The length MUST NOT exceed 2^14 + 256 bytes.
      if (fragment_length > MAX_CIPHERTEXT_SIZE_TLS13)
         throw TLS_Exception(Alert::RECORD_OVERFLOW, "overflowing record received");
      }

   TLSPlaintext_Header(const Record_Type type, const size_t fragment_length)
      : type(type)
      , legacy_version(0x0303)
      , fragment_length(static_cast<uint16_t>(fragment_length)) {}

   std::vector<uint8_t> serialize() const {
      return
         {
         static_cast<uint8_t>(type),
         legacy_version.major_version(), legacy_version.minor_version(),
         get_byte<0>(fragment_length), get_byte<1>(fragment_length),
         };
   }

   Record_Type      type;
   Protocol_Version legacy_version;
   uint16_t         fragment_length;
};

}  // namespace


Record_Layer::Record_Layer()
   : m_cipher(std::make_unique<Cipher_State>()) {}

Record_Layer::~Record_Layer() {};

Record_Layer::ReadResult<std::vector<Record>>
Record_Layer::parse_records(const std::vector<uint8_t>& data_from_peer)
{
   std::vector<Record> records_received;

   m_read_buffer.insert(m_read_buffer.end(), data_from_peer.cbegin(), data_from_peer.cend());
   while (true)
      {
      auto result = read_record();

      if (std::holds_alternative<BytesNeeded>(result))
         {
         if (records_received.empty())
            return std::get<BytesNeeded>(result);
         return records_received;
         }

      records_received.emplace_back(std::move(std::get<Record>(result)));
      }
}

std::vector<uint8_t> Record_Layer::prepare_records(const Record_Type type,
                                                   const uint8_t data[],
                                                   size_t size,
                                                   const bool protect)
   {
   // RFC 8446 5.1
   BOTAN_ASSERT(protect || type != Record_Type::APPLICATION_DATA,
      "Application Data records MUST NOT be written to the wire unprotected");

   // RFC 8446 5.1
   //   "MUST NOT sent zero-length fragments of Handshake types"
   //   "a record with an Alert type MUST contain exactly one message" [of non-zero length]
   //   "Zero-length fragments of Application Data MAY be sent"
   BOTAN_ASSERT(size != 0 || type == Record_Type::APPLICATION_DATA,
      "zero-length fragments of types other than application data are not allowed");

   if (type == Record_Type::CHANGE_CIPHER_SPEC &&
       !verify_change_cipher_spec(data, size))
      {
      throw Invalid_Argument("TLS 1.3 deprecated CHANGE_CIPHER_SPEC");
      }

   std::vector<uint8_t> output;

   // calculate the final buffer length to prevent unneccesary reallocations
   const auto records = std::max((size + MAX_PLAINTEXT_SIZE - 1) / MAX_PLAINTEXT_SIZE, size_t(1));
   auto output_length = records * TLS_HEADER_SIZE;
   if (protect) {
      output_length += m_cipher->encrypt_output_length(MAX_PLAINTEXT_SIZE + 1 /* for content type byte */) * (records - 1);
      output_length += m_cipher->encrypt_output_length(size % MAX_PLAINTEXT_SIZE + 1);
   } else {
      output_length += size;
   }
   output.reserve(output_length);

   size_t pt_offset = 0;

   // For protected records we need to write at least one encrypted fragment,
   // even if the plaintext size is zero. This happens only for Application
   // Data types.
   BOTAN_ASSERT_NOMSG(size != 0 || protect);
   do {
      const size_t pt_size = std::min<size_t>(size, MAX_PLAINTEXT_SIZE);
      const size_t ct_size = (!protect) ? pt_size : m_cipher->encrypt_output_length(pt_size + 1 /* for content type byte */);
      const auto   pt_type = (!protect) ? type : Record_Type::APPLICATION_DATA;

      const auto record_header = TLSPlaintext_Header(pt_type, ct_size).serialize();

      output.reserve(output.size() + record_header.size() + ct_size);
      output.insert(output.end(), record_header.cbegin(), record_header.cend());

      if (protect)
         {
         secure_vector<uint8_t> fragment;
         fragment.reserve(ct_size);

         // assemble TLSInnerPlaintext structure
         fragment.insert(fragment.end(), data + pt_offset, data + pt_offset + pt_size);
         fragment.push_back(static_cast<uint8_t>(type));
         // TODO: zero padding could go here, see RFC 8446 5.4

         m_cipher->encrypt(record_header, fragment);
         BOTAN_ASSERT_NOMSG(fragment.size() == ct_size);

         output.insert(output.end(), fragment.cbegin(), fragment.cend());
         }
      else
         {
         output.insert(output.end(), data + pt_offset, data + pt_offset + pt_size);
         }

      pt_offset += pt_size;
      size -= pt_size;
      }
   while(size > 0);

   BOTAN_ASSERT_NOMSG(output.size() == output_length);
   return output;
   }

std::vector<uint8_t> Record_Layer::prepare_dummy_ccs_record()
   {
   uint8_t data = 0x01;
   return prepare_records(Record_Type::CHANGE_CIPHER_SPEC, &data, 1);
   }


Record_Layer::ReadResult<Record> Record_Layer::read_record()
   {
   if (m_read_buffer.size() < TLS_HEADER_SIZE)
      {
      return TLS_HEADER_SIZE - m_read_buffer.size();
      }

   const auto header_begin = m_read_buffer.cbegin();
   const auto header_end   = header_begin + TLS_HEADER_SIZE;
   TLSPlaintext_Header plaintext_header(header_begin);

   if (m_read_buffer.size() < TLS_HEADER_SIZE + plaintext_header.fragment_length)
      {
      return TLS_HEADER_SIZE + plaintext_header.fragment_length - m_read_buffer.size();
      }

   const auto fragment_begin = header_end;
   const auto fragment_end   = fragment_begin + plaintext_header.fragment_length;

   if (plaintext_header.type == Record_Type::CHANGE_CIPHER_SPEC &&
       !verify_change_cipher_spec(fragment_begin, plaintext_header.fragment_length))
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                          "malformed change cipher spec record received");
      }

   Record record(plaintext_header.type,
                 secure_vector<uint8_t>(fragment_begin, fragment_end));
   m_read_buffer.erase(header_begin, fragment_end);

   if (record.type == Record_Type::APPLICATION_DATA)
      {
      m_cipher->decrypt({header_begin, header_end}, record.fragment);

      // hydrate the actual content type from TLSInnerPlaintext
      record.type = read_record_type(record.fragment.back());

      if (record.type == Record_Type::CHANGE_CIPHER_SPEC)
         {
         // RFC 8446 5
         //  An implementation [...] which receives a protected change_cipher_spec record MUST
         //  abort the handshake with an "unexpected_message" alert.
         throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "protected change cipher spec received");
         }
      record.fragment.pop_back();
      }

   return record;
   }
}
