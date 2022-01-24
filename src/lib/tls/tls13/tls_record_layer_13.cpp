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

#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

namespace {

/**
 * Thrown when some parsing code detects that it needs more bytes
 * Note: this is normal control flow implemented via an exception.
 *       waiting for C++'s std::expected<>
 */
class More_Bytes_Needed : public Exception
{
public:
   More_Bytes_Needed(BytesNeeded needed) : Exception("more!"), m_needed(needed) {}

   BytesNeeded how_many() const
      {
      return m_needed;
      }

private:
   BytesNeeded m_needed;
};

void check_enough_bytes(const TLS_Data_Reader &reader, const BytesNeeded bytes_needed)
   {
   if (reader.remaining_bytes() < bytes_needed)
      {
      throw More_Bytes_Needed(bytes_needed - reader.remaining_bytes());
      }
   }

/**
 * RFC 8446 5.1 `TLSPlaintext` without the `fragment` payload data
 */
struct TLSPlaintext_Header
{
   TLSPlaintext_Header(TLS_Data_Reader& reader)
      {
      check_enough_bytes(reader, TLS_HEADER_SIZE);

      type            = static_cast<Record_Type>(reader.get_byte());
      legacy_version  = Protocol_Version(reader.get_uint16_t());
      fragment_length = reader.get_uint16_t();

      // RFC 8446 5.
      //    If a TLS implementation receives an unexpected record type,
      //    it MUST terminate the connection with an "unexpected_message" alert.
      if (type != Record_Type::APPLICATION_DATA &&
          type != Record_Type::HANDSHAKE        &&
          type != Record_Type::ALERT            &&
          type != Record_Type::CHANGE_CIPHER_SPEC)
      {
         throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "unexpected message received");
      }

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

   Record_Type      type;
   Protocol_Version legacy_version;
   uint16_t         fragment_length;
};

}  // namespace

Record_Layer::ReadResult<std::vector<Record>>
Record_Layer::received_data(const std::vector<uint8_t>& data_from_peer)
{
   std::vector<Record> records_received;

   try
      {
      m_buffer.insert(m_buffer.end(), data_from_peer.cbegin(), data_from_peer.cend());

      auto reader = std::make_unique<TLS_Data_Reader>("TLS 1.3 record", m_buffer);

      while (reader->has_remaining())
         {
         TLSPlaintext_Header plaintext_header(*reader);
         check_enough_bytes(*reader, plaintext_header.fragment_length);

         if (plaintext_header.type == Record_Type::CHANGE_CIPHER_SPEC)
            {
            // RFC 8446 5.
            //    An implementation may receive an unencrypted record of type
            //    change_cipher_spec consisting of the single byte value 0x01
            //    at any time [...]. An implementation which receives any other
            //    change_cipher_spec value or which receives a protected
            //    change_cipher_spec record MUST abort the handshake [...].
            const size_t expected_fragment_length = 1;
            const uint8_t expected_fragment_byte = 0x01;
            if (plaintext_header.fragment_length != expected_fragment_length ||
                reader->get_byte() != expected_fragment_byte)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                                   "unexpected change cipher spec record received");

            // reset reader and buffer
            m_buffer.erase(m_buffer.begin(), m_buffer.begin() + TLS_HEADER_SIZE + plaintext_header.fragment_length);
            reader = std::make_unique<TLS_Data_Reader>("TLS 1.3 record", m_buffer);

            records_received.emplace_back(Record_Type::CHANGE_CIPHER_SPEC, secure_vector<uint8_t>());
            }
         else if (plaintext_header.type == Record_Type::HANDSHAKE || plaintext_header.type == Record_Type::ALERT)
            {
            records_received.emplace_back(plaintext_header.type,
                reader->get_elem<uint8_t,
                secure_vector<uint8_t>>(plaintext_header.fragment_length));

            m_buffer.erase(m_buffer.begin(), m_buffer.begin() + TLS_HEADER_SIZE + plaintext_header.fragment_length);
            reader = std::make_unique<TLS_Data_Reader>("TLS 1.3 record", m_buffer);
            }
         else
            {
            // TODO: make this a valid implementation
            m_buffer.erase(m_buffer.begin(), m_buffer.begin() + TLS_HEADER_SIZE + plaintext_header.fragment_length);
            reader = std::make_unique<TLS_Data_Reader>("TLS 1.3 record", m_buffer);

            records_received.emplace_back(plaintext_header.type, secure_vector<uint8_t>(plaintext_header.fragment_length));
            }
         }
      }
   catch (const More_Bytes_Needed &needs)
      {
      if (records_received.empty())
         return needs.how_many();
      }

   return records_received;
}

}
