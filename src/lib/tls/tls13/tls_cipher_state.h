/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CIPHER_STATE_
#define BOTAN_TLS_CIPHER_STATE_

#if defined(BOTAN_HAS_TLS_13)

#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/hash.h>

#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>

namespace Botan::TLS {

/**
 * Cipher_State state machine adapted from RFC 8446 7.1.
 *
 *                                     0
 *                                     |
 *                                     v
 *                           PSK ->  HKDF-Extract = Early Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *                                     |                     = binder_key
 *                                     |
 *                                     +-----> Derive-Secret(., "c e traffic", ClientHello)
 *                                     |                     = client_early_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "e exp master", ClientHello)
 *                                     |                     = early_exporter_master_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                             STATE EARLY TRAFFIC
 * This state is reached by constructing Cipher_State using init_with_psk() (not yet implemented).
 * The state can then be further advanced using advance_with_server_hello().
 *                                     *
 *                                     |
 *                                     v
 *                           (EC)DHE -> HKDF-Extract = Handshake Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = client_handshake_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "s hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = server_handshake_traffic_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                          STATE HANDSHAKE TRAFFIC
 * This state is reached by constructing Cipher_State using init_with_server_hello().
 * In this state the handshake traffic secrets are available. The state can then be further
 * advanced using advance_with_server_finished().
 *                                     *
 *                                     |
 *                                     v
 *                           0 -> HKDF-Extract = Master Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = client_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "s ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = server_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "exp master",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = exporter_master_secret
 *                                     *
 *                         STATE APPLICATION TRAFFIC
 * This state is reached by calling advance_with_server_finished(). The state can then be further
 * advanced using advance_with_client_finished().
 *                                     *
 *                                     |
 *                                     +-----> Derive-Secret(., "res master",
 *                                                           ClientHello...client Finished)
 *                                                           = resumption_master_secret
 *                             STATE COMPLETED
 */
class Cipher_State
   {
   public:
      /**
       * Construct a Cipher_State after receiving a server hello message.
       */
      static std::unique_ptr<Cipher_State> init_with_server_hello(
         secure_vector<uint8_t>&& shared_secret,
         const Ciphersuite& cipher,
         const std::vector<uint8_t>& transcript_hash)
         {
         auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(cipher));
         cs->advance_without_psk();
         return cs;
         }

      void advance_with_server_finished(const std::vector<uint8_t>& transcript_hash)
      {
      }

      void advance_with_client_finished(const std::vector<uint8_t>& transcript_hash)
      {
        throw Invalid_State("nyi");
      }

      void encrypt(const std::vector<uint8_t>& header, secure_vector<uint8_t>& fragment)
         {
         const auto key = Botan::hex_decode("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");
         const auto iv  = Botan::hex_decode("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");

         m_encrypt->set_key(key);
         m_encrypt->set_associated_data_vec(header);
         m_encrypt->start(iv);
         m_encrypt->finish(fragment);
         }

      void decrypt(const std::vector<uint8_t>& header, secure_vector<uint8_t>& encrypted_fragment)
         {
         const auto key = Botan::hex_decode("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");
         const auto iv  = Botan::hex_decode("5d 31 3e b2 67 12 76 ee 13 00 0b 30");

         m_decrypt->set_key(m_peer_write_key);
         m_decrypt->set_associated_data_vec(header);
         m_decrypt->start(m_peer_write_iv);

         try
            {
            m_decrypt->finish(encrypted_fragment);
            }
         catch(const Decoding_Error& ex)
            {
            // Decoding_Error is thrown by AEADs if the provided cipher text was
            // too short to hold an authentication tag. We are treating this as
            // an Invalid_Authentication_Tag so that the TLS channel will react
            // with an BAD_RECORD_MAC alert as specified in RFC 8446 5.2.
            throw Invalid_Authentication_Tag(ex.what());
            }
         }

      size_t encrypt_output_length(const size_t input_length) const
         {
         return m_encrypt->output_length(input_length);
         }

   private:
      static size_t hash_output_length(const Ciphersuite& cipher)
         {
         return HashFunction::create_or_throw(cipher.prf_algo())->output_length();
         }

      static std::unique_ptr<MessageAuthenticationCode> create_hmac(const Ciphersuite& cipher)
         {
         return std::make_unique<HMAC>(HashFunction::create_or_throw(cipher.prf_algo()));
         }

      Cipher_State(const Ciphersuite& cipher)
         : m_hash_length(hash_output_length(cipher))
         , m_encrypt(AEAD_Mode::create(cipher.cipher_algo(), ENCRYPTION))
         , m_decrypt(AEAD_Mode::create(cipher.cipher_algo(), DECRYPTION))
         , m_extract(std::make_unique<HKDF_Extract>(create_hmac(cipher)))
         , m_expand(std::make_unique<HKDF_Expand>(create_hmac(cipher)))
         , m_salt(m_hash_length, 0x00) {}

      void advance_without_psk()
         {
         const auto psk = std::vector<uint8_t>(m_hash_length, 0x00);
         const auto early_secret = m_extract->derive_key(m_hash_length, psk, m_salt, std::vector<uint8_t>());
         m_salt = m_expand->derive_key(m_hash_length, early_secret, "", "derived");
         }

   private:
      const size_t m_hash_length;

      std::unique_ptr<AEAD_Mode> m_encrypt;
      std::unique_ptr<AEAD_Mode> m_decrypt;

      std::unique_ptr<HKDF_Extract> m_extract;
      std::unique_ptr<HKDF_Expand>  m_expand;

      secure_vector<uint8_t> m_salt;

      secure_vector<uint8_t> m_write_key;
      secure_vector<uint8_t> m_write_iv;
      secure_vector<uint8_t> m_peer_write_key;
      secure_vector<uint8_t> m_peer_write_iv;
   };

}

#endif
#endif
