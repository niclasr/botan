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
#include <botan/tls_magic.h>

#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/loadstor.h>

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
         const Connection_Side side,
         secure_vector<uint8_t>&& shared_secret,
         const Ciphersuite& cipher,
         const std::vector<uint8_t>& transcript_hash)
         {
         auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, cipher));
         cs->advance_without_psk();
         cs->advance_with_server_hello(std::move(shared_secret), transcript_hash);
         return cs;
         }

      void advance_with_server_finished(const std::vector<uint8_t>& transcript_hash)
         {
         BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);
         }

      void advance_with_client_finished(const std::vector<uint8_t>& transcript_hash)
         {
         BOTAN_ASSERT_NOMSG(m_state == State::ApplicationTraffic);
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

      /**
       * @param cipher  the negotiated cipher suite
       * @param whoami  whether we play the SERVER or CLIENT
       */
      Cipher_State(Connection_Side whoami, const Ciphersuite& cipher)
         : m_state(State::Uninitialized)
         , m_connection_side(whoami)
         , m_hash_length(hash_output_length(cipher))
         , m_encrypt(AEAD_Mode::create(cipher.cipher_algo(), ENCRYPTION))
         , m_decrypt(AEAD_Mode::create(cipher.cipher_algo(), DECRYPTION))
         , m_extract(std::make_unique<HKDF_Extract>(create_hmac(cipher)))
         , m_expand(std::make_unique<HKDF_Expand>(create_hmac(cipher)))
         , m_salt(m_hash_length, 0x00) {}

      void advance_without_psk()
         {
         BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);

         const auto early_secret = hkdf_extract(secure_vector<uint8_t>(m_hash_length, 0x00));
         m_salt = derive_secret(early_secret, "derived");

         m_state = State::EarlyTraffic;
         }

      void advance_with_server_hello(secure_vector<uint8_t>&& shared_secret,
                                     const std::vector<uint8_t>& transcript_hash)
         {
         BOTAN_ASSERT_NOMSG(m_state == State::EarlyTraffic);

         const auto handshake_secret = hkdf_extract(std::move(shared_secret));

         derive_traffic_secrets(
            derive_secret(handshake_secret, "c hs traffic", transcript_hash),
            derive_secret(handshake_secret, "s hs traffic", transcript_hash));

         m_salt = derive_secret(handshake_secret, "derived");

         m_state = State::HandshakeTraffic;
         }

      void derive_traffic_secrets(secure_vector<uint8_t> client_traffic_secret,
                                  secure_vector<uint8_t> server_traffic_secret)
         {
         const auto& traffic_secret =
            (m_connection_side == Connection_Side::CLIENT)
               ? client_traffic_secret
               : server_traffic_secret;

         const auto& peer_traffic_secret =
            (m_connection_side == Connection_Side::SERVER)
               ? client_traffic_secret
               : server_traffic_secret;

         m_write_key = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
         m_peer_write_key = hkdf_expand_label(peer_traffic_secret, "key", {}, m_decrypt->minimum_keylength());

         m_write_iv = hkdf_expand_label(traffic_secret, "iv", {}, m_encrypt->default_nonce_length());
         m_peer_write_iv = hkdf_expand_label(peer_traffic_secret, "iv", {}, m_decrypt->default_nonce_length());
         }

      /**
       * HKDF-Extract from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_extract(secure_vector<uint8_t>&& ikm)
          {
         return m_extract->derive_key(m_hash_length, ikm, m_salt, std::vector<uint8_t>());
         }

      /**
       * HKDF-Expand-Label from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_expand_label(
          const secure_vector<uint8_t>& secret,
          std::string                   label,
          const std::vector<uint8_t>&   context,
          const size_t                  length)
         {
         // assemble (serialized) HkdfLabel
         std::vector<uint8_t> hkdf_label;
         hkdf_label.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */) + context.size());

         // length
         BOTAN_ASSERT_NOMSG(length <= std::numeric_limits<uint16_t>::max());
         const auto len = static_cast<uint16_t>(length);
         hkdf_label.push_back(get_byte<0>(len));
         hkdf_label.push_back(get_byte<1>(len));

         // label
         const std::string prefix = "tls13 ";
         hkdf_label.insert(hkdf_label.end(), prefix.cbegin(), prefix.cend());
         hkdf_label.insert(hkdf_label.end(), label.cbegin(), label.cend());

         // context
         hkdf_label.insert(hkdf_label.end(), context.cbegin(), context.cend());

         // HKDF-Expand
         return m_expand->derive_key(length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
         }

      /**
       * Derive-Secret from RFC 8446 7.1
       */
      secure_vector<uint8_t> derive_secret(
          const secure_vector<uint8_t>& secret,
          std::string label,
          const std::vector<uint8_t>& messages={})
      {
         return hkdf_expand_label(secret, label, messages, m_hash_length);
      }

   private:
      enum class State
         {
         Uninitialized,
         EarlyTraffic,
         HandshakeTraffic,
         ApplicationTraffic,
         Completed
         };

   private:
      State           m_state;
      Connection_Side m_connection_side;

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
