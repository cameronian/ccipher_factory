

require_relative '../../symkey_cipher/symkey_cipher'
require_relative '../../kdf/kdf'
require_relative '../../asymkey/ecc_keypair'

module CcipherFactory
  module AsymKeyCipher
    module ECCDecrypt
      include TR::CondUtils
      include Common

      class ECCCipherError < AsymKeyCipherError; end

      attr_accessor :decryption_key
      def decrypt_init(opts = {  }, &block)

        #raise ECCCipherError, "Decryption keypair is mandatory" if is_empty?(eccKeypair)

        #@eccKeypair = eccKeypair

        if block
          instance_eval(&block)
          decrypt_final
        else
          self
        end

      end

      def decrypt_update_meta(meta)

        raise ECCCipherError, "Output is required" if not is_output_given?

        ts = Encoding::ASN1Decoder.from_asn1(meta)
        senderPub = ts.value(:sender_public)
        cipherConf = ts.value(:cipher_config)
        keyConf = ts.value(:key_config)

        #sender = OpenSSL::PKey::EC.new(senderPub)
        sender = Ccrypto::AlgoFactory.engine(Ccrypto::ECCPublicKey).to_key(senderPub)
        #derived = @decryption_key.dh_compute_key(sender.public_key)
        derived = @decryption_key.derive_dh_shared_secret(sender)

        sessKey = DerivedSymKey.from_asn1(keyConf) do |ops|
          case ops
          when :password
            derived
          end
        end

        @cipher = SymKeyCipher.decryptor
        @cipher.output(@output)
        @cipher.key = sessKey
        @cipher.decrypt_init
        @cipher.decrypt_update_meta(cipherConf)

      end

      def decrypt_update_cipher(cipher)
        raise ECCCipherError, "Please update meta first before update cipher" if is_empty?(@cipher) 

        @cipher.decrypt_update_cipher(cipher)
      end

      def decrypt_final

        @cipher.decrypt_final

      end

    end
  end
end
