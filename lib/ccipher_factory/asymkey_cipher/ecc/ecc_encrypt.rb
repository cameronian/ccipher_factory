
require_relative '../../symkey_cipher/symkey_cipher'
require_relative '../../kdf/kdf'

require_relative '../../asymkey/asymkey_generator'
require_relative '../../compression/compression_helper'

module CcipherFactory
  module AsymKeyCipher
    module ECCEncrypt
      include TR::CondUtils
      include Common
      include Compression::CompressionHelper

      class ECCCipherError < AsymKeyCipher::AsymKeyCipherError; end

      attr_accessor :recipient_key, :sender_keypair

      def encrypt_init(opts = { }, &block)

        #@sender = opts[:sender_keypair]
        #recpPub = opts[:recipient_public]
        recpPub = @recipient_key

        raise ECCCipherError, "Receipient public key is required" if is_empty?(recpPub)
        raise ECCCipherError, "Cipher requires output to be set" if not is_output_given?  

        if is_empty?(@sender_keypair)
          @sender_keypair = AsymKeyGenerator.generate(:ecc) 
        end

        #derived = @sender_keypair.dh_compute_key(recpPub)
        #logger.debug "sender : #{@sender_keypair.inspect} / #{@sender_keypair.private?}"
        #logger.debug "recp : #{recpPub.inspect}"
        derived = @sender_keypair.derive_dh_shared_secret(recpPub)

        @sessKey = SymKeyGenerator.derive(:aes, 256) do |ops|
          case ops
          when :password
            derived
          end
        end

        @cipher = SymKeyCipher.encryptor
        @cipher.output(intOutputFile)
        @cipher.key = @sessKey

        if is_compression_on?
          @cipher.compression_on
        else
          @cipher.compression_off
        end

        @cipher.encrypt_init #(@sessKey)

        if block
          instance_eval(&block)
          encrypt_final
        else
          self
        end

      end

      def encrypt_update(val)
        @cipher.encrypt_update(val) 
      end

      def encrypt_final

        cipherConfig = @cipher.encrypt_final 

        intOutputFile.rewind
        while not intOutputFile.eof?
          write_to_output(intOutputFile.read)
        end
        intOutputFile.close!

        ts = Encoding::ASN1Encoder.instance(:ecc_cipher)
        ts.set(:sender_public, @sender_keypair.public_key.to_bin)
        ts.set(:cipher_config, cipherConfig)
        ts.set(:key_config, @sessKey.to_asn1) 
        ts.to_asn1

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_enc
        end
        @logger
      end

    end
  end
end
