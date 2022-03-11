

require_relative '../asymkey_cipher/asymkey_cipher'
require_relative '../symkey_cipher/symkey_cipher'

module CcipherFactory
  module CompositeCipher

    module SignEncryptor
      include TR::CondUtils
      include Common
      include Compression::CompressionHelper

      attr_accessor :signing_key, :encryption_key, :sender_keypair

      def sign_encrypt_init(opts = {  }, &block)

        sKey = @signing_key
        eKey = @encryption_key
        sender = @sender_keypair

        compress = opts[:compress] || false

        raise CompositeCipherError, "Signing key is required" if is_empty?(sKey)
        raise CompositeCipherError, "Encryption key is required" if is_empty?(eKey)
        raise CompositeCipherError, "Output is required" if not is_output_given?

        @signingBuf = Tempfile.new
        @signingBuf.binmode

        case sKey
        when SymKey
          @signer = SymKeySigner.att_signer
          @signer.output(@signingBuf)
          @signer.compression_on if is_compression_on?
          @signer.signing_key = sKey
          @signer.att_sign_init
        when AsymKey
          @signer = AsymKeySigner.att_signer
          @signer.output(@signingBuf)
          @signer.compression_on if is_compression_on?
          @signer.signing_key = sKey
          @signer.att_sign_init
        else
          raise CompositeCipherError, "Unknown signing key type '#{sKey.class}'"
        end

        # Encryption Key
        case eKey
        when SymKey
          @enc = SymKeyCipher.encryptor
          @enc.output(@output)
          @enc.key = eKey
          @enc.encrypt_init
        when AsymKey, Ccrypto::PublicKey #, OpenSSL::PKey::EC::Point
          @enc = AsymKeyCipher.encryptor
          @enc.output(@output)
          @enc.recipient_key = eKey
          @enc.sender_keypair = sender if not_empty?(sender)
          @enc.encrypt_init
        else
          raise CompositeCipherError, "Unknown encryption key type '#{eKey.class}'"
        end

        if block
          instance_eval(&block)
          sign_encrypt_final
        else
          self
        end

      end

      def sign_encrypt_update(data)
        @signer.att_sign_update(data)   
      end

      def sign_encrypt_final

        smeta = @signer.att_sign_final 

        @signingBuf.rewind
        while not @signingBuf.eof?
          @enc.encrypt_update(@signingBuf.read)
        end

        meta = @enc.encrypt_final

        ts = Encoding::ASN1Encoder.instance(:sign_encrypt_cipher)
        ts.set(:signer_config, smeta)
        ts.set(:cipher_config, meta)

        ts.to_asn1


      end

    end

  end
end

