
require 'openssl'

require_relative '../digest/supported_digest'

module CcipherFactory
  module SymKeySigner

    module SymKeySign
      include TR::CondUtils
      include Common

      attr_accessor :signing_key, :digest_algo

      def init
        @digest_algo = Digest::SupportedDigest.instance.default_digest
      end

      def sign_init(opts = { }, &block)

        raise SymKeySignerError, "Signing symkey is required" if is_empty?(@signing_key)
        raise SymKeySignerError, "Given digest algo is not supported" if not Digest::SupportedDigest.instance.is_supported?(@digest_algo)

        hconf = Ccrypto::HMACConfig.new
        hconf.key = Ccrypto::SecretKey.new(@signing_key.keytype, @signing_key.key)
        hconf.digest = @digest_algo

        @hmac = Ccrypto::AlgoFactory.engine(hconf)

        #@hmac = OpenSSL::HMAC.new(@signing_key.key, OpenSSL::Digest.new(Digest.to_digest_string(@digest_algo)))

        if block
          instance_eval(&block)
          sign_final
        else
          self
        end

      end

      def sign_update(val)
        raise SymKeySignerError, "Please call sign_init before sign_update" if @hmac.nil?
        @hmac.hmac_update(val)
      end

      def sign_final

        raise SymKeySignerError, "Please call sign_init before sign_update" if @hmac.nil?

        sign = @hmac.hmac_final

        ts = BinStruct.instance.struct(:symkey_signature) 
        ts.digest_algo = BTag.constant_value(@digest_algo)
        ts.signature = sign
        ts.encoded

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :symkey_sign
        end
        @logger
      end

    end

  end
end
