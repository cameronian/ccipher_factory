


module CcipherFactory
  module SymKeySigner

    module SymKeyVerify
      include TR::CondUtils

      attr_accessor :verification_key
      def verify_init(opts = {  }, &block)

        if block
          instance_eval(&block)
          verify_final
        else
          self
        end

      end

      def verify_update_meta(meta)

        ts = Encoding::ASN1Decoder.from_asn1(meta)
        digestAlgo = Tag.constant_key(ts.value(:digest_algo))
        @sign = ts.value(:signature)

        raise SymKeySignerError, "Verification key must be given" if is_empty?(@verification_key)

        raise SymKeySignerError, "Symmetric key type is expected" if not @verification_key.is_a?(SymKey)

        raise SymKeySignerError, "Given digest algo '#{digestAlgo}' is not supported" if not Digest::SupportedDigest.instance.is_supported?(digestAlgo)

        hconf = Ccrypto::HMACConfig.new
        hconf.key = Ccrypto::SecretKey.new(:aes, @verification_key.key)
        hconf.digest = digestAlgo

        @hmac = Ccrypto::AlgoFactory.engine(hconf)

        #@hmac = OpenSSL::HMAC.new(@verification_key.key, OpenSSL::Digest.new(Digest.to_digest_string(digestAlgo)))

      end

      def verify_update_data(val)
        @hmac.hmac_update(val) 
      end

      def verify_final

        sign = @hmac.hmac_final

        logger.tdebug :symkey_ver, "Generated : #{sign}"
        logger.tdebug :symkey_ver, "Enveloped : #{@sign}"

        sign == @sign

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :symkey_ver
        end
        @logger
      end

    end

  end
end
