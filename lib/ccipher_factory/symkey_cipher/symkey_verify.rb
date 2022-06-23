


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

        ts = BinStruct.instance.struct_from_bin(meta)
        digestAlgo = BTag.value_constant(ts.digest_algo)
        @sign = ts.signature

        raise SymKeySignerError, "Verification key must be given" if is_empty?(@verification_key)

        raise SymKeySignerError, "Symmetric key type is expected" if not @verification_key.is_a?(SymKey)

        raise SymKeySignerError, "Given digest algo '#{digestAlgo}' is not supported" if not Digest::SupportedDigest.instance.is_supported?(digestAlgo)

        hconf = Ccrypto::HMACConfig.new
        hconf.key = Ccrypto::SecretKey.new(@verification_key.keytype, @verification_key.key)
        hconf.digest = digestAlgo

        @hmac = Ccrypto::AlgoFactory.engine(hconf)

        #@hmac = OpenSSL::HMAC.new(@verification_key.key, OpenSSL::Digest.new(Digest.to_digest_string(digestAlgo)))

      end

      def verify_update_data(val)
        @hmac.hmac_update(val) 
      end

      def verify_final

        sign = @hmac.hmac_final

        comp = Ccrypto::UtilFactory.instance(:comparator)
        res = comp.is_equal?(sign, @sign)
        #res = (sign == @sign)

        if not res
          logger.tdebug :symkey_ver, "Generated : #{sign}"
          logger.tdebug :symkey_ver, "Enveloped : #{@sign}"
        end

        res

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
