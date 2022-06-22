


require_relative '../digest/digest'
require_relative '../digest/supported_digest'

module CcipherFactory
  module KDF
    module HKDF
      include TR::CondUtils
      include Common
      include TR::DataConvUtils

      attr_accessor :outByteLength, :salt
      attr_accessor :digestAlgo
      attr_reader :derivedVal
      def derive_init(*args, &block)

        len = args.first
        @outByteLength = len/8 if not_empty?(len)

        @salt = SecureRandom.random_bytes(@outByteLength) if is_empty?(@salt)

        if block
          instance_eval(&block)
          derive_final
        else
          self
        end

      end

      def derive_update(val)
        intOutputBuf.write(val)
      end

      def derive_final

        raise KDFError, "outByteLength is required" if is_empty?(@outByteLength)

        digest = nil
        digestId = nil
        #if not_empty?(@digest)

        #  case @digest
        #  when String, Symbol
        #    logger.tdebug :hkdf_derive_final, "Given digest object is a string/symbol #{@digest}"
        #    @digestAlgo = @digest

        #  #when OpenSSL::Digest
        #  #  digestId = Digest.to_digest_string(@digest.name)
        #  #  logger.tdebug :hkdf_derive_final, "Using user given OpenSSL digest object #{@digest}"
        #  #  digest = @digest

        #  #when CcipherFactory::Digest
        #  #  digestId = @digest.algo

        #  #  logger.tdebug :hkdf_derive_final, "Using user given CipherFactory digest #{@digest}"
        #  #  digest = OpenSSL::Digest.new(digestId)

        #  else
        #    raise KDFError, "Digest object #{@digest.class} is not supported"
        #  end

        #end

        if is_empty?(@digestAlgo)
          digestVal = CcipherFactory::Digest::SupportedDigest.instance.default_digest
          digestId = digestVal

          logger.tdebug :hkdf_derive_final, "digest algo is nil. Using default digest #{digestVal}"

        else
          raise KDFError, "Given digest algo '#{@digestAlgo}' is not supported" if not Digest::SupportedDigest.instance.is_supported?(@digestAlgo)

          logger.tdebug :hkdf_derive_final, "Using user given digest algo #{@digestAlgo}"

          digestId = @digestAlgo
        end

        @info = "" if @info.nil?

        hconf = Ccrypto::HKDFConfig.new
        hconf.digest = digestId
        hconf.salt = @salt
        hconf.info = @info
        hconf.outBitLength = @outByteLength*8

        hkdf = Ccrypto::AlgoFactory.engine(hconf)

        @derivedVal = hkdf.derive(intOutputBuf.bytes)

        write_to_output(@derivedVal) if is_output_given?

        #ts = Encoding::ASN1Encoder.instance(:kdf_hkdf)
        #ts.set(:digest, Tag.constant(digestId))
        #ts.set(:salt, @salt)
        #ts.set(:outByteLength, @outByteLength)
        #ts.to_asn1 

        ts = BinStruct.instance.struct(:kdf_hkdf)
        ts.digest = BTag.constant_value(digestId)
        ts.salt = @salt
        ts.outByteLength = @outByteLength
        p ts
        ts.encoded

      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :hkdf
        end
        @logger
      end

    end
  end
end
