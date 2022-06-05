

require_relative '../digest/digest'
require_relative '../digest/supported_digest'

module CcipherFactory
  module KDF
    module Scrypt
      include TR::CondUtils
      include Common

      ## 
      # Mixin methods
      ##
      attr_accessor :cost, :parallel, :blocksize, :salt, :outByteLength
      attr_accessor :digestAlgo, :digest
      attr_reader :derivedVal
      def derive_init(*args, &block)

        len = args.first
        @outByteLength = len/8 if not_empty?(len)

        @cost = 65536 if is_empty?(@cost)
        @parallel = 1 if is_empty?(@parallel)
        @blocksize = 8 if is_empty?(@blocksize)
        @salt = SecureRandom.random_bytes(16) if is_empty?(@salt)

        if @digest.nil?
          @digestAlgo = Digest::SupportedDigest.instance.default_digest if is_empty?(@digestAlgo)
          @digest = Digest.instance
          @digest.digest_init(@digestAlgo)
        else
          @digestAlgo = @digest.algo
        end

        @digest.output(intOutputBuf)

        if block
          instance_eval(&block)
          derive_final
        else
          self
        end

      end

      def derive_update(val)
        @digest.digest_update(val) 
      end

      def derive_final(&block)

        raise KDFError, "outByteLength is required" if is_empty?(@outByteLength)

        digMeta = @digest.digest_final 

        sconf = Ccrypto::ScryptConfig.new
        sconf.outBitLength = @outByteLength*8
        sconf.salt = @salt
        sconf.cost = @cost
        sconf.parallel = @parallel
        sconf.blockSize = @blocksize

        scrypt = Ccrypto::AlgoFactory.engine(sconf)

        @derivedVal = scrypt.derive(intOutputBuf.bytes)

        #@derivedVal = OpenSSL::KDF.scrypt(intOutputBuf.string, salt: @salt, N: @cost, r: @blocksize, p: @parallel, length: @outByteLength)

        write_to_output(@derivedVal) if is_output_given?

        ts = Encoding::ASN1Encoder.instance(:kdf_scrypt)
        ts.set(:digest, digMeta)
        ts.set(:salt, @salt)
        ts.set(:cost, @cost)
        ts.set(:blocksize, @blocksize)
        ts.set(:parallel, @parallel)
        ts.set(:outByteLength, @outByteLength)
        ts.to_asn1 

      end


    end
  end
end
