

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
      attr_accessor :attachedDigest, :attachedValue
      attr_reader :derivedVal
      def derive_init(*args, &block)

        len = args.first
        @outByteLength = len/8 if not_empty?(len)

        @cost = 65536 if is_empty?(@cost)
        @parallel = 1 if is_empty?(@parallel)
        @blocksize = 8 if is_empty?(@blocksize)
        @salt = SecureRandom.random_bytes(16) if is_empty?(@salt)

        logger.debug "Cost : #{@cost}"
        logger.debug "Parallel : #{@parallel}"
        logger.debug "Blocksize : #{@blocksize}"
        logger.debug "Salt : #{@salt.inspect}"
        logger.debug "Digest Algo : #{@digestAlgo}"
        logger.debug "Digest : #{@digest}"

        if @digest.nil?
          logger.debug "Initializing digest with algo #{@digestAlgo}"
          @digestAlgo = Digest::SupportedDigest.instance.default_digest if is_empty?(@digestAlgo)
          @digest = Digest.instance
          @digest.digest_init(@digestAlgo)
        else
          logger.debug "Setting digest algo value from digest #{@digest}"
          @digestAlgo = @digest.algo
        end

        @digest.output(intOutputBuf)

        if is_empty?(@attachedValue)
          @attachedDigest = false if is_empty?(@attachedDigest)
        else
          @attachedDigest = true
        end

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

        if is_output_given?
          write_to_output(@derivedVal)
        end

        ts = BinStruct.instance.struct(:kdf_scrypt) 
        ts.digest = digMeta
        ts.salt = @salt
        ts.cost = @cost
        ts.blocksize = @blocksize
        ts.parallel = @parallel
        ts.outByteLength = @outByteLength
        if is_bool?(@attachedDigest) and @attachedDigest
          ts.value = @derivedVal
        else
          ts.value = ""
        end
        ts.encoded

      end

      def is_attached_mode?
        if is_empty?(@attachedValue) 
          @attachedDigest
        else
          true
        end
      end

      private
      def logger
        if @logger.nil?
          @logger = TeLogger::Tlogger.new
          @logger.tag = :scrypt
        end
        
        @logger
      end


    end
  end
end
