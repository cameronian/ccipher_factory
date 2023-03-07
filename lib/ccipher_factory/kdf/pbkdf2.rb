

module CcipherFactory
  module KDF
    module PBKDF2
      include TR::CondUtils
      include Common

      attr_accessor :salt, :iter, :outByteLength, :digestAlgo
      attr_accessor :attachedDigest, :attachedValue
      attr_reader :derivedVal

      def derive_init(*args, &block)

        len = args.first
        @outByteLength = len/8 if not_empty?(len)

        @salt = SecureRandom.random_bytes(@outByteLength) if is_empty?(@salt)

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
        intOutputBuf.write(val)
      end

      def derive_final
        
        raise KDFError, "outByteLength is required" if is_empty?(@outByteLength)
        
        #if is_empty?(@digestAlgo)
        #  digestVal = CcipherFactory::Digest::SupportedDigest.instance.default_digest
        #  digestId = digestVal

        #  logger.tdebug :pbkdf2_derive_final, "digest algo is nil. Using default digest #{digestVal}"

        #else
        #  raise KDFError, "Given digest algo '#{@digestAlgo}' is not supported" if not Digest::SupportedDigest.instance.is_supported?(@digestAlgo)

        #  logger.tdebug :pbkdf2_derive_final, "Using user given digest algo #{@digestAlgo}"

        #  digestId = @digestAlgo
        #end

        hconf = Ccrypto::PBKDF2Config.new
        #hconf.digest = digestId
        hconf.digest = @digestAlgo
        hconf.salt = @salt if not_empty?(@salt)
        hconf.iter = @iter if not_empty?(@iter)
        hconf.outBitLength = @outByteLength*8

        hkdf = Ccrypto::AlgoFactory.engine(hconf)

        @derivedVal = hkdf.derive(intOutputBuf.bytes)

        write_to_output(@derivedVal) if is_output_given?

        ts = BinStruct.instance.struct(:kdf_pbkdf2)
        #ts.digest = BTag.constant_value(digestId)
        ts.digest = BTag.constant_value(hconf.digest)
        ts.salt = @salt
        ts.outByteLength = @outByteLength
        ts.iterations = hconf.iter
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

      def logger
        if @logger.nil?
          @logger = TeLogger::Tlogger.new
          @logger.tag = :pbkdf2
        end
        @logger
      end

    end
  end
end
