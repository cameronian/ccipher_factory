
require_relative 'supported_digest'

module CcipherFactory
  module Digest
    include TR::CondUtils
    include CcipherFactory::Common

    class DigestError < StandardError; end

    class DigestEngine; end

    def self.instance #(eng = SupportedDigest.instance.default_digest, *args)
      #raise DigestEror, "Digest '#{eng}' is not supported" if not SupportedDigest.instance.is_supported?(eng)
      dig = DigestEngine.new
      dig.extend(Digest)
      dig
    end

    def self.from_encoded(bin, &block)
      ts = BinStruct.instance.struct_from_bin(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)

      if ts.oid == BTag.constant_value(:digest_attached)
        dig = from_encoded(ts.digest_config)
        dig.digestVal = ts.digest_value
        dig
      else

        algo = BTag.value_constant(ts.digest_algo)
        logger.debug "from_encoded algo : #{algo}"
        dig = instance
        dig.salt = ts.salt
        dig.digest_init(algo, dig.salt, &block)
      end
    end

    def self.parse(bin, &block)
     
      res = {  }
      ts = BinStruct.instance.struct_from_bin(bin)
      res[:type] = BTag.value_constant(ts.oid)

      if res[:type] == :digest_attached
        #conf = Encoding::ASN1Decoder.from_encoded(ts.value(:digest_config))
        conf = BinStruct.instance.struct_from_bin(ts.digest_config)
        res[:algo] = BTag.value_constant(conf.digest_algo)
        res[:salt] = conf.salt
        #res[:algo] = Tag.constant_key(conf.value(:digest_algo)) 
        #res[:salt] = conf.value(:salt)
      end

      res[:digest] = ts.digest_value

      res

    end

    def self.logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :ccfact_digest
      end
      @logger
    end

    ## 
    # Mixin methods
    ##
    attr_accessor :algo, :salt, :digestVal
    def digest_init(*args, &block)

      logger.debug "args : #{args}"

      @algo = args.first
      @algo = SupportedDigest.instance.default_digest if is_empty?(@algo)
      raise DigestError, "Given digest '#{@algo}' is not supported.\nPossible digest algo including: #{SupportedDigest.instance.supported.join(", ")}" if not SupportedDigest.instance.is_supported?(@algo)

      logger.debug "Digest algo in init : #{@algo}"

      @digest = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig).digest(@algo)

      #@digest = OpenSSL::Digest.new(Digest.to_digest_string(@algo))

      salt = args[1]
      if not_empty?(salt)
        logger.debug "Salt given #{salt} / #{salt.length}"

        case salt
        when :random_salt, :random
          saltLen = args[2] || 16
          sre = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)
          @salt = sre.random_bytes(saltLen)
          @digest.digest_update(@salt)
        else
          if salt.is_a?(String)
            @salt = salt
            @digest.digest_update(@salt)
          else
            raise DigestError, "Unknown option '#{salt}' for salt"
          end
        end
      end

      if block
        instance_eval(&block)
        digest_final
      else
        self
      end

    end

    def digest_update(val)
      raise DigestError, "Please call digest_init first before call update() (#{@digest.inspect})" if @digest.nil?
      @digest.digest_update(val) 
    end

    def digest_final

      raise DigestError, "Please call digest_init first before call final() (#{@digest.inspect})" if @digest.nil?

      @digestVal = @digest.digest_final
      @digest = nil

      write_to_output(@digestVal)

      #ts = Encoding::ASN1Encoder.instance(:digest)
      ts = BinStruct.instance.struct(:digest)
      ts.digest_algo = BTag.constant_value(@algo)
      if not_empty?(@salt)
        ts.salt = @salt
      else
        ts.salt = ""
      end

      if is_attach_mode?
        tsd = BinStruct.instance.struct(:digest_attached)
        #tsd = Encoding::ASN1Encoder.instance(:digest_attached)
        tsd.digest_config = ts.encoded
        tsd.digest_value = @digestVal
        res = tsd.encoded
      else
        res = ts.encoded
      end

      res

    end

    def self.to_digest_string(sym)
      if not_empty?(sym)
        sym.to_s.gsub("_","-")
      else
        sym
      end
    end

    #def self.from_digest_engine_to_symbol(str)
    #  if not_empty?(str)
    #    str.gsub("-","_").to_sym
    #  else
    #    str
    #  end
    #end

    #def self.init_native_digest_object(digest)
    #  OpenSSL::Digest.new(to_digest_string(digest)) 
    #end

    private
    def logger
      Digest.logger
    end

  end
end
