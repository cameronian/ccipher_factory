
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

    def self.from_asn1(bin, &block)
      ts = Encoding::ASN1Decoder.from_asn1(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)

      if ts.id == :digest_attached
        dig = from_asn1(ts.value(:digest_config))
        dig.digestVal = ts.value(:digest_value)
        dig
      else

        algo = Tag.constant_key(ts.value(:digest_algo))
        logger.debug "from_asn1 algo : #{algo}"
        dig = instance
        dig.salt = ts.value(:salt)
        dig.digest_init(algo, &block)
      end
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

      @algo = args.first
      @algo = SupportedDigest.instance.default_digest if is_empty?(@algo)
      raise DigestError, "Given digest '#{@algo}' is not supported.\nPossible digest algo including: #{SupportedDigest.instance.supported.join(", ")}" if not SupportedDigest.instance.is_supported?(@algo)

      logger.debug "Digest algo in init : #{@algo}"

      @digest = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig).digest(@algo)

      #@digest = OpenSSL::Digest.new(Digest.to_digest_string(@algo))

      salt = args[1]
      if not_empty?(salt)
        case salt
        when :random_salt, :random
          saltLen = args[2] || 16
          sre = Ccrypto::AlgoFactorye.engine(Ccrypto::SecureRandomEngine)
          @salt = sre.random_bytes(16)
          @digest.update(@salt)
        else
          if salt.is_a?(String)
            @salt = salt
            @digest.update(@salt)
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
      raise DigestError, "Please call digest_init first before call update()" if @digest.nil?
      @digest.digest_update(val) 
    end

    def digest_final

      raise DigestError, "Please call digest_init first before call final()" if @digest.nil?

      @digestVal = @digest.digest_final
      @digest = nil

      write_to_output(@digestVal)

      ts = Encoding::ASN1Encoder.instance(:digest)
      ts.set(:digest_algo, Tag.constant(@algo))
      if not_empty?(@salt)
        ts.set(:salt, @salt)
      else
        ts.set(:salt, "")
      end

      if is_attach_mode?
        tsd = Encoding::ASN1Encoder.instance(:digest_attached)
        tsd.set(:digest_config, ts.to_asn1)
        tsd.set(:digest_value, @digestVal)
        res = tsd.to_asn1
      else
        res = ts.to_asn1
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
