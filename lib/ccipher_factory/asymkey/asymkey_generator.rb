

require 'openssl'
require_relative 'ecc_keypair'

module CcipherFactory
    module AsymKeyGenerator
      include TR::CondUtils
     
      class AsymKeyGeneratorError < StandardError; end

      def self.supported_asymkey
        {
          #ecc: Ccrypto::KeypairGenerator.instance(:ecc).curves
          ecc: Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig).supported_curves
        }
      end

      def self.set_default(keytype, opts = { }, &block)
        
        defVal = algo_default(keytype)
        defVal.merge!(opts)
        defVal

      end

      def self.algo_default(keytype)
        case keytype
        when :ecc
          @algoDef = { } if is_empty?(@algoDef)
          @algoDef[:ecc] = { } if is_empty?(@algoDef[:ecc])
          # default is NIST P-256
          @algoDef[:ecc][:curve] = 'prime256v1' if is_empty?(@algoDef[:ecc][:curve])

          @algoDef[:ecc]
        else
          raise AsymKeyGeneratorError, "Unknown default for '#{keytype}'"
        end

      end

      def self.generate(keytype, opts = { }, &block)
       
        raise AsymKeyGeneratorError, "Given key type '#{keytype}' is not supported. Supported key type are: #{supported_asymkey.keys.join(",")}" if not supported_asymkey.keys.include?(keytype)

        case keytype
        when :ecc
          
          curve = opts[:curve]
          curve = algo_default(:ecc)[:curve] if is_empty?(curve)

          #raise AsymKeyGeneratorError, "Curve '#{curve}' is not supported. Supported curves are #{supported_asymkey[:ecc].join(", ")}" if not supported_asymkey[:ecc].include?(curve)

          case curve
          when Ccrypto::ECCConfig
            key = Ccrypto::AlgoFactory.engine(curve).generate_keypair
            ecKey = KeyPair::ECCKeyPair.new(key)
            ecKey.curve = curve.curve
          when String
            key = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new(curve)).generate_keypair
            ecKey = KeyPair::ECCKeyPair.new(key)
            ecKey.curve = curve
          else
            raise AsymKeyGeneratorError, "Unknown curve value type #{curve.class}"
          end

          logger.debug "Generated key : #{ecKey.inspect}"
          ecKey

        else
          raise AsymKeyGeneratorError, "Unknown asymmetric key type '#{keytype}'"
        end

      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :asym_keygen
        end
        @logger
      end

    end
end
