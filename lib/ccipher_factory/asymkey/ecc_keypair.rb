
require_relative 'asymkey'

module CcipherFactory
  module KeyPair
    class ECCKeyPair
      include AsymKey
      include TR::CondUtils

      attr_writer :curve

      def curve
        if is_empty?(@curve) and not_empty?(@key)
          @curve = @key.group.curve_name
        end
        @curve
      end

      def to_signer_info
        ts = Encoding::ASN1Encoder.instance(:ecc_signer_info)
        ts.set(:signer_info_type, Tag.constant(:public_key))
        ts.set(:signer_info_value, @keypair.public_key.to_bin)
        ts.to_asn1
      end

      def self.from_signer_info(bin)
        ts = Encoding::ASN1Decoder.from_asn1(bin)
        siType = ts.value(:signer_info_type)
        val = ts.value(:signer_info_value)
        case Tag.constant_key(siType)
        when :public_key
          Ccrypto::AlgoFactory.engine(Ccrypto::ECCPublicKey).to_key(val)
          #OpenSSL::PKey::EC.new(val)
        else
          raise AsymKeyError, "Unknown signer info type #{Tag.constant_key(siType)}"
        end
      end


      def method_missing(mtd, *args, &block)
        logger.debug "sending method #{mtd} to #{@keypair}"
        @keypair.send(mtd, *args, &block)
      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :cf_ecc_keypair
        end
        @logger
      end

    end
  end
end
