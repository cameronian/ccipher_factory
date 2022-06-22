
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
        bs = BinStruct.instance.struct(:ecc_signer_info)
        bs.signer_info_value = @keypair.public_key.to_bin
        bs.encoded
      end

      def self.from_signer_info(bin)

        bs = BinStruct.instance.struct(:ecc_signer_info)
        ts = bs.from_bin(bin)
        siType = ts.signer_info_type
        val = ts.signer_info_value
        case BTag.value_constant(siType)
        when :public_key
          Ccrypto::AlgoFactory.engine(Ccrypto::ECCPublicKey).to_key(val)
        else
          raise AsymKeyError, "Unknown signer info type #{BTag.value_constant(siType)}"
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
