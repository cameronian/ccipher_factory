
require_relative '../symkey_cipher/symkey_cipher'
require_relative '../symkey_cipher/symkey_encrypt'

module CcipherFactory
  class KCV
    include TR::CondUtils
    include SymKeyCipher::SymKeyEncrypt

    class KCVError < StandardError; end

    attr_accessor :nonce, :check_value

    def self.from_asn1(bin) 

      ts = Encoding::ASN1Decoder.from_asn1(bin)
      kcv = KCV.new
      kcv.mode = Tag.constant_key(ts.value(:mode))
      kcv.iv = ts.value(:iv)
      kcv.nonce = ts.value(:nonce)
      kcv.check_value = ts.value(:check_value)

      kcv

    end

    def self.converter
      if @conv.nil?
        @conv = Ccrypto::UtilFactory.instance(:data_converter)
      end
      @conv
    end

    def is_matched?
      logger.tdebug :kcv_match, "Check if KCV matched"
      to_asn1
      res = intOutputBuf.string
      @check_value == res
    end

    def to_asn1

      raise KCVError, "Key must be given" if is_empty?(@key)

      logger.debug "Generating KCV"
      compression_off
      output(intOutputBuf)

      encrypt_init(@key)

      if is_empty?(@nonce)
        logger.debug "Random nounce"
        @nonce = SecureRandom.random_bytes(@key.keysize)
      else
        logger.debug "Nounce is given"
      end

      encrypt_update(@nonce)
      encrypt_final

      ts = Encoding::ASN1Encoder.instance(:kcv)
      ts.set(:mode, Tag.constant(@mode))
      ts.set(:iv, @iv)
      ts.set(:nonce, @nonce)
      ts.set(:check_value, intOutputBuf.string)

      #logger.debug "Key : #{self.class.converter.to_hex(@key.key)}"
      #logger.debug "mode #{@mode}"
      #logger.debug "IV #{self.class.converter.to_hex(@iv)}"
      #logger.debug "nounce #{self.class.converter.to_hex(@nonce)}"
      #logger.debug "check_value #{self.class.converter.to_hex(intOutputBuf.string)}"

      ts.to_asn1

    end

    def self.logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :kcv
      end
      @logger
    end
    def logger
      self.class.logger
    end

  end
end
