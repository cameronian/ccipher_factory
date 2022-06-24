
require_relative '../symkey_cipher/symkey_cipher'
require_relative '../symkey_cipher/symkey_encrypt'

module CcipherFactory
  class KCV
    include TR::CondUtils
    include SymKeyCipher::SymKeyEncrypt

    class KCVError < StandardError; end

    attr_accessor :nonce, :check_value

    def self.from_asn1(bin) 

      ts = BinStruct.instance.struct_from_bin(bin)
      kcv = KCV.new
      kcv.mode = BTag.constant_value(ts.mode)
      kcv.iv = ts.iv
      kcv.nonce = ts.nonce
      kcv.check_value = ts.check_value

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
      encoded
      res = intOutputBuf.bytes
      comp = Ccrypto::UtilFactory.instance(:comparator)
      comp.is_equal?(@check_value, res)
      #@check_value == res
    end

    def encoded

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

      ts = BinStruct.instance.struct(:kcv)
      ts.mode = BTag.constant_value(@mode)
      ts.iv = @iv
      ts.nonce = @nonce
      ts.check_value = intOutputBuf.bytes
      
      ts.encoded

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
