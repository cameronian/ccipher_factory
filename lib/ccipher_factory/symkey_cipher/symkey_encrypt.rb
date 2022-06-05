
require_relative '../compression/compression_helper'

module CcipherFactory
  module SymKeyCipher
    module SymKeyEncrypt
      include TR::CondUtils
      include Common
      include Compression::CompressionHelper

      attr_accessor :key, :mode, :iv

      def encrypt_init(*args, &block)

        raise SymKeyCipherError, "Encryption key is required" if is_empty?(@key)
        raise SymKeyCipherError, "SymKey object is required" if not @key.is_a?(SymKey)
        raise SymKeyCipherError, "Cipher requires output to be set" if not is_output_given?

        #_, _, mode = SymKeyCipher.algo_default(@key.keytype)
        @cconf = SymKeyCipher.algo_default(@key.keytype)
        @cconf.key = @key.key
        @cconf.keysize = @key.keysize
        @cconf.iv = @iv if not_empty?(@iv)
        if is_empty?(@mode)
          @mode = @cconf.mode
        else
          @cconf.mode = @mode
        end

        #spec = SymKeyCipher.key_to_spec(@key, @mode)
        logger.tdebug :symkey_enc, "Encrypt cipher spec : #{@cconf}"

       
        @cconf.cipherOps = :encrypt
        begin
          @cipher = Ccrypto::AlgoFactory.engine(@cconf)
        #rescue Ccrypto::CipherEngineException => ex
        rescue Exception => ex
          raise SymKeyCipherError, ex
        end


        #@cipher = OpenSSL::Cipher.new(cconf.provider_config)
        #@cipher.encrypt
        #@cipher.key = @key.key

        #if is_empty?(@iv)
        #  @iv = @cipher.random_iv
        #else
        #  @cipher.iv = @iv
        #end

        if is_compression_on?
          logger.tdebug :symkey_enc, "Compression on"
        else
          logger.tdebug :symkey_enc, "Compression off"
        end

        @totalPlain = 0
        @totalCompressed = 0

        if block
          instance_eval(&block)
          encrypt_final
        else
          self
        end

      end

      def encrypt_update(val)

        if not_empty?(val)
          @totalPlain += val.length
          cval = compress_data_if_active(val)
          @totalCompressed += cval.length

          enc = @cipher.update(cval)
          if not_empty?(enc)
            write_to_output(enc)
          end
        end

      end

      def encrypt_final

        #if not is_gcm_mode?
          enc = @cipher.final
          logger.debug "Cipher final returns #{enc.length} bytes"
          write_to_output(enc)
        #end

        @cipher = nil
        # this is to clear up the cipher object from memory 
        # including key and IV value
        # Tested with aes-finder utility on ruby 3.0.2
        # https://github.com/mmozeiko/aes-finder
        GC.start  

        @iv = @cconf.iv if is_empty?(@iv)

        conv = Ccrypto::UtilFactory.instance(:data_converter)
        #logger.debug "Key : #{conv.to_hex(@key.key)}"
        #logger.debug "IV : #{conv.to_hex(@iv)}"
        #logger.debug "Mode : #{@mode}"
        #logger.debug "Output : #{conv.to_hex(@output.string)}"

        ts = Encoding::ASN1Encoder.instance(:symkey_cipher)
        if is_empty?(@mode)
          ts.set(:mode, 0)
          logger.debug "Encoding null mode"
        else
          ts.set(:mode, Tag.constant(@mode))
          logger.debug "Encoding mode #{@mode}"
        end

        if is_empty?(@iv)
          ts.set(:iv, "")
          logger.debug "Encoding empty IV"
        else
          ts.set(:iv, @iv)
          logger.debug "Encoding IV of #{@iv.length} bytes"
        end

        if is_compression_on?
          ts.set(:compression, compressor.compress_final)
          logger.tdebug :symkey_enc, "Plain : #{@totalPlain} / Compressed : #{@totalCompressed} = #{(@totalCompressed*1.0)/@totalPlain*100} %"
        else
          ts.set(:compression, Encoding::ASN1Encoder.instance(:compression_none).to_asn1)
        end

        if @cconf.respond_to?(:auth_tag)
          if is_empty?(@cconf.auth_tag)
            ts.set(:auth_tag, "")
            logger.debug "Encoding empty AuthTag"
          else
            ts.set(:auth_tag, @cconf.auth_tag)
            logger.debug "Encoding AuthTag of #{@cconf.auth_tag.length}"
          end
        else
          ts.set(:auth_tag, "")
          logger.debug "AuthTag not relevent"
        end

        ts.to_asn1

      end

      private
      #def is_gcm_mode?
      #  @mode == :gcm
      #end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :symkey_enc
        end
        @logger
      end

    end
  end
end
