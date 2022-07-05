
require_relative '../compression/compressor'

module CcipherFactory
  module SymKeyCipher
    module SymKeyDecrypt
      include TR::CondUtils
      include Common
      include Compression::CompressionHelper

      class SymKeyDecryptError < StandardError; end

      attr_accessor :key

      def init

      end

      def decrypt_init(*args, &block)

        #@decKey = args.first
        raise SymKeyDecryptError, "Decryption key is required" if is_empty?(@key)

        if block
          instance_eval(&block)
          decrypt_final
        else
          self
        end

      end

      def decrypt_update_meta(val)

        intOutputBuf.write(val)
        begin
          Encoding.extract_meta(intOutputBuf) do |meta, bal|

            ts = BinStruct.instance.struct_from_bin(meta)
            @mode = BTag.value_constant(ts.mode)
            iv = ts.iv
            comp = ts.compression

            cts = BinStruct.instance.struct_from_bin(comp)
            if cts.oid == BTag.constant_value(:compression_zlib)
              @decompressor = CcipherFactory::Compression::Compressor.new
              @decompressor.decompress
              @decompressor.decompress_init
              @decompressor.decompress_update_meta(comp)

              compression_on
              logger.tdebug :symkey_dec, "Compression is active"
            else
              compression_off
              logger.tdebug :symkey_dec, "Compression is NOT active"
            end

            authTag = ts.auth_tag

            algoDef = SymKeyCipher.algo_default(@key.keytype)

            cconf = Ccrypto::DirectCipherConfig.new({ algo: @key.keytype, keysize: @key.keysize, mode: @mode, padding: :pkcs5 })
            cconf.cipherOps = :decrypt
            cconf.key = @key.key
            cconf.iv = iv if not_empty?(iv)
            cconf.auth_tag = authTag if cconf.respond_to?(:auth_tag=)
            @cipher = Ccrypto::AlgoFactory.engine(cconf)

            @cipher

          end
        rescue Encoding::InsufficientData => e
        end


      end

      def decrypt_update_cipher(val)

        raise SymKeyCipherError, "Please call update_meta() first before update_cipher()" if @cipher.nil?
        
        logger.debug "Given cipher data : #{val.length}"

        dec = @cipher.update(val)


        if not_empty?(dec) and dec.length > 0

          logger.debug "After cipher before compression check : #{dec.length}"
          res = decompress_data_if_active(dec)
          write_to_output(res)

          #if @decompressor.nil?
          #  dc = dec
          #else
          #  begin
          #    dc = @decompressor.decompress_update(dec)
          #  rescue Zlib::Error => ex
          #    raise SymKeyDecryptionError, "Data decompression failed: #{ex.message}"
          #  end
          #end

          #write_to_output(dc)

        else

          logger.debug "Cipher update returns nothing"
        end

      end

      def decrypt_final

        begin
          dec = @cipher.final 
          logger.debug "Final length : #{dec.length}"
          res = decompress_data_if_active(dec)
          write_to_output(res)
        rescue Ccrypto::CipherEngineException => ex
          raise SymKeyDecryptionError, ex
        end

        @cipher = nil

        @key = nil
        # this is to clear up the cipher object from memory 
        # including key and IV value
        # Tested with aes-finder utility on ruby 3.0.2
        # https://github.com/mmozeiko/aes-finder
        GC.start

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :symkey_dec
        end
        @logger
      end

    end
  end
end
