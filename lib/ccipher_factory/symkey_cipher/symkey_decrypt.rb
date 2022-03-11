
require_relative '../compression/compressor'

module CcipherFactory
  module SymKeyCipher
    module SymKeyDecrypt
      include TR::CondUtils
      include Common
      include Encoding::ASN1Decoder

      #class SymKeyDecryptError < StandardError; end

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
          extract_meta(intOutputBuf) do |meta, bal|

            ts = Encoding::ASN1Decoder.from_asn1(meta)
            @mode = Tag.constant_key(ts.value(:mode))
            logger.debug "Decoded mode : #{@mode}"
            iv = ts.value(:iv)
            comp = ts.value(:compression)

            cts = Encoding::ASN1Decoder.from_asn1(comp)
            if cts.id == :compression_zlib
              @decompressor = CcipherFactory::Compression::Compressor.new
              @decompressor.decompress
              @decompressor.decompress_init
              @decompressor.decompress_update_meta(comp)
              logger.tdebug :symkey_dec, "Compression is active"
            else
              logger.tdebug :symkey_dec, "Compression is NOT active"
            end

            aad = ts.value(:aad)

            algoDef = SymKeyCipher.algo_default(@key.keytype)

            cconf = Ccrypto::DirectCipherConfig.new({ algo: @key.keytype, keysize: @key.keysize, mode: @mode, padding: :pkcs5 })
            cconf.cipherOps = :decrypt
            cconf.key = @key.key
            cconf.iv = iv if not_empty?(iv)
            cconf.auth_tag = aad if cconf.respond_to?(:auth_tag=)
            @cipher = Ccrypto::AlgoFactory.engine(cconf)

            logger.debug "Decrypt config : #{cconf}"

            #spec = SymKeyCipher.key_to_spec(@key, @mode)
            #logger.tdebug :symkey_dec, "Decrypt cipher spec : #{spec}"
            #@cipher = OpenSSL::Cipher.new(spec)
            #@cipher.decrypt
            #@cipher.key = @key.key
            #@cipher.iv = iv if not_empty?(iv)

            #decrypt_update_cipher(bal) if bal.length > 0

            @cipher

          end
        rescue InsufficientData => e
        end


      end

      def decrypt_update_cipher(val)

        raise SymKeyCipherError, "Please call update_meta() first before update_cipher()" if @cipher.nil?

        dec = @cipher.update(val)

        if @decompressor.nil?
          dc = dec
        else
          begin
            dc = @decompressor.decompress_update(dec)
          rescue Zlib::Error => ex
            raise SymKeyDecryptionError, "Data decompression failed: #{ex.message}"
          end
        end

        write_to_output(dc)

      end

      def decrypt_final

        begin
          dec = @cipher.final 
          write_to_output(dec)
        rescue Ccrypto::CipherEngineException => ex
          raise SymKeyDecryptionError, ex
        end

        @cipher = nil
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
