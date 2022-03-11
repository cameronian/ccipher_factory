
require_relative 'symkey_cipher'

require_relative '../compression/compression_helper'

module CcipherFactory

  module SymKeyCipher
    module SymKeyAttEncrypt
      include Common
      include Compression::CompressionHelper

      attr_accessor :key, :mode
      def att_encrypt_init(*args, &block) 

        raise SymKeyCipherError, "Cipher requires output to be set" if not is_output_given?

        @enc = SymKeyCipher.encryptor 
        @enc.compression_on if is_compression_on?
        @enc.output(intOutputFile)
        @enc.key = @key
        @enc.mode = @mode if not_empty?(@mode)

        @enc.encrypt_init(*args)

        if block
          instance_eval(&block)
          att_encrypt_final
        else
          self
        end

      end

      def att_encrypt_update(val)
        raise SymKeyCipherError, "Please call att_encrypt_init() before calling update()" if @enc.nil?

        @enc.encrypt_update(val) 
      end

      def att_encrypt_final

        meta = @enc.encrypt_final

        write_to_output(meta)
        intOutputFile.rewind
        while not intOutputFile.eof?
          write_to_output(intOutputFile.read)
        end

        intOutputFile.close!

        nil

      end

      def method_missing(mtd, *args, &block)
        if not_empty?(@enc)
          @enc.send(mtd, *args, &block) 
        end
      end

    end
  end
end
