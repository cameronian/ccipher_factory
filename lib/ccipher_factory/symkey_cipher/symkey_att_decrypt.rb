

module CcipherFactory
  module SymKeyCipher
    module SymKeyAttDecrypt
      include Common

      attr_accessor :key
      def att_decrypt_init(*args, &block)

        raise SymKeyCipherError, "Output is required for attached decryption" if not is_output_given?

        @initParams = args

        if block
          instance_eval(&block)
          att_decrypt_final
        else
          self
        end

      end

      def att_decrypt_update(val)
        if @dec.nil?
          intOutputBuf.write(val)
          begin
            Encoding.extract_meta(intOutputBuf) do |meta, bal|

              @dec = SymKeyCipher.decryptor
              @dec.output(@output)
              @dec.key = @key
              @dec.decrypt_init(*@initParams)
              @dec.decrypt_update_meta(meta)

              logger.tdebug :att_dec, "Balance has data length #{bal.length}"
              att_decrypt_update(bal) if bal.length > 0

              disposeOutput(intOutputBuf)

            end
          rescue Encoding::InsufficientData => e
          end
        else
          logger.tdebug :att_dec, "Updating cipher size #{val.length}"
          @dec.decrypt_update_cipher(val)
        end
      end

      def att_decrypt_final
        @dec.decrypt_final
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
        end
        @logger
      end

    end
  end
end
