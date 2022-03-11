

module CcipherFactory
  module AsymKeyCipher
    module ECCAttDecrypt
      include Common
      include Encoding::ASN1Decoder 

      attr_accessor :decryption_key 
      def att_decrypt_init(opts = { }, &block)

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
            extract_meta(intOutputBuf) do |meta, bal|

              @dec = AsymKeyCipher.decryptor(:ecc)
              @dec.output(@output)
              @dec.decryption_key = @decryption_key
              @dec.decrypt_init
              @dec.decrypt_update_meta(meta)

              att_decrypt_update(bal) if bal.length > 0

              intOutputBuf.rewind
              intOutputBuf = nil

            end
          rescue InsufficientData => e
          end

        else
          @dec.decrypt_update_cipher(val)
        end
      end

      def att_decrypt_final
        @dec.decrypt_final 
      end

    end
  end
end


