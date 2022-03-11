
require_relative '../asymkey_cipher/asymkey_cipher'
require_relative '../symkey_cipher/symkey_cipher'

module CcipherFactory
  module CompositeCipher

    module DecryptVerifier
      include TR::CondUtils
      include Common
      include Encoding::ASN1Decoder
      include TloggerHelper

      attr_accessor :decryption_key, :verification_key
      def decrypt_verify_init(opts = {  }, &block)

        #@dKey = opts[:decryption_key]
        #@vKey = opts[:verification_key] # optional as asymkey the key is included

        raise CompositeCipherError, "Decryption key is required" if is_empty?(@decryption_key)
        raise CompositeCipherError, "Output is required" if not is_output_given?

        if block
          instance_eval(&block)
          decrypt_verify_final
        else
          self
        end

      end

      def decrypt_verify_update_meta(meta)

        intOutputBuf.write(meta)

        begin

          extract_meta(intOutputBuf) do |meta, bal|

            ts = Encoding::ASN1Decoder.from_asn1(meta)
            ccBin = ts.value(:cipher_config)
            cc = Encoding::ASN1Decoder.from_asn1(ccBin)
            scBin = ts.value(:signer_config)
            sc = Encoding::ASN1Decoder.from_asn1(scBin)

            case cc.id
            when :symkey_cipher
              @cipher = CcipherFactory::SymKeyCipher.decryptor
              @cipher.output(intOutputFile)
              @cipher.key = @decryption_key
              @cipher.decrypt_init
              @cipher.decrypt_update_meta(ccBin)
            when :ecc_cipher
              @cipher = CcipherFactory::AsymKeyCipher.decryptor
              @cipher.output(intOutputFile)
              @cipher.decryption_key = @decryption_key
              @cipher.decrypt_init
              @cipher.decrypt_update_meta(ccBin)
            else
              raise CompositeCipherError, "Unknown envelope type '#{cc.id}'"
            end

            case sc.id
            when :ecc_att_sign
              @verifier = AsymKeySigner.att_verifier
              @verifier.output(@output)
            when :symkey_att_sign
              @verifier = SymKeySigner.att_verifier
              @verifier.output(@output)
              @verifier.verification_key = @verification_key
              @verifier.att_verify_init
            else
              raise CompositeCipherError, "Unknown signer type '#{sc.id}'"
            end

            decrypt_verify_update_cipher(bal) if bal.length > 0

            disposeOutput(intOutputBuf)

          end

        rescue InsufficientData
        end



      end

      def decrypt_verify_update_cipher(cipher)
        raise CompositeCipherError, "Please call update_meta() before calling update_cipher()" if is_empty?(@cipher) 

        @cipher.decrypt_update_cipher(cipher)
      end

      def decrypt_verify_final

        @cipher.decrypt_final

        intOutputFile.rewind
        while not intOutputFile.eof?
          @verifier.att_verify_update(intOutputFile.read)
        end

        @verifier.att_verify_final

      end

      def embedded_signer
        @verifier.embedded_signer if not_empty?(@verifier) and @verifier.respond_to?(:embedded_signer)
      end

    end

  end
end
