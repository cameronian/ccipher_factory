

module CcipherFactory
  module AsymKeyCipher
    module ECCAttEncrypt
      include Common
      include TR::CondUtils
      include Compression::CompressionHelper

      attr_accessor :recipient_key, :sender_keypair

      def att_encrypt_init(opts = { }, &block)

        @enc = AsymKeyCipher.encryptor(:ecc)
        @enc.output(intOutputFile)

        if is_compression_on?
          logger.tdebug :ecc_att_enc, "Compression on"
          @enc.compression_on
        else
          logger.tdebug :ecc_att_enc, "Compression off"
          @enc.compression_off
        end

        @enc.recipient_key = @recipient_key
        @enc.sender_keypair = @sender_keypair

        @enc.encrypt_init(opts)

        if block
          instance_eval(&block)
          att_encrypt_final
        else
          self
        end

      end

      def att_encrypt_update(val)
        raise ECCCipherError, "Output is required for encryption" if not is_output_given?
        @enc.encrypt_update(val) 
      end

      def att_encrypt_final

        ts = @enc.encrypt_final

        write_to_output(ts)

        intOutputFile.rewind
        while not intOutputFile.eof?
          write_to_output(intOutputFile.read)
        end

        intOutputFile.close!

        @output

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
        end
        @logger
      end

    end
  end
end
