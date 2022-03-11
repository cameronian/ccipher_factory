
require_relative 'symkey_signer'

require_relative '../compression/compression_helper'

module CcipherFactory
  module SymKeySigner

    module SymKeyAttSign

      include Common
      include Compression::CompressionHelper

      attr_accessor :signing_key

      def att_sign_init(opts = { }, &block)

        @signer = SymKeySigner.signer
        @signer.signing_key = @signing_key
        @signer.sign_init(opts)

        @totalPlain = 0
        @totalCompressed = 0

        if block
          instance_eval(&block)
          att_sign_final
        else
          self
        end

      end

      def att_sign_update(val)
        raise SymKeySignerError, "Output is required for attached sign" if not is_output_given?

        @totalPlain += val.length
        @signer.sign_update(val)
        res = compress_data_if_active(val)
        intOutputFile.write(res)
        @totalCompressed += res.length
      end

      def att_sign_final

        meta = @signer.sign_final

        ts = Encoding::ASN1Encoder.instance(:symkey_att_sign)
        ts.set(:symkey_signature, meta)

        if is_compression_on?
          compRes = compressor.compress_final
          ts.set(:compression, compRes)
        else
          ts.set(:compression, encode_null_compressor)
        end

        attMeta = ts.to_asn1

        write_to_output(attMeta)
        intOutputFile.rewind
        while not intOutputFile.eof?
          write_to_output(intOutputFile.read)
        end

        logger.tdebug :symkey_att_sign, "Total Plain : #{@totalPlain} / Total Compressed : #{@totalCompressed} = #{(@totalCompressed*1.0)/@totalPlain*100} %" if is_compression_on?

        intOutputFile.close!

        attMeta

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
