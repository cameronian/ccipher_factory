



module CcipherFactory
  module AsymKeySigner

    module ECCAttSigner
      include Common
      include Compression::CompressionHelper

      attr_accessor :signing_key
      def att_sign_init(*args, &block)

        @signer = AsymKeySigner.signer
        @signer.signing_key = @signing_key

        @signer.sign_init(*args)

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

        raise ECCSignerError, "Output is required for attached sign with ECC" if not is_output_given?

        @totalPlain += val.length
        @signer.sign_update(val) 
        res = compress_data_if_active(val)
        intOutputFile.write(res)
        @totalCompressed += res.length

        res

      end

      def att_sign_final
        meta = @signer.sign_final 

        #ts = Encoding::ASN1Encoder.instance(:ecc_att_sign)
        ts = BinStruct.instance.struct(:ecc_att_sign)
        ts.ecc_signature = meta

        #ts.set(:ecc_signature, meta)
        if is_compression_on?
          #ts.set(:compression, compressor.compress_final)
          ts.compression = compressor.compress_final
        else
          #ts.set(:compression, encode_null_compressor)
          ts.compression = encode_null_compressor
        end

        #smeta = ts.to_asn1
        smeta = ts.encoded
        write_to_output(smeta)

        intOutputFile.rewind
        while not intOutputFile.eof?
          write_to_output(intOutputFile.read)
        end

        disposeOutput(intOutputFile)

        logger.tdebug :ecc_att_sign, "Total Plain : #{@totalPlain} / Total Compressed : #{@totalCompressed} = #{(@totalCompressed*1.0)/@totalPlain*100} %" if is_compression_on?

        smeta

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
