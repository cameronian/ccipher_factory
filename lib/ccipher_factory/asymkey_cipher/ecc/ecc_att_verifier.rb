


module CcipherFactory
  module AsymKeySigner

    module ECCAttVerifier
      include Common
      include Compression::CompressionHelper

      def embedded_signer
        if not_empty?(@ver)
          @ver.embedded_signer
        else
          nil
        end
      end

      def att_verify_init(*args, &block)

        @params = args

        if block
          instance_eval(&block)
          att_verify_final
        else
          self
        end

      end

      def att_verify_update(val)

        if @ver.nil?

          intOutputBuf.write(val)
          begin
            Encoding.extract_meta(intOutputBuf) do |meta, bal|

              ts = BinStruct.instance.struct_from_bin(meta)
              smeta = ts.ecc_signature
              compression = ts.compression

              decompressor_from_asn1(compression)
              if is_compression_on?
                logger.tdebug :ecc_att_ver, "Compression on"
              else
                logger.tdebug :ecc_att_ver, "No compression"
              end

              @ver = AsymKeySigner.verifier
              @ver.output(@output) if is_output_given?

              @ver.verify_init(*@params)
              @ver.verify_update_meta(smeta)

              att_verify_update(bal) if bal.length > 0

              disposeOutput(intOutputBuf)

            end
          rescue Encoding::InsufficientData
          end

        else
          logger.tdebug :ecc_att_ver, "Compressed size : #{val.length}" if is_compression_on?
          res = decompress_data_if_active(val) 
          @ver.verify_update_data(res)
          intOutputFile.write(res)
        end

      end

      def att_verify_final

        res = @ver.verify_final

        if is_output_given?
          intOutputFile.rewind
          while not intOutputFile.eof?
            write_to_output(intOutputFile.read)
          end
        end

        disposeOutput(intOutputFile)
        res

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
