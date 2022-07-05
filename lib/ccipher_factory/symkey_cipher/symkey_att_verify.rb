
require_relative 'symkey_signer'

module CcipherFactory
  module SymKeySigner

    module SymKeyAttVerify
      include Common
      include Compression::CompressionHelper

      attr_accessor :verification_key
      def att_verify_init(opts = {  }, &block)

        @params = opts

        raise SymKeySignerError, "Please provide output for attached verify" if not is_output_given?

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

              vmeta = ts.symkey_signature
              compression = ts.compression

              cts = BinStruct.instance.struct_from_bin(compression)
              if cts.oid == BTag.constant_value(:compression_zlib)
                compression_on
                decompressor.decompress_update_meta(compression)
              end

              @ver = SymKeySigner.verifier

              @ver.verification_key = @verification_key
              @ver.verify_init(@params)
              @ver.verify_update_meta(vmeta)

              att_verify_update(bal) if bal.length > 0

              intOutputBuf.rewind
              intOutputBuf = nil
            end
          rescue Encoding::InsufficientData
          end
        else
          res = decompress_data_if_active(val)
          @ver.verify_update_data(res)
          intOutputFile.write(res)
        end

      end

      def att_verify_final
        res = @ver.verify_final 

        if res
          intOutputFile.rewind
          while not intOutputFile.eof?
            write_to_output(intOutputFile.read)
          end

          disposeOutput(intOutputFile)
        end

        res

      end

    end

  end
end
