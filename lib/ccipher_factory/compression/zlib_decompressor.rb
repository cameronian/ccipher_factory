
require 'zlib'

module CcipherFactory 
  module Compression
    module ZlibDecompressor
      include CcipherFactory::Common
      include Encoding::ASN1Decoder 

      def decompress_init(*args, &block)

        if block
          instance_eval(&block)
          decompress_final
        else
          self
        end

      end

      def decompress_update_meta(val)
        if @decompressor.nil?
          begin
            intOutputBuf.write(val)
            extract_meta(intOutputBuf) do |meta, bal|
              ts = Encoding::ASN1Decoder.from_asn1(meta)
              case ts.id
              when :compression_zlib
                @decompressor = Zlib::Inflate.new
              else
                raise DecompressionError, "Unknown compression type '#{ts.id}'"
              end

              decompress_update(bal)
            end
          rescue InsufficientData => e
          end
        else
          decompress_update(val)
        end
      end

      def decompress_update(val)
        check_state
        res = @decompressor.inflate(val)
        write_to_output(res)
        res
      end

      def decompress_final
        check_state 
        @decompressor.close
      end

      private
      def check_state
        raise DecompressionError, "Please call decompress_update_meta() to setup the state first." if @decompressor.nil?
      end

    end
  end
end
