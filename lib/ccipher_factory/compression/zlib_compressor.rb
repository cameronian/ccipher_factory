
require 'zlib'

module CcipherFactory
  module Compression
    module ZlibCompressor
      include CcipherFactory::Common

      def compress_init(*args, &block)

        @compressor = Zlib::Deflate.new

        if block
          instance_eval(&block)
          compress_final
        else
          self
        end

      end

      def compress_update(val)
        res = @compressor.deflate(val, Zlib::SYNC_FLUSH)
        write_to_output(res)
        res
      end

      def compress_final
        @compressor.finish
        @compressor.close

        ts = Encoding::ASN1Encoder.instance(:compression_zlib)
        ts.to_asn1
      end

    end
  end
end
