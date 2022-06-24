
require 'zlib'

module CcipherFactory
  module Compression
    module ZlibCompressor
      include CcipherFactory::Common

      def compress_init(*args, &block)

        @compressor = Ccrypto::UtilFactory.instance(:compression, Ccrypto::CompressionConfig.new)
        #@compressor = Zlib::Deflate.new

        if block
          instance_eval(&block)
          compress_final
        else
          self
        end

      end

      def compress_update(val)
        res = @compressor.update(val)
        #res = @compressor.deflate(val, Zlib::SYNC_FLUSH)
        write_to_output(res)
        res
      end

      def compress_final
        @compressor.final

        ts = BinStruct.instance.struct(:compression_zlib)
        ts.encoded
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :zlibComp
        end
        @logger
      end

    end
  end
end
