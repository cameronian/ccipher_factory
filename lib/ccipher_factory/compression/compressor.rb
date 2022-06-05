
require_relative 'zlib_compressor'
require_relative 'zlib_decompressor'

module CcipherFactory
  class CompressionError < StandardError; end
  class DecompressionError < StandardError; end
end

module CcipherFactory
  module Compression
    #class CompressionError < StandardError; end
    #class DecompressionError < StandardError; end

    module NullCompressor
      def method_missing(mtd, *args, &block)
        # sink hole
        #args
      end
    end

    class Compressor

      def self.instance(eng = :zlib)
        Compressor.new
      end

      def compress
        self.extend(ZlibCompressor)
        self
      end

      def decompress
        self.extend(ZlibDecompressor)
        self
      end

      def null_engine
        self.extend(NullCompressor)
        self
      end

      def self.supported_envelope
        [:compression_none, :compression_zlib]
      end

      def self.rebuild(ts, &block)
        Compressor.new
      end

    end
  end
end


