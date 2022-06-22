
require_relative 'compressor'

module CcipherFactory
  module Compression

    module CompressionHelper

      def decompressor_from_asn1(bin)

        ts = BinStruct.instance.struct_from_bin(bin)
        case BTag.value_constant(ts.oid)
        when :compression_zlib
          compression_on
        when :compression_none
          compression_off
        else
          compression_off
        end

        decompressor.decompress_update_meta(bin)

      end

      def compression_on
        @compress = true
      end

      def compression_off
        @compress = false
      end

      def is_compression_on?
        if @compress.nil?
          false
        else
          @compress
        end
      end

      def compressor
        if @compressor.nil? 
          if is_compression_on?
            @compressor = Compressor.instance.compress 
            @compressor.compress_init
          else
            @compressor = Compressor.instance.null_engine
          end
        end

        @compressor
      end

      def compress_data_if_active(val)
        if is_compression_on?
          logger.tdebug :compress_if_active, "Compression is on"
          compressor.compress_update(val)
        else
          logger.tdebug :compress_if_active, "Compression is OFF"
          val
        end
      end

      def decompress_data_if_active(val)
        if is_compression_on?
          logger.tdebug :decompress_if_active, "Decompression is on"
          decompressor.decompress_update(val)
        else
          logger.tdebug :decompress_if_active, "decompression is OFF"
          val
        end
      end

      def decompressor
        if @decompressor.nil?
          if is_compression_on?
            @decompressor = Compressor.instance.decompress
            @decompressor.decompress_init
          else
            @decompressor = Compressor.instance.null_engine
          end
        end

        @decompressor
      end

      def encode_null_compressor
        BinStruct.instance.struct(:compression_none).encoded
        #Encoding::ASN1Encoder.instance(:compression_none).to_asn1
      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :comp_helper
        end
        @logger
      end

    end


  end
end
