

module CcipherFactory 
  module Encoding
    class EncoderError < StandardError; end

    class InsufficientData < StandardError; end

    def self.extract_meta(buf, &block)

      cpos = buf.pos

      begin

        #len = find_asn1_length(buf.string)
        len = Ccrypto::ASN1.engine.asn1_length(buf.bytes)
        #logger.debug "Found meta length : #{len}" if not logger.nil?
        raise InsufficientData if len == 0

        buf.rewind
        meta = buf.read(len)

        if block
          block.call(meta, buf.read(cpos-len))
        else
          meta
        end

        #rescue OpenSSL::ASN1::ASN1Error => ex
      rescue Ccrypto::ASN1EngineException => ex
        logger.error ex
        buf.seek(cpos)
        raise InsufficientData
      end

    end

  end
end

#require_relative 'asn1_encoder'
#require_relative 'asn1_decoder'

