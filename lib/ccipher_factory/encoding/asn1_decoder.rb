


module CcipherFactory
  module Encoding
    module ASN1Decoder

      def self.from_asn1(bin)
        tspec = SpecDslBuilder.from_bin(bin) do |*args|
          ops = args.first
          case ops
          when :decode
            val = args[1]
            #OpenSSL::ASN1.decode(val).value
            Ccrypto::ASN1.engine.to_value(val)
          when :value
            val = args[1]
            Ccrypto::ASN1.engine.to_value(val)
            #v = OpenSSL::ASN1.decode(val).value
            #v = Ccrypto::ASN1.engine.to_value(val)
            # downgrade automatically since not really
            # encoding bignum value at this juncture
            #if val.is_type?(:int)
            #  logger.odebug :from_asn1, "Converting to Integer implicitly"
            #  Ccrypto::ASN1.engine.to_value(val).to_i
            #  #v.to_i
            #else
            #  Ccrypto::ASN1.engine.to_value(val)
            #  #v
            #end
          end
        end
        tspec
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :asn1_decoder
        end
        @logger
      end


      class InsufficientData < StandardError; end

      def extract_meta(buf, &block)

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

      #def find_asn1_length(buf)
      #  totalLen = 0
      #  begin
      #    OpenSSL::ASN1.traverse(buf) do |depth,offset,headerLen,length,constructed,tagClass,tag|
      #      totalLen = headerLen+length
      #      break
      #    end
      #  rescue StandardError => ex
      #    #p ex
      #  end
      #  totalLen
      #end

      private
      def logger
        self.class.logger
      end

    end
  end
end
