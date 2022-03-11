
require_relative 'spec_dsl'
require 'openssl'

module CcipherFactory
  module Encoding
    module ASN1Encoder

      def self.instance(tspec)
        ts = CcipherFactory::SpecDslBuilder.instance(tspec)
        ts.extend(ASN1Encoder)
        ts
      end

      def encode_asn1(type, val)

        Ccrypto::ASN1.engine.build(type, val)

        #case type
        #when :oid
        #  OpenSSL::ASN1::ObjectId.new(val)
        #when :seq
        #  OpenSSL::ASN1::Sequence.new(val)
        #when :str
        #  OpenSSL::ASN1::UTF8String.new(val)
        #when :octet_str
        #  OpenSSL::ASN1::OctetString.new(val)
        #when :int
        #  OpenSSL::ASN1::Integer.new(val)
        #when :bin
        #  OpenSSL::ASN1::BitString.new(val)
        #when :date, :time, :generalize_time
        #  OpenSSL::ASN1::GeneralizedTime.new(val)
        #else
        #  raise EncoderError, "Unknown type '#{type}' for encoding"
        #end
      end

      def to_asn1
        to_bin do |*args|
          ops = args.first
          case ops
          when :encode
            encode_asn1(args[1], args[2])
          when :to_bin
            args[1].to_bin
          end
        end
      end

    end
  end

end



