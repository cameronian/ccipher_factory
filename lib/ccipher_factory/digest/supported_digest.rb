
require 'singleton'

module CcipherFactory
  module Digest

    class SupportedDigest
      include Singleton
      attr_reader :supported, :possible, :default_digest
      def initialize
        #@possible = [:sha1, :sha224, :sha256, :sha384, :sha512, :sha3_224, :sha3_256, :sha3_384, :sha3_512, :shake128, :shake256]
        #@supported = []
        #test_algo

        @dig = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig)

        @possible = @dig.engineKeys.keys
        @supported = @possible

        if @dig.is_supported?(:sha3_256)
          @default_digest = :sha3_256
        elsif @dig.is_supported?(:sha256)
          @default_digest = :sha256
        else
          raise DigestError, "Failed to set default digest" 
        end
      end

      def is_supported?(algo)
        #@supported.include?(algo)
        @dig.is_supported?(algo)
      end

      #def test_algo
      #  @possible.each do |dig|
      #    begin
      #      OpenSSL::Digest.new(Digest.to_digest_string(dig)) 
      #      @supported << dig
      #    rescue NotImplementedError => e
      #    end
      #  end
      #end

    end # class SupportedDigest

  end
end
