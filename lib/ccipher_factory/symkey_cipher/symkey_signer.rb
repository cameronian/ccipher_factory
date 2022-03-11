

module CcipherFactory
  module SymKeySigner
    include TR::CondUtils

    class SKSigner; end

    class SymKeySignerError < StandardError; end

    def self.signer
      s = SKSigner.new
      s.extend(CcipherFactory::SymKeySigner::SymKeySign)
      s.init if s.respond_to?(:init)
      s
    end

    def self.att_signer
      s = SKSigner.new
      s.extend(SymKeyAttSign)
      s.init if s.respond_to?(:init)
      s
    end

    def self.verifier
      s = SKSigner.new
      s.extend(SymKeyVerify)
      s.init if s.respond_to?(:init)
      s
    end

    def self.att_verifier
      s = SKSigner.new
      s.extend(SymKeyAttVerify)
      s.init if s.respond_to?(:init)
      s
    end

    def SymKeySigner.algo_default(algo)

      case algo
      when :ecc
        { curve: :prime256v1 }
      when :rsa
        { keysize: 2048  }
      end

    end

  end
end


require_relative 'symkey_sign'
require_relative 'symkey_verify'

require_relative 'symkey_att_sign'
require_relative 'symkey_att_verify'

