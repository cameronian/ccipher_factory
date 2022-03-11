

module CcipherFactory
  module AsymKeySigner

    class ASKSigner; end
    class ASKVerifier; end

    class AsymKeySignerError < StandardError; end

    def self.signer(eng = :ecc)
      s = ASKSigner.new
      s.extend(ECCSigner)
      s
    end

    def self.verifier(eng = :ecc)
      s = ASKSigner.new
      s.extend(ECCVerifier)
      s
    end

    def self.att_signer(eng = :ecc)
      s = ASKSigner.new
      s.extend(ECCAttSigner)
      s
    end

    def self.att_verifier(eng = :ecc)
      s = ASKSigner.new
      s.extend(ECCAttVerifier)
      s
    end


  end
end

require_relative 'ecc/ecc_signer'
require_relative 'ecc/ecc_verifier'

require_relative 'ecc/ecc_att_signer'
require_relative 'ecc/ecc_att_verifier'

