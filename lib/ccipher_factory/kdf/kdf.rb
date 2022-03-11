
require_relative 'scrypt'
require_relative 'hkdf'

module CcipherFactory
  module KDF

    class KDFError < StandardError; end

    class KDFEngine; end

    def KDF.instance(eng = :scrypt)
      kdf = KDFEngine.new

      case eng
      when :scrypt
        kdf.extend(Scrypt)
      when :hkdf
        kdf.extend(HKDF)
      else
        raise KDFError, "Unknown KDF engine '#{eng}'"
      end

      kdf
    end

    def self.from_asn1(bin, &block)
      ts = Encoding::ASN1Decoder.from_asn1(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)
      case ts.id
      when :kdf_scrypt
        kdf = KDFEngine.new
        kdf.extend(Scrypt)
        kdf.cost = ts.value(:cost)
        kdf.parallel = ts.value(:parallel)
        kdf.blocksize = ts.value(:blocksize)
        kdf.salt = ts.value(:salt)
        kdf.outByteLength = ts.value(:outByteLength)
        kdf.digest = Digest.from_asn1(ts.value(:digest))
        kdf.derive_init
        kdf
      when :kdf_hkdf
        kdf = KDFEngine.new
        kdf.extend(HKDF)
        kdf.digestAlgo = Tag.constant_key(ts.value(:digest))
        kdf.salt = ts.value(:salt)
        kdf.outByteLength = ts.value(:outByteLength)
        kdf.derive_init
      else
        raise KDFError, "Unknown KDF envelope ID '#{ts.id}'"
      end
    end

  end
end
