
require_relative 'scrypt'
require_relative 'hkdf'
require_relative 'pbkdf2'

module CcipherFactory
  module KDF

    class KDFError < StandardError; end

    class KDFEngine; end

    def KDF.instance(eng = :scrypt, &block)
      kdf = KDFEngine.new

      case eng
      when :scrypt
        kdf.extend(Scrypt)
      when :hkdf
        kdf.extend(HKDF)
      when :pbkdf2
        kdf.extend(PBKDF2)
      else
        raise KDFError, "Unknown KDF engine '#{eng}'"
      end

      kdf
    end

    def self.supported_kdf_algo
      [:scrypt, :hkdf, :pbkdf2].freeze
    end

    def self.from_encoded(bin, &block)
      ts = BinStruct.instance.struct_from_bin(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)
      case BTag.value_constant(ts.oid)
      when :kdf_scrypt
        kdf = KDFEngine.new
        kdf.extend(Scrypt)
        kdf.cost = ts.cost
        kdf.parallel = ts.parallel
        kdf.blocksize = ts.blocksize
        kdf.salt = ts.salt
        kdf.outByteLength = ts.outByteLength
        kdf.digest = Digest.from_encoded(ts.digest)
        kdf.attachedValue = ts.value
        kdf.derive_init
        kdf
      when :kdf_hkdf
        kdf = KDFEngine.new
        kdf.extend(HKDF)
        kdf.digestAlgo = BTag.value_constant(ts.digest)
        kdf.salt = ts.salt
        kdf.outByteLength = ts.outByteLength
        kdf.attachedValue = ts.value
        kdf.derive_init
      when :kdf_pbkdf2
        kdf = KDFEngine.new
        kdf.extend(PBKDF2)
        kdf.digestAlgo = BTag.value_constant(ts.digest)
        kdf.salt = ts.salt
        kdf.iter = ts.iterations
        kdf.outByteLength = ts.outByteLength
        kdf.attachedValue = ts.value
        kdf.derive_init
      else
        raise KDFError, "Unknown KDF envelope ID '#{ts.oid}'"
      end
    end

  end
end
