
require_relative '../kdf/kdf'

module CcipherFactory
  class DerivedSymKey
    include TR::CondUtils
    include SymKey
    include Common

    def self.from_asn1(bin, &block)
      ts = Encoding::ASN1Decoder.from_asn1(bin) 
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)

      raise SymKeyError, "Block is required" if not block

      pass = block.call(:password)
      raise SymKeyError, "Password to derive symkey is not available" if is_empty?(pass)

      keytype = Tag.constant_key(ts.value(:keytype))
      keysize = ts.value(:keysize)
      dsk = DerivedSymKey.new(keytype, keysize) 
      dsk.kdf = KDF.from_asn1(ts.value(:kdf_config)) 
      dsk.derive(pass)

      kcvBin = ts.value(:kcv)

      # default is NOT to generate the KCV flag to beat the recursive test 
      if block
        if not_empty?(kcvBin) and block.call(:pre_verify_password) == true
          kcv = KCV.from_asn1(kcvBin)
          kcv.key = dsk
          raise SymKeyError, "Given password is incorrect" if not kcv.is_matched?
        end
        #else
        #  raise SymKeyError, "Given password is incorrect" if not kcv.is_matched?
      end

      dsk

    end


    attr_accessor :kdf
    def activate_password_verifier
      @passVer = true
    end
    def deactivate_password_verifier
      @passVer = false
    end

    def derive(pass, eng = :scrypt)

      if is_empty?(@kdf)
        @kdf = KDF.instance(eng) 
        @kdf.derive_init(@keysize)
      end

      @kdf.derive_update(pass)
      @kdfAsn1 = @kdf.derive_final

      @key = @kdf.derivedVal

    end

    def to_asn1

      ts = Encoding::ASN1Encoder.instance(:symkey_derived)
      ts.set(:keytype, Tag.constant(@keytype))
      ts.set(:keysize, @keysize)
      ts.set(:kdf_config, @kdfAsn1)
      if @passVer == true
        kcv = KCV.new
        kcv.key = self
        ts.set(:kcv, kcv.to_asn1)
      else
        ts.set(:kcv, "")
      end
      ts.to_asn1
    end

  end
end
