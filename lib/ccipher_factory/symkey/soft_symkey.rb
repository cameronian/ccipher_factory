
require_relative 'symkey'

module CcipherFactory
  class SoftSymKey
    include TR::CondUtils
    include SymKey
    include Common

    def self.from_asn1(bin, &block)
      ts = Encoding::ASN1Decoder.from_asn1(bin) 
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)
      raise SymKeyError, "Given envelope not symkey enveloppe [#{ts.id}]" if ts.id != :symkey

      keytype = Tag.constant_key(ts.value(:keytype))
      keysize = ts.value(:keysize)
      key = ts.value(:key)
      if is_empty?(key)
        if not block
          raise SymKeyError, "Key is not in the meta data. Key is required to complete the construction of the object"
        end
        key = block.call(:key)
      end

      SoftSymKey.new(keytype, keysize, key) 
    end

    ## 
    # Mixin methods
    ##
    def initialize(keytype, keysize, key = nil)
      super(keytype, keysize, key)
    end

    def to_asn1
      ts = Encoding::ASN1Encoder.instance(:symkey)
      ts.set(:keytype, Tag.constant(@keytype))
      ts.set(:keysize, @keysize)
      if is_attach_mode? 
        ts.set(:key, @key)
      else
        ts.set(:key, "")
      end
      ts.to_asn1
    end

  end
end
