
require_relative 'symkey'

module CcipherFactory
  class SoftSymKey
    include TR::CondUtils
    include SymKey
    include Common

    def self.from_asn1(bin, &block)
      ts = BinStruct.instance.struct_from_bin(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)
      
      #raise SymKeyError, "Given envelope not symkey enveloppe [#{ts.id}]" if ts.id != :symkey
      raise SymKeyError, "Given envelope not symkey enveloppe [#{ts.oid}]" if ts.oid != BTag.constant_value(:symkey)

      #keytype = Tag.constant_key(ts.value(:keytype))
      #keysize = ts.value(:keysize)
      #key = ts.value(:key)

      keytype = BTag.value_constant(ts.keytype)
      keysize = ts.keysize
      key = ts.key
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

    def encoded
      ts = BinStruct.instance.struct(:symkey)
      ts.keytype = BTag.constant_value(@keytype)
      ts.keysize = @keysize
      if is_attach_mode? 
        case @key
        when String
          ts.key = @key
        else
          ts.key = @key.to_bin
        end
      else
        ts.key = ""
      end
      ts.encoded

    end

  end
end
