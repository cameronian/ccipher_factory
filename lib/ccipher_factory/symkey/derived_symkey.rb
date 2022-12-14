
require_relative '../kdf/kdf'

module CcipherFactory
  class DerivedSymKey
    include TR::CondUtils
    include SymKey
    include Common

    def self.from_encoded(bin, &block)
      ts = BinStruct.instance.struct_from_bin(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)

      raise SymKeyError, "Block is required" if not block

      pass = block.call(:password)
      raise SymKeyError, "Password to derive symkey is not available" if is_empty?(pass)

      keytype = BTag.value_constant(ts.keytype)
      keysize = ts.keysize
      dsk = DerivedSymKey.new(keytype, keysize) 
      dsk.kdf = KDF.from_encoded(ts.kdf_config)
      dsk.derive(pass)

      kcvBin = ts.kcv

      # default is NOT to generate the KCV flag to beat the recursive test 
      if block
        if not_empty?(kcvBin) and block.call(:pre_verify_password) == true
          kcv = KCV.from_encoded(kcvBin)
          kcv.key = dsk
          raise SymKeyError, "Given password is incorrect" if not kcv.is_matched?
        end
        #else
        #  raise SymKeyError, "Given password is incorrect" if not kcv.is_matched?
      end

      dsk

    end

    def self.logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :derived_symkey
      end
      @logger
    end

    attr_accessor :kdf
    def activate_password_verifier
      @passVer = true
    end
    def deactivate_password_verifier
      @passVer = false
    end

    def derive(pass, eng = :scrypt, &block)

      if is_empty?(@kdf)
        @kdf = KDF.instance(eng) 
        if block
          case eng
          when :scrypt
            @kdf.cost = block.call(:kdf_scrypt_cost)
            @kdf.parallel = block.call(:kdf_scrypt_parallel)
            @kdf.blocksize = block.call(:kdf_scrypt_blocksize)
            @kdf.salt = block.call(:kdf_scrypt_salt)
            @kdf.digestAlgo = block.call(:kdf_scrypt_digestAlgo)
          end
        end

        @kdf.derive_init(@keysize)
      end

      @kdf.derive_update(pass)
      @kdfAsn1 = @kdf.derive_final

      @key = @kdf.derivedVal

      #logger.debug "Derived : #{@key}"

    end

    def encoded

      ts = BinStruct.instance.struct(:symkey_derived)
      ts.keytype = BTag.constant_value(@keytype)
      ts.keysize = @keysize
      ts.kdf_config = @kdfAsn1
      if @passVer == true
        kcv = KCV.new
        kcv.key = self
        ts.kcv = kcv.encoded
      else
        ts.kcv = ""
      end
      ts.encoded

    end

    def logger
      self.class.logger
    end

  end
end
