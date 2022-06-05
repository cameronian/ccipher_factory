
require 'tlogger'

module CcipherFactory

  class TagException < StandardError; end

  class Tag
    extend ToolRack::ExceptionUtils

    REGISTRY = {}
    CONSTANT = {}

    def initialize(&block)
      @parentTag = []
      @definedTag = {}
      @logger = Tlogger.new
      @logger.tag = :tag
      instance_eval(&block)
    end

    def self.tag(key)
      if REGISTRY[key].nil?
        res = CONSTANT[key]
      else
        res = REGISTRY[key][:const]
      end
      raise_if_empty(res, "Value with key #{key} not found")
      res
    end

    def self.value(key)
      tag(key)
    end

    def self.constant(key)
      CONSTANT[key]
    end

    def self.constant_key(val)
      # for some reasons if not done like this, Java side has issue finding the value
      CONSTANT.invert[val.to_s.to_i]
    end

    def self.text(key)
      REGISTRY[key] == nil ? nil : REGISTRY[key][:text]
    end

    def add_constant(key,val)
      if CONSTANT.keys.include?(key)
        raise TagException, "Constant already have key '#{key}' defined"
      end

      CONSTANT[key] = val
    end

    def register(key, const, text, &block)
      if const =~ /#parent/
        const.gsub!("#parent",@parentTag[-1])
      end
      add_to_registry(key, { const: const, text: text })
    end

    def parent(key, val, text = "", &block) 
      if val =~ /#parent/
        val.gsub!("#parent",@parentTag[-1])
      end

      add_to_registry(key, { const: val, text: text })

      @parentTag.push(val)
      instance_eval(&block)
      @parentTag.pop
    end

    def add_to_registry(key,val)
      if not REGISTRY[key].nil?
        STDERR.puts "Key #{key} already defined and tied to value #{REGISTRY[key]}."
        raise TagException, "Key #{key} already defined and tied to value #{REGISTRY[key]}."
      else
        constCheck = @definedTag[val[:const]]
        if not constCheck.nil?
          STDERR.puts "Constant #{val[:const]} already defined and mapped to key #{constCheck}"
          raise TagException, "Constant #{val[:const]} already defined and mapped to key #{constCheck}"
        else
          @definedTag[val[:const]] = key
          REGISTRY[key] = val
          CONSTANT[val[:const]] = key

          #@logger.debug "#{key} / #{val} added to registry"
        end
      end
    end

  end

  #include CypherFactory

  # 
  # DSL to construct the Tag tree
  #
  Tag.new do

    parent(:root, '2.8.8', "CypherFactory Root OID") do

      parent(:encoder_id, "#parent.100") do 
        register(:ruby_encoder, "#parent.1", "Default Ruby encoding engine")
      end

      parent(:kdf, "#parent.10", "Key Derivation Formula") do
        register(:kdf_scrypt, "#parent.0", "KDF Scrypt")
        register(:kdf_hkdf, "#parent.1", "KDF HKDF")
      end

      parent(:digest, "#parent.20", "Digest Hashing") do
        add_constant(:sha1,     0x0101)
        add_constant(:sha256,   0x0102)
        add_constant(:sha384,   0x0103)
        add_constant(:sha224,   0x0104)
        add_constant(:sha512,   0x0105)
        add_constant(:sha512_224,   0x0106)
        add_constant(:sha512_256,   0x0107)

        add_constant(:sha3_256, 0x0110)
        add_constant(:sha3_224, 0x0111)
        add_constant(:sha3_384, 0x0112)
        add_constant(:sha3_512, 0x0113)

        add_constant(:shake128, 0x0120)
        add_constant(:shake256, 0x0121)

        add_constant(:blake2b160, 0x0130)
        add_constant(:blake2b256, 0x0131)
        add_constant(:blake2b384, 0x0132)
        add_constant(:blake2b512, 0x0133)

        add_constant(:blake2s128, 0x0134)
        add_constant(:blake2s160, 0x0135)
        add_constant(:blake2s224, 0x0136)
        add_constant(:blake2s256, 0x0137)

        add_constant(:haraka256, 0x0140)
        add_constant(:haraka512, 0x0141)

        add_constant(:shake128_256, 0x0142)
        add_constant(:shake256_512, 0x0143)

        add_constant(:sm3, 0x0144)
        add_constant(:whirlpool, 0x0145)

        add_constant(:keccak224, 0x0150)
        add_constant(:keccak256, 0x0151)
        add_constant(:keccak288, 0x0152)
        add_constant(:keccak384, 0x0153)
        add_constant(:keccak512, 0x0154)

        add_constant(:ripemd128, 0x0160)
        add_constant(:ripemd160, 0x0161)
        add_constant(:ripemd256, 0x0162)
        add_constant(:ripemd320, 0x0163)

        add_constant(:skein1024_1024, 0x0170)
        add_constant(:skein1024_384, 0x0171)
        add_constant(:skein1024_512, 0x0172)
        
        add_constant(:skein256_128, 0x0173)
        add_constant(:skein256_160, 0x0174)
        add_constant(:skein256_224, 0x0175)
        add_constant(:skein256_256, 0x0176)

        add_constant(:skein512_128, 0x0177)
        add_constant(:skein512_160, 0x0178)
        add_constant(:skein512_224, 0x0179)
        add_constant(:skein512_256, 0x0180)
        add_constant(:skein512_384, 0x0181)
        add_constant(:skein512_512, 0x0182)


      end
      register(:digest_attached, "#parent.21", "Digest with output attached")

      parent(:symkey, "#parent.30", "Symmetric key output") do

        add_constant(:aes, 0x0201)
        add_constant(:chacha20, 0x0202)
        add_constant(:chacha20_poly1305, 0x0203)
        add_constant(:blowfish, 0x0204)
        add_constant(:camellia, 0x0205)
        add_constant(:aria, 0x0206)

        add_constant(:gcm, 0x0220)
        add_constant(:cbc, 0x0221)
        add_constant(:cfb, 0x0222)
        add_constant(:ctr, 0x0223)
        add_constant(:ccm, 0x0224)

        add_constant(:ecb, 0x0225)

        add_constant(:ofb, 0x0226)
        add_constant(:ocb, 0x0227)

        add_constant(:poly1305, 0x0228)


        register(:symkey_derived, "#parent.0", "Symmetric key not included")
        register(:plain_symkey, "#parent.1", "Plain symmetric key")
        register(:symkey_vtype_kdf, "#parent.2", "KDF derived symmetric key")

        register(:symkey_cipher, "#parent.20", "Symmetric key cipher")
        register(:symkey_signature, "#parent.21", "Symmetric key signature")
        register(:symkey_att_sign, "#parent.22", "Symmetric key attached signature")

        register(:kcv, "#parent.30", "Symmetric key check value")

      end

      parent(:compression, "#parent.40", "Compression struture") do
        register(:compression_none, "#parent.0","No compression")
        register(:compression_zlib, "#parent.1", "Zlib compression")
        register(:compression_zlib_attached, "#parent.2", "Zlib compression includes data")
      end

      parent(:asymkey, "#parent.50", "Asymmetric key") do
        add_constant(:public_key, 0x0230)
        add_constant(:x509_cert, 0x0231)
        add_constant(:cf_cert, 0x0232)

        parent(:ecc, "#parent.1", "ECC cipher") do
          register(:ecc_cipher, "#parent.10","ECC Cipher")
          parent(:ecc_signature, "#parent.11","ECC Signature") do
            register(:ecc_signer_info, "#parent.1", "ECC signer info")
          end

          register(:ecc_att_sign, "#parent.12","ECC Attached Signature")
        end

      end

      parent(:composite, "#parent.60","Composite cipher operations") do

        register(:sign_encrypt_cipher, "#parent.1","Sign and encrypt cipher")

      end

      register(:shared_secret, "#parent.70","Shared secret")

    end 
  end

end

if $0 == __FILE__
  Tag::REGISTRY.each do |k,v|
    puts "#{k} : #{v}"
  end
end
