
BTag = Binenc::BinTag.instance

BTag.load do

  # hierarchy
  define_constant(:root, '2.8.8') do
    
    define_constant(:kdf, "#.10") do
      define_constant(:kdf_scrypt, "#.0")
      define_constant(:kdf_hkdf, "#.1")
      define_constant(:kdf_pbkdf2, "#.2")
    end

    define_constant(:digest, "#.20")
    define_constant(:digest_attached, "#.21")

    define_constant(:symkey, "#.30") do
      define_constant(:symkey_derived, "#.0")
      define_constant(:plain_symkey, "#.1")
      define_constant(:symkey_vtype_kdf, "#.2")

      define_constant(:symkey_cipher, "#.20")
      define_constant(:symkey_signature, "#.21")
      define_constant(:symkey_att_sign, "#.22")

      define_constant(:kcv, "#.30")
    end

    define_constant(:compression, "#.40") do
      define_constant(:compression_none, "#.0")
      define_constant(:compression_zlib, "#.1")
      define_constant(:compression_zlib_attached, "#.2")
    end

    define_constant(:asymkey, "#.50") do
      define_constant(:ecc, "#.1") do
        define_constant(:ecc_cipher, "#.10")
        define_constant(:ecc_signature, "#.11") do
          define_constant(:ecc_signer_info, "#.1")
        end

        define_constant(:ecc_att_sign, "#.12")
      end
    end

    define_constant(:composite, "#.60") do
      define_constant(:sign_encrypt_cipher, "#.1")
    end

    define_constant(:shared_secret, "#.70")

  end



  # constant
  define_constant(:sha1,         0x0101)
  define_constant(:sha256,       0x0102)
  define_constant(:sha384,       0x0103)
  define_constant(:sha224,       0x0104)
  define_constant(:sha512,       0x0105)
  define_constant(:sha512_224,   0x0106)
  define_constant(:sha512_256,   0x0107)

  define_constant(:sha3_256,     0x0110)
  define_constant(:sha3_224,     0x0111)
  define_constant(:sha3_384,     0x0112)
  define_constant(:sha3_512,     0x0113)

  define_constant(:shake128,     0x0120)
  define_constant(:shake256,     0x0121)

  define_constant(:blake2b160,   0x0130)
  define_constant(:blake2b256,   0x0131)
  define_constant(:blake2b384,   0x0132)
  define_constant(:blake2b512,   0x0133)

  define_constant(:blake2s128,   0x0134)
  define_constant(:blake2s160,   0x0135)
  define_constant(:blake2s224,   0x0136)
  define_constant(:blake2s256,   0x0137)

  define_constant(:haraka256,    0x0140)
  define_constant(:haraka512,    0x0141)

  define_constant(:shake128_256, 0x0142)
  define_constant(:shake256_512, 0x0143)

  define_constant(:sm3,          0x0144)
  define_constant(:whirlpool,    0x0145)

  define_constant(:keccak224,    0x0150)
  define_constant(:keccak256,    0x0151)
  define_constant(:keccak288,    0x0152)
  define_constant(:keccak384,    0x0153)
  define_constant(:keccak512,    0x0154)

  define_constant(:ripemd128,    0x0160)
  define_constant(:ripemd160,    0x0161)
  define_constant(:ripemd256,    0x0162)
  define_constant(:ripemd320,    0x0163)

  define_constant(:skein1024_1024, 0x0170)
  define_constant(:skein1024_384, 0x0171)
  define_constant(:skein1024_512, 0x0172)

  define_constant(:skein256_128, 0x0173)
  define_constant(:skein256_160, 0x0174)
  define_constant(:skein256_224, 0x0175)
  define_constant(:skein256_256, 0x0176)

  define_constant(:skein512_128, 0x0177)
  define_constant(:skein512_160, 0x0178)
  define_constant(:skein512_224, 0x0179)
  define_constant(:skein512_256, 0x0180)
  define_constant(:skein512_384, 0x0181)
  define_constant(:skein512_512, 0x0182)


  define_constant(:aes,          0x0201)
  define_constant(:chacha20,     0x0202)
  define_constant(:chacha20_poly1305, 0x0203)
  define_constant(:blowfish,     0x0204)
  define_constant(:camellia,     0x0205)
  define_constant(:aria,         0x0206)

  define_constant(:gcm, 0x0220)
  define_constant(:cbc, 0x0221)
  define_constant(:cfb, 0x0222)
  define_constant(:ctr, 0x0223)
  define_constant(:ccm, 0x0224)

  define_constant(:ecb, 0x0225)

  define_constant(:ofb, 0x0226)
  define_constant(:ocb, 0x0227)

  define_constant(:poly1305,   0x0228)

  define_constant(:public_key, 0x0230)
  define_constant(:x509_cert,  0x0231)
  define_constant(:cf_cert,    0x0232)


end
