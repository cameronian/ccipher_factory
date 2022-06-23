
require 'singleton'

module CcipherFactory
  class BinStruct
    include Singleton

    def struct(key, ver = "1.0")
      st = structure(ver)[key] 
      st.clone if not st.nil?
    end

    def struct_from_bin(bin)
      bs = Binenc::EngineFactory.instance(:bin_struct)
      type, ver = bs.value_from_bin_struct(bin, 0, 1)
      c = BTag.value_constant(type) 
      st = struct(c, translate_version(ver))
      st.from_bin(bin) if not st.nil?
    end

    private
    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :binstruct
      end
      @logger
    end

    def structure(ver = "1.0")
      
      if @struct.nil?
        @struct = {  }

        @struct["1.0"] = {

          compression_none: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:compression_none)
            int :version, 0x0100
          end,

          compression_zlib: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:compression_zlib)
            int :version, 0x0100
          end,

          digest: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:digest)
            int :version, 0x0100
            int :digest_algo
            bin :salt
          end,

          digest_attached: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:digest_attached)
            int :version, 0x0100
            bin :digest_config
            bin :digest_value
          end,

          ecc_att_sign: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:ecc_att_sign)
            int :version, 0x0100
            bin :ecc_signature
            bin :compression
          end,

          ecc_cipher: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:ecc_cipher)
            int :version, 0x0100
            bin :sender_public
            bin :cipher_config
            bin :key_config
          end,

          ecc_signature: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:ecc_signature)
            int :version, 0x0100
            bin :digest_info
            bin :signer_info
            bin :signature
          end,

          ecc_signer_info: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:ecc_signer_info)
            int :version, 0x0100
            int :signer_info_type, BTag.constant_value(:public_key)
            bin :signer_info_value
          end,

          kcv: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:kcv)
            int :version, 0x0100
            int :mode
            bin :iv
            bin :nonce
            bin :check_value
          end,

          kdf_hkdf: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:kdf_hkdf)
            int :version, 0x0100
            int :digest
            int :outByteLength
            bin :salt
          end,

          kdf_scrypt: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:kdf_scrypt)
            int :version, 0x0100
            bin :digest
            bin :salt
            int :cost
            int :blocksize
            int :parallel
            int :outByteLength
          end,


          kdf_pbkdf2: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:kdf_pbkdf2)
            int :version, 0x0100
            int :digest
            bin :salt
            int :iterations
            int :outByteLength
          end,


          shared_secret: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:shared_secret)
            int :version, 0x0100
            int :req_share
            int :share_id
            bin :serial
            bin :shared_value
          end,

          sign_encrypt_cipher: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:sign_encrypt_cipher)
            int :version, 0x0100
            bin :signer_config
            bin :cipher_config
          end,

          symkey: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:symkey)
            int :version, 0x0100
            int :keytype
            int :keysize
            bin :key
          end,
          
          symkey_att_sign: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:symkey_att_sign)
            int :version, 0x0100
            bin :symkey_signature
            bin :compression
          end,

          symkey_cipher: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:symkey_cipher)
            int :version, 0x0100

            int :mode
            bin :iv
            bin :compression
            bin :auth_tag
          end,

          symkey_derived: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:symkey_derived)
            int :version, 0x0100

            int :keytype
            int :keysize
            bin :kdf_config
            bin :kcv
          end,

          symkey_signature: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, BTag.constant_value(:symkey_signature)
            int :version, 0x0100

            int :digest_algo
            bin :signature
          end,

        }
      end

      @struct[ver]

    end

    def translate_version(ver)
      case ver.to_i
      when 0x0100
        "1.0"
      else
        raise Exception, "Version #{ver} is unknown"
      end
    end


  end
end
