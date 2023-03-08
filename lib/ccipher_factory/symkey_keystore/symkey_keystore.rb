

module CcipherFactory
  class SymKeyKeystore
    include TR::CondUtils
    def self.from_encoded(bin, &block)
      
      raise SymKeyCipherError, "Block is required" if not block

      ts = BinStruct.instance.struct_from_bin(bin)
      from_tspec(ts, &block)
    end

    def self.from_tspec(ts, &block)
      
      sk = CcipherFactory::SymKey.from_encoded(ts.symkey_derived) do |ops|
        case ops
        when :password
          block.call(:password)
        end
      end

      dec = CcipherFactory::SymKeyCipher.att_decryptor
      decOut = MemBuf.new
      dec.output(decOut)
      dec.key = sk
      dec.att_decrypt_init
      dec.att_decrypt_update(ts.symkey_cipher)
      dec.att_decrypt_final

      CcipherFactory::SymKey.from_encoded(decOut.bytes)

    end

    def to_keystore(key, &block)
     
      raise SymKeyCipherError, "Key is required" if is_empty?(key)
      raise SymKeyCipherError, "Block is required" if not block

      # 1. Derive session key from user password
      sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
        case ops
        when :password
          pass = block.call(:password)
          if is_empty?(pass)
            raise SymKeyCipherError, "Password is required" 
          end
          pass
        end
      end
    
      # 2. Encrypt the given key with session key
      enc = CcipherFactory::SymKeyCipher.att_encryptor 
      enc.mode = :gcm
      enc.key = sk

      encOut = MemBuf.new
      enc.output(encOut)

      key.attach_mode

      enc.att_encrypt_init
      enc.att_encrypt_update(key.encoded)
      enc.att_encrypt_final

      ts = BinStruct.instance.struct(:symkey_keystore)
      ts.symkey_derived = sk.encoded
      ts.symkey_cipher = encOut.bytes
      ts.symkey = "testing"
      ts.encoded

    end
  end
end
