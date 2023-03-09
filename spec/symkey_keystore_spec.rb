
require_relative '../lib/ccipher_factory/symkey/symkey'
require_relative '../lib/ccipher_factory/symkey/symkey_generator'
require_relative '../lib/ccipher_factory/symkey_keystore/symkey_keystore'

RSpec.describe CcipherFactory::SymKeyKeystore do

  it 'generates keystore and load it back' do
   
    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)

    ks = CcipherFactory::SymKeyKeystore.new.to_keystore(sk) do |ops|
      case ops
      when :store_pass
        "password"
      end
    end

    rsk = CcipherFactory::SymKeyKeystore.from_encoded(ks) do |ops|
      case ops
      when :store_pass
        "password"
      end
    end

    expect(rsk.raw_key == sk.raw_key).to be true

    expect do
      CcipherFactory::SymKeyKeystore.from_encoded(ks) do |ops|
        case ops
        when :store_pass
          "wrong_password"
        end
      end
    end.to raise_exception(CcipherFactory::SymKeyDecryptionError)

    expect do
      CcipherFactory::SymKeyKeystore.from_encoded(ks) 
    end.to raise_exception(CcipherFactory::KeystoreError)


    expect do
      CcipherFactory::SymKeyKeystore.new.to_keystore(sk)
    end.to raise_exception(CcipherFactory::KeystoreError)

  end

end


