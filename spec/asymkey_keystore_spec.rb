
require_relative '../lib/ccipher_factory/asymkey/asymkey'
require_relative '../lib/ccipher_factory/asymkey/asymkey_generator'
require_relative '../lib/ccipher_factory/asymkey_keystore/asymkey_keystore'

RSpec.describe CcipherFactory::AsymKeyKeystore do

  it 'generates keystore and load it back' do
   
    kp = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    ks = CcipherFactory::AsymKeyKeystore.new.to_keystore(kp) do |ops|
      case ops
      when :store_pass
        "password"
      end
    end


    rks = CcipherFactory::AsymKeyKeystore.from_encoded(ks) do |ops|
      case ops
      when :store_pass
        "password"
      end
    end

    expect(rks.private_key.to_der == kp.private_key.to_der).to be true

  end

end
