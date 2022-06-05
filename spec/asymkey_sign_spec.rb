

RSpec.describe CcipherFactory::AsymKeySigner do

  it 'signs and verifies given data' do
    
    ask = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    data = File.read(__FILE__)

    signer = subject.signer
    signer.signing_key = ask
    signer.sign_init #(ask)
    signer.sign_update(data)
    meta = signer.sign_final

    ver = subject.verifier
    ver.verify_init
    ver.verify_update_meta(meta)
    ver.verify_update_data(data)
    res = ver.verify_final

    p res
    expect(res).to be true
    #expect(ver.embedded_signer.to_der == ask.public_key.public_key.to_der).to be true
    expect(ask.is_public_key_equal?(ver.embedded_signer)).to be true

  end

end

