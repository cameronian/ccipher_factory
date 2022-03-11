

RSpec.describe CcipherFactory::AsymKeySigner do

  it 'signs and verifies attached signature' do
   
    ask = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    data = File.read(__FILE__)

    out = MemBuf.new

    signer = subject.att_signer
    signer.output(out)
    signer.signing_key = ask
    signer.att_sign_init
    signer.att_sign_update(data)
    meta = signer.att_sign_final

    vout = MemBuf.new
    ver = subject.att_verifier
    ver.output(vout)
    ver.att_verify_init
    ver.att_verify_update(out.string)
    res = ver.att_verify_final

    expect(res).to be true
    expect(vout.string == data).to be true
    #expect(ver.embedded_signer.to_der == ask.public_key.public_key.to_der).to be true

  end

  it 'signs and verifies attached signature with compression on' do
   
    ask = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    data = File.read(__FILE__)

    out = MemBuf.new

    signer = subject.att_signer
    signer.output(out)
    signer.compression_on
    signer.signing_key = ask
    signer.att_sign_init
    signer.att_sign_update(data)
    meta = signer.att_sign_final

    vout = MemBuf.new
    ver = subject.att_verifier
    ver.output(vout)
    ver.att_verify_init
    ver.att_verify_update(out.string)
    res = ver.att_verify_final

    expect(res).to be true
    expect(vout.string == data).to be true
    #expect(ver.embedded_signer.to_der == ask.public_key.public_key.to_der).to be true

  end


end
