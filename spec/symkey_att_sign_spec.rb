

RSpec.describe CcipherFactory::SymKeySigner do

  it 'create attached signature for symkey signing' do
    
    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)

    signer = subject.att_signer

    data = File.read('spec/kcv_spec.rb')

    out = MemBuf.new
    signer.output(out)

    signer.signing_key = sk
    signer.att_sign_init
    signer.att_sign_update(data)
    signer.att_sign_final

    vout = MemBuf.new

    ver = subject.att_verifier
    ver.output(vout)
    ver.verification_key = sk
    ver.att_verify_init
    ver.att_verify_update(out.string)
    res = ver.att_verify_final

    expect(vout.string == data).to be true

  end

  it 'create compressed attached signature for symkey signing' do
    
    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)

    signer = subject.att_signer

    data = File.read('spec/kcv_spec.rb')

    out = MemBuf.new
    signer.output(out)

    signer.compression_on
    signer.signing_key = sk
    signer.att_sign_init
    signer.att_sign_update(data)
    signer.att_sign_final

    vout = MemBuf.new

    ver = subject.att_verifier
    ver.output(vout)
    ver.verification_key = sk
    ver.att_verify_init
    ver.att_verify_update(out.string)
    res = ver.att_verify_final

    expect(vout.string == data).to be true

  end


end
