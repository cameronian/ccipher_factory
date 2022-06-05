
#require_relative '../../lib/cipherfact/ruby/kdf/kdf'

RSpec.describe CcipherFactory::KDF do

  it 'generates HKDF derived output based on input' do

    #skip("Java has no HKDF implementation yet") if TR::RTUtils.on_jruby? 

    sk = SecureRandom.random_bytes(32)

    kdf = subject.instance(:hkdf)
    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(512)
    kdf.derive_update(sk)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.bytes).not_to be_nil
    expect(kdfOut.bytes.length == 64).to be true

    rkdf = subject.from_asn1(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(sk)
    rkdf.derive_final

    expect(rout.bytes).not_to be_empty
    expect(rout.bytes == kdfOut.bytes).to be true

  end

  it 'generates custom HKDF derived output based on input' do
    
    #skip("Java has no HKDF implementation yet") if TR::RTUtils.on_jruby? 

    sk = SecureRandom.random_bytes(32)

    kdf = subject.instance(:hkdf)
    kdf.salt = SecureRandom.random_bytes(12)
    kdf.digestAlgo = :sha3_512

    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(512)
    kdf.derive_update(sk)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.bytes).not_to be_nil
    expect(kdfOut.bytes.length == 64).to be true

    rkdf = subject.from_asn1(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(sk)
    rkdf.derive_final

    expect(rout.bytes).not_to be_empty
    expect(rout.bytes == kdfOut.bytes).to be true

  end


end
