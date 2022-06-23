
#require_relative '../../lib/cipherfact/ruby/kdf/kdf'

RSpec.describe CcipherFactory::KDF do

  it 'generates PBKDF2 derived output based on input' do

    sk = SecureRandom.random_bytes(32)

    kdf = subject.instance(:pbkdf2)

    if TR::RTUtils.on_java?
      # Java side not supported default digest SHA3_256
      kdf.digestAlgo = :sha256
    end

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

  it 'generates custom PBKDF2 derived output based on input' do
    
    sk = SecureRandom.random_bytes(32)

    kdf = subject.instance(:pbkdf2)
    kdf.salt = SecureRandom.random_bytes(12)

    if TR::RTUtils.on_java?
      kdf.digestAlgo = :sha512
    else
      kdf.digestAlgo = :sha3_512
    end

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
