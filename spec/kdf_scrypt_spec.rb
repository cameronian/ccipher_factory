
require_relative '../lib/ccipher_factory/kdf/kdf'

RSpec.describe CcipherFactory::KDF do

  it 'generates default derived output based on input' do
    
    input = "password"

    kdf = subject.instance(:scrypt)
    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(256)
    kdf.derive_update(input)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.bytes).not_to be_nil
    expect(kdf.is_attached_mode?).to be false

    rkdf = subject.from_encoded(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(input)
    rkdf.derive_final

    expect(rout.bytes).not_to be_empty
    expect(rout.bytes == kdfOut.bytes).to be true
    expect(rkdf.is_attached_mode?).to be false

  end

  it 'generates default derived attached KDF based on input' do
    
    input = "password"

    kdf = subject.instance(:scrypt)
    kdf.attachedDigest = true
    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(256)
    kdf.derive_update(input)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.bytes).not_to be_nil
    expect(kdf.is_attached_mode?).to be true

    rkdf = subject.from_encoded(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(input)
    rkdf.derive_final

    expect(rout.bytes).not_to be_empty
    expect(rout.bytes == kdfOut.bytes).to be true
    expect(rkdf.is_attached_mode?).to be true
    expect(kdfOut.bytes == rkdf.attachedValue).to be true

  end


  it 'generates custom derived output based on input' do
    
    input = "password"

    kdf = subject.instance(:scrypt)
    kdf.cost = 2**14
    kdf.salt = SecureRandom.random_bytes(12)
    kdf.blocksize = 16

    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(512)
    kdf.derive_update(input)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.bytes).not_to be_nil

    rkdf = subject.from_encoded(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(input)
    rkdf.derive_final

    expect(rout.bytes).not_to be_empty
    expect(rout.bytes == kdfOut.bytes).to be true

  end


end
