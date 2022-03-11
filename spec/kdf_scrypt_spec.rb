
require_relative '../lib/ccipher_factory/kdf/kdf'

RSpec.describe CcipherFactory::KDF do

  it 'generates default derived output based on input' do
    
    input = "password"

    kdf = subject.instance
    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(256)
    kdf.derive_update(input)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.string).not_to be_nil

    rkdf = subject.from_asn1(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(input)
    rkdf.derive_final

    p rout.string
    expect(rout.string).not_to be_empty
    expect(rout.string == kdfOut.string).to be true

  end

  it 'generates custom derived output based on input' do
    
    input = "password"

    kdf = subject.instance
    kdf.cost = 2**14
    kdf.salt = SecureRandom.random_bytes(12)
    kdf.blocksize = 16

    kdfOut = MemBuf.new
    kdf.output(kdfOut)
    kdf.derive_init(512)
    kdf.derive_update(input)
    meta = kdf.derive_final

    expect(meta).not_to be_nil
    expect(kdfOut.string).not_to be_nil

    rkdf = subject.from_asn1(meta)
    rout = MemBuf.new
    rkdf.output(rout)
    rkdf.derive_update(input)
    rkdf.derive_final

    p rout.string
    expect(rout.string).not_to be_empty
    expect(rout.string == kdfOut.string).to be true

  end


end
