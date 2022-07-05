
require_relative '../lib/ccipher_factory/digest/digest'
require_relative '../lib/ccipher_factory/digest/supported_digest'

RSpec.describe CcipherFactory::Digest do

  let(:supported) { CcipherFactory::Digest::SupportedDigest.instance }

  it 'generates digests for all supported digest' do

    data = "testing"

    supported.supported.each do |da|
     
      next if da =~ /haraka/
      puts "Testing digest #{da}"
      d = subject.instance
      digRes = MemBuf.new
      d.output(digRes)
      meta = d.digest_init(da) do
        digest_update(data)
      end
      expect(meta).not_to be_nil

      d2 = subject.instance
      digRes2 = MemBuf.new
      d2.output(digRes2)
      d2.digest_init(da)
      d2.digest_update(data)
      meta2 = d2.digest_final
      expect(meta2 == meta).to be true
      expect(digRes.bytes.length > 0).to be true
      expect(digRes.bytes == digRes2.bytes).to be true

      rd = subject.from_encoded(meta)
      rdigRes = MemBuf.new
      rd.output(rdigRes)
      rd.digest_update(data)
      rmeta = rd.digest_final
      expect(rdigRes.bytes == digRes2.bytes).to be true

      rd2 = subject.from_encoded(meta)
      rdigRes2 = MemBuf.new
      rd2.output(rdigRes2)
      rd2.digest_update("invalid data!")
      rmeta = rd2.digest_final
      expect(rdigRes2.bytes == digRes2.bytes).to be false


      # attached mode
      d = subject.instance
      d.attach_mode
      meta = d.digest_init(da) do
        digest_update(data)
      end
      expect(meta).not_to be_nil
      expect(d.digestVal).not_to be_nil

      d2 = subject.instance
      d2.attach_mode
      d2.digest_init(da)
      d2.digest_update(data)
      meta2 = d2.digest_final
      expect(meta2 == meta).to be true
      expect(digRes.bytes.length > 0).to be true
      expect(digRes.bytes == digRes2.bytes).to be true
      expect(d.digestVal == d2.digestVal).to be true

      rd = subject.from_encoded(meta)
      rd.digest_update(data)
      rmeta = rd.digest_final
      expect(rd.digestVal == d2.digestVal).to be true

      puts "Testing digest algo #{da} successful"

    end

  end

  it 'create digest for user given value' do
    
  end


end
