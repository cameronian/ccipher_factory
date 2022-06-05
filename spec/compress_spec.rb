


RSpec.describe CcipherFactory::Compression::Compressor do


  it 'compresses input data and decompress for output' do
    
    c = CcipherFactory::Compression::Compressor.new
    c.compress

    dig = CcipherFactory::Digest.instance
    dig.digest_init
    dig.attach_mode
    digOut = MemBuf.new
    dig.output(digOut)

    source = File.expand_path("./spec/digest_spec.rb")
    out = MemBuf.new
    c.output(out)
    res = c.compress_init do
      File.open(source,'rb') do |f|
        data = f.read
        compress_update data 
        dig.digest_update data
      end
    end
    expect(out.length > 0).to be true
    puts "Compressed length : #{out.length}"
    puts "Orignal length : #{File.size(source)}"
    expect(out.length < File.size(source)).to be true
    expect(res.length > 0).to be true

    digMeta = dig.digest_final

    c = CcipherFactory::Compression::Compressor.new
    c.decompress

    dig2 = CcipherFactory::Digest.from_asn1(digMeta) 
    digOut2 = MemBuf.new
    dig2.output(digOut2)

    dout = MemBuf.new
    c.output(dout)
    c.decompress_init do
      decompress_update_meta(res)
      decompress_update(out.bytes)
    end
    puts "Inflated size : #{dout.length}"
    dig2.digest_update(dout)
    digRes = dig2.digest_final
    expect(digOut2.bytes == digOut.bytes).to be true

  end

end
