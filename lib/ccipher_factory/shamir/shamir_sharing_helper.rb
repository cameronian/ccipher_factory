
#require_relative 'shamir_sharing'

module CcipherFactory
  module ShamirSharingHelper

    class ShamirSharingError < StandardError; end
    class InvalidShare < StandardError; end
    class NotEnoughShare < StandardError; end

    def shamir_split(data, totalShare, reqShare)

      rand = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)

      ssc = Ccrypto::SecretSharingConfig.new
      ssc.split_into = totalShare
      ssc.required_parts = reqShare
      ss = Ccrypto::AlgoFactory.engine(ssc)

      serial = rand.random_bytes(8)
      shares = ss.split(data)
      shares = shares.map { |s| 
        ts = Encoding::ASN1Encoder.instance(:shared_secret)
        ts.set(:req_share, reqShare)
        ts.set(:share_id, s[0])
        ts.set(:serial, serial)
        #sbin = share[1].map { |v| v.chr }.join
        ts.set(:shared_value, s[1]) 
        ts.to_asn1
      }

      #shares = []
      #(1..totalShare).each do |i|
      #  share = ss.compute_share(i)
      #  ts = Encoding::ASN1Encoder.instance(:shared_secret)
      #  ts.set(:req_share, reqShare)
      #  ts.set(:share_id, share[0])
      #  ts.set(:serial, serial)
      #  sbin = share[1].map { |v| v.chr }.join
      #  ts.set(:shared_value, sbin) 
      #  shares << ts.to_asn1
      #end

      shares

    end

    def shamir_recover(shares)

      shares = [shares] if not shares.is_a?(Array)
      shares = [] if is_empty?(shares)

      reqShare = nil
      res = { }
      foundSerial = nil
      shares.each do |s|
        ts = Encoding::ASN1Decoder.from_asn1(s)

        raise ShamirSharingError, "Not a shared secret envelope [#{ts.id}]" if ts.id != :shared_secret

        serial = ts.value(:serial)
        raise InvalidShare, "Given share not in same batch. Cannot proceed" if not_empty?(foundSerial) and serial != foundSerial

        rs = ts.value(:req_share) 
        raise ShamirSharingError, "Inconsistancy required shares value in given shares" if not_empty?(reqShare) and rs != reqShare
        reqShare = rs  

        sid = ts.value(:share_id)
        if not res.keys.include?(sid)
          val = ts.value(:shared_value)
          #res[sid.to_i] = val.chars.map(&:ord)
          res[sid.to_i] = val
        end

        foundSerial = serial
      end

      raise NotEnoughShare, "Required #{reqShare} share(s) but only #{res.size} is/are given" if res.size < reqShare or res.size == 0

      #ssc = Ccrypto::SecretSharingConfig.new
      #ssc.required_parts = reqShare
      #ss = Ccrypto::AlgoFactory.engine(ssc)
      ss = Ccrypto::AlgoFactory.engine(Ccrypto::SecretSharingConfig)
      ss.combine(reqShare, res)

    end

  end
end
