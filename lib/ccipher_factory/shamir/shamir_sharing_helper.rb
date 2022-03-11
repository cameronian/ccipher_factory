
require_relative 'shamir_sharing'

module CcipherFactory
  module ShamirSharingHelper

    class ShamirSharingError < StandardError; end
    class InvalidShare < StandardError; end
    class NotEnoughShare < StandardError; end

    def shamir_split(data, totalShare, reqShare)

      ss = ShamirSharing.new(reqShare, data)

      serial = SecureRandom.random_bytes(8)
      shares = []
      (1..totalShare).each do |i|
        share = ss.compute_share(i)
        ts = Encoding::ASN1Encoder.instance(:shared_secret)
        ts.set(:req_share, reqShare)
        ts.set(:share_id, share[0])
        ts.set(:serial, serial)
        sbin = share[1].map { |v| v.chr }.join
        ts.set(:shared_value, sbin) 
        shares << ts.to_asn1
      end

      shares

    end

    def shamir_recover(shares)

      shares = [shares] if not shares.is_a?(Array)
      shares = [] if is_empty?(shares)

      reqShare = 0
      res = { }
      foundSerial = nil
      shares.each do |s|
        ts = Encoding::ASN1Decoder.from_asn1(s)

        raise ShamirSharingError, "Not a shared secret envelope [#{ts.id}]" if ts.id != :shared_secret

        serial = ts.value(:serial)
        raise InvalidShare, "Given share not in same batch. Cannot proceed" if not_empty?(foundSerial) and serial != foundSerial

        reqShare = ts.value(:req_share)
        sid = ts.value(:share_id)
        if not res.keys.include?(sid)
          val = ts.value(:shared_value)
          res[sid.to_i] = val.chars.map(&:ord)
        end

        foundSerial = serial
      end

      raise NotEnoughShare, "Required #{reqShare} share(s) but only #{res.size} is/are given" if res.size < reqShare or res.size == 0

      ss = ShamirSharing.new(reqShare)
      ss.recover_secretdata(res.to_a)

    end

  end
end
