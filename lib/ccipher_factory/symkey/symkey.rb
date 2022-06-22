
require_relative '../shamir/shamir_sharing_helper'

module CcipherFactory
  # 
  # Generic category to handle 4 types of symkey:
  # - software internal generated symkey (key value is generated internally)
  # - software external generated symkey (key value is being set by caller)
  # - derived symkey (key value is derived from password)
  # - hardware symkey (key value is stored in hardware and not going to be available)
  module SymKey
    extend TR::CondUtils
    include ShamirSharingHelper

    class SymKeyError < StandardError; end


    #module ClassMethods
    #  include ShamirSharingHelper

    #  def from_shares(keytype, keysize, shares)
    #    #self.send(:initialize, *[keytype, keysize, shamir_recover(shares)])
    #    #SymKey.instance_method(:initialize).bind(self).call(keytype, keysize, shamir_recover(shares))  

    #  end
    #end
    #def self.included(klass)
    #  klass.extend(ClassMethods)
    #end

    ## 
    # Mixin methods
    ##
    attr_accessor :keytype, :keysize, :key
    def initialize(keytype, keysize, key = nil)
      @keytype = keytype
      @keysize = keysize
      @key = key
    end

    def split_key(totalShare, reqShare, &block)
      shamir_split(@key, totalShare, reqShare)
    end

    def merge_key(shares)
      @key = shamir_recover(shares)
    end

    def dispose
      @key = nil
      GC.start
    end

    def self.from_asn1(bin, &block)
      raise SymKeyError, "Input should not be empty" if is_empty?(bin)

      ts = BinStruct.instance.struct_from_bin(bin)
      case ts.oid
      when BTag.constant_value(:symkey_derived)
        DerivedSymKey.from_tspec(ts, &block)
      when BTag.constant_value(:symkey)
        SoftSymKey.from_tspec(ts, &block)
      else
        raise SymKeyError, "Unknown symkey envelope '#{ts.oid}'"
      end


      #case ts.id
      #when :symkey_derived
      #  DerivedSymKey.from_tspec(ts, &block)
      #when :symkey
      #  SoftSymKey.from_tspec(ts, &block)
      #else
      #  raise SymKeyError, "Unknown symkey envelope '#{ts.id}'"
      #end

    end

  end
end
