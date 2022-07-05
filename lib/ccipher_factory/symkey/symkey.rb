
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
    
    # Symmetric key type. Supported key type refers 
    # CcipherFactory::SymKeyGenerator#supported_symkey
    attr_accessor :keytype
    
    # Key length in bits
    attr_accessor :keysize
    
    # Raw key. It could be bytes or key object
    attr_accessor :key

    def initialize(keytype, keysize, key = nil)
      @keytype = keytype
      @keysize = keysize
      @key = key
    end

    # split the raw key value into secret shares
    def split_key(totalShare, reqShare, &block)
      shamir_split(@key, totalShare, reqShare)
    end

    # merge the splited share values into raw key value back
    def merge_key(shares)
      @key = shamir_recover(shares)
    end

    def dispose
      @key = nil
      GC.start
    end

    def raw_key
      if not @key.nil?
        nativeHelper = Ccrypto::UtilFactory.instance(:native_helper)
        if @key.is_a?(String) or nativeHelper.is_byte_array?(@key)
          @key
        elsif @key.respond_to?(:to_bin)
          @key.to_bin
        else
          raise SymKeyError, "Not sure how to get raw_key for #{@key.inspect}"
        end
        #case @key
        #when String, ::Java::byte[]
        #  @key
        #else
        #  if @key.respond_to?(:to_bin)
        #    @key.to_bin
        #  else
        #    raise SymKeyError, "Not sure how to get raw_key for #{@key.inspect}"
        #  end
        #end
      else
        raise SymKeyError, "Key instance is nil. Cannot get raw_key from nil instance"
      end
    end

    def is_equals?(key)
      comp = Ccrypto::UtilFactory.instance(:comparator)
      comp.is_equal?(@key, key)
    end

    def self.from_encoded(bin, &block)
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
