

module CcipherFactory

  module AsymKey

    class AsymKeyError < StandardError; end

    attr_reader :keypair
    def initialize(keypair = nil)
      @keypair = keypair
    end

  end

end
