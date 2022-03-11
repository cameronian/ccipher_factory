

module CcipherFactory
  class MemoryBuffer

    def initialize
      @buffer = StringIO.new
      @buffer.binmode
    end

    def buffer
      @buffer.string
    end
    alias_method :bin, :buffer
    alias_method :value, :buffer

    def method_missing(mtd, *args, &block)
      @buffer.send(mtd, *args, &block)
    end

    def respond_to_missing?(mtd, inc_private = false)
      @buffer.respond_to?(mtd, inc_private)
    end

    def dispose(wcnt = 32)
      len = @buffer.length
      cnt = 0
      loop do
        @buffer.rewind
        @buffer.write(SecureRandom.random_bytes(len))

        cnt += 1
        break if cnt >= wcnt
      end

      @buffer = nil
      GC.start
    end

  end
end


