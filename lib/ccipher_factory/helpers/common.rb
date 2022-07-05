
require 'tempfile'

module CcipherFactory
  module Common
    include TR::CondUtils

    # 
    # output section
    #
    def output(output)
      raise CcipherFactory::Error, "Output requires to support write(). StringIO is a good example." if output.nil? or not output.respond_to?(:write)
      @output = output
    end

    def output_obj
      @output
    end

    def write_to_output(val)
      @output.write(val) if not @output.nil? and not_empty?(val)
    end

    def is_output_given?
      not @output.nil?
    end

    def intOutputBuf
      if @intOutputBuf.nil?
        @intOutputBuf = MemBuf.new
      end
      @intOutputBuf
    end

    def cleanup_intOutputBuf
      if not @intOutputBuf.nil?
        @intOutputBuf = nil
      end
    end

    def intOutputFile
      if @intOutputFile.nil?
        @intOutputFile = Tempfile.new
      end
      @intOutputFile
    end

    def cleanup_intOutputFile
      if not @intOutputFile.nil?
        @intOutputFile.close!
        @intOutputFile = nil
      end
    end

    def disposeOutput(obj)
      case obj
      when intOutputBuf
        cnt = 0
        len = @intOutputBuf.length
        loop do
          @intOutputBuf.rewind
          @intOutputBuf.write(SecureRandom.random_bytes(len))
          cnt += 1
          break if cnt >= 16
        end
        @intOutputBuf.rewind
        @intOutputBuf = nil
      when intOutputFile
        @intOutputFile.close!
      end
    end
    # 
    # end output section
    #

    # 
    # attached mode
    # Flag to indicate if the result of the operation 
    # should be part of the header/meta data directly
    # return from the API
    #
    def attach_mode
      @attachMode = true
    end

    def detach_mode
      @attachMode = false
    end

    def is_attach_mode?
      if @attachMode.nil? or not is_bool?(@attachMode)
        # default detach
        # The impact is mainly on huge data encrypt/decrypt
        # Returning the huge data through the API returned might
        # have undetermined behaviour
        false
      else
        @attachMode
      end
    end
    # 
    # End attach mode section
    #


    def sanitize_symbol(sym, conv = :downcase)
      if not_empty?(sym)
        case conv
        when :downcase
          sym.to_s.downcase.to_sym
        when :upcase
          sym.to_s.upcase.to_sym
        when :capitalize
          sym.to_s.capitalize.to_sym
        else
          sym
        end
      else
        sym
      end
    end

  end
end
