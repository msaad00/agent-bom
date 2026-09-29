require "fast_mcp"
require "nokogiri"
require "sinatra"

class RunTool < FastMcp::Tool
  description "Run a command"

  def call(command:)
    parse(command)
    system(command)
  end

  def parse(xml)
    Nokogiri::XML(xml)
  end
end

get "/run" do
  `#{params[:cmd]}`
end
