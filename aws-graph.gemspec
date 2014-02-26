# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'aws-graph/version'

Gem::Specification.new do |spec|
  spec.name          = "aws-graph"
  spec.version       = AwsGraph::VERSION
  spec.authors       = ["k1LoW"]
  spec.email         = ["k1lowxb@gmail.com"]
  spec.summary       = %q{Draw AWS graph tool}
  spec.description   = %q{Draw AWS graph tool}
  spec.homepage      = "https://github.com/k1LoW/aws-graph"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.5"
  spec.add_development_dependency "rake"

  spec.add_dependency "aws-sdk"
  spec.add_dependency "thor"
  spec.add_dependency "gviz"
end
