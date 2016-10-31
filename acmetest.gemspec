Gem::Specification.new do |s|
  s.name        = 'acmetest'
  s.version     = '0.0.1'
  s.date        = '2016-10-31'
  s.summary     = "Let's Encrypt with DNS"
  s.description = "A letsencrypt client that uses DNS with Dyn or DNSimple"
  s.authors     = ["Andrew J. Brown"]
  s.email       = 'andrew.j.brown@gmail.com'
  s.files       = ["lib/acmetest.rb"]
  s.homepage    =
    'http://github.com/andrewjamesbrown/acmetet'
  s.license       = 'MIT'

  s.add_runtime_dependency 'acme-client'
  s.add_runtime_dependency 'dynect_rest'
  s.add_runtime_dependency 'dnsimple'
end

