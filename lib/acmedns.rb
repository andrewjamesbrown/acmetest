#!/usr/bin/env ruby

require 'acme-client'
require 'dynect_rest'
require 'dnsimple'
require 'openssl'
require 'restclient/exceptions'
require 'resolv'

class ACMEError < StandardError
end

class AcmeDns
  def read_config
    config = YAML.load_file(ENV['ACME_CONFIG'] || 'config.yml')
    @config = config['config']
    @config['email'] ||= raise "'email' is a mandatory configuration parameter."
    @config['endpoint'] ||= 'https://acme-staging.api.letsencrypt.org'
    @config['private_key_path'] ||= './letsencrypt.pem'
    @config['dyn'] ||= {}
    @config['dnsimple'] ||= {}
    @config['domains'] ||= []
  end

  def register(client, email)
    begin
      registration = client.register(contact: "mailto:#{email}")
      registration.agree_terms
    rescue Acme::Client::Error::Malformed
    end
  end

  def get_nameservers(zone)
    dns = Resolv::DNS.new
    ips = []
    names = dns.getresources(zone, Resolv::DNS::Resource::IN::NS)
    names.each do |name|
      ips << dns.getresource(name.name, Resolv::DNS::Resource::IN::A).address
    end
    ips.map { |n| n.to_s }
  end

  def get_zone(hostname)
    dns = Resolv::DNS.new
    make_domains(hostname).each do |host|
      begin
        dns.getresource(host, Resolv::DNS::Resource::IN::NS)
        return host
      rescue Resolv::ResolvError
      end
    end
  end

  def wait_until_published(zone, challenge, domain)
    print "Waiting for #{challenge.record_name}.#{domain} to be published... "
    for ns in get_nameservers(zone) do
      dns = Resolv::DNS.new(:nameserver => ns,
                            :search => zone,
                            :ndots => 1)
      i = 0
      begin
        i = i + 1
        rec = dns.getresource("#{challenge.record_name}.#{domain}", Resolv::DNS::Resource::IN::TXT)
        raise Resolv::ResolvError if rec.data != challenge.record_content
      rescue Resolv::ResolvError => e
        # puts "#{challenge.record_name}.#{domain}", challenge.record_content, rec.data
        sleep 1
        print '.'
        retry if i < 300 # Wait 5 minutes for DNS to propagate
        raise e
      end
    end
    puts " Done."
  end

  def make_domains(domain)
    vals = domain.split('.')
    mem = []
    (vals.length - 1).downto(0).each do |num|
      mem << vals[num, vals.length].join('.')
    end
    mem.reverse
  end

  def get_domain(client, hostname)
    account_id = client.identity.whoami.data.account.id
    make_domains(hostname).each do |domain|
      client.domains.all_domains(account_id, filter: { name_like: domain }).data.each do |record|
        return record if record.name == domain
      end
    end
    return nil
  end

  def delete_existing_challenge(dyn, zone, hostname, challenge)
    dns = Resolv::DNS.new(:nameserver => get_nameservers(zone),
                          :search => zone,
                          :ndots => 1)
    begin
      records = dns.getresources("#{challenge.record_name}.#{hostname}", Resolv::DNS::Resource::IN::TXT)
      puts records
      if @config['dns_provider'].downcase.eql?('dnsimple')
        dnsimple_client = Dnsimple::Client.new(access_token: @config['dnsimple']['token'])
        whoami = dnsimple_client.identity.whoami.data
        account_id = whoami.account.id
        records.each do |record|
          domain = get_domain(dnsimple_client, hostname)
          next if domain.nil?
          filter_name = "#{challenge.record_name}.#{hostname.split(domain.name).first.chomp('.')}"
          recs = dnsimple_client.zones.records(account_id, domain.name, { filter: { name_like: filter_name } })
          recs.data.each do |rec|
            dnsimple_client.zones.delete_record(account_id, domain.name, rec.id)
          end
        end
      elsif @config['dns_provider'].downcase.eql?('dyn')
        records.each do |record|
          next if record.nil?
          rec = dyn.txt.fqdn("#{challenge.record_name}.#{hostname}").ttl(60)
          rec['txtdata'] = record.data
          rec.delete
        end
        dyn.publish
      end
    rescue Resolv::ResolvError => e
      # Not found... we're good
    end
  end

  def load_private_key(filename)
    if File.exists?(filename)
      private_key = OpenSSL::PKey::RSA.new(File.read(filename))
    else
      private_key = OpenSSL::PKey::RSA.new(4096)
      File.write(filename, private_key)
    end
    private_key
  end

  def do_acme(client)
    register(client, @config['email'])
    @config['domains'].each do |domain|
      begin
        authorization = client.authorize(domain: domain)

        if authorization.status == 'valid'
          next
        elsif authorization.status == 'pending'
          begin
            challenge = authorization.dns01
            zone = get_zone(domain)

            # Check for existing TXT record and delete it if present
            if @config['dns_provider'].downcase.eql?('dnsimple')
              dnsimple_client = Dnsimple::Client.new(access_token: @config['dnsimple']['token'])
              account_id = dnsimple_client.identity.whoami.data.account.id
              delete_existing_challenge(nil, zone, domain, challenge)
              zone = get_domain(dnsimple_client, domain).name
              record_name = "#{challenge.record_name}.#{domain.split(zone).first.chomp('.')}"
              dnsimple_client.zones.create_record(account_id, zone, 
                                                  name: record_name, type: 'txt',
                                                  content: challenge.record_content, ttl: 60)
            elsif @config['dns_provider'].downcase.eql?('dyn')
              dyn = DynectRest.new(@config['dyn']['organization'],
                                   @config['dyn']['username'],
                                   @config['dyn']['token'], zone, true, true, 10)
              dyn.login
              delete_existing_challenge(dyn, zone, domain, challenge)
              rec = dyn.txt.fqdn("#{challenge.record_name}.#{domain}").ttl(60)
              rec['txtdata'] = challenge.record_content
              rec.save
              dyn.publish
            end

            wait_until_published(zone, challenge, domain)
            challenge.request_verification
            10.times do
              sleep(1)
              break if challenge.verify_status == 'valid'
            end
          rescue DynectRest::Exceptions::RequestFailed => e
            puts e.message
          end
        end
        raise ACMEError if challenge.verify_status != 'valid'
      rescue ACMEError
        retry
      end
    end
  end

  def run(domains)
    private_key = load_private_key(@config['private_key_path'])
    client = Acme::Client.new(private_key: private_key, endpoint: @config['endpoint'],
                              connection_options: { request: { open_timeout: 5, timeout: 5 } })
    do_acme(client)
    csr = Acme::Client::CertificateRequest.new(names: domains)
    certificate = client.new_certificate(csr)

    File.write("privkey.pem", certificate.request.private_key.to_pem)
    File.write("cert.pem", certificate.to_pem)
    File.write("chain.pem", certificate.chain_to_pem)
    File.write("fullchain.pem", certificate.fullchain_to_pem)

    # Ruby creates files that are double the size of OpenSSL, so we're going to trust `openssl` instead
    # pkcs12 = OpenSSL::PKCS12.create('passw0rd', 'kafkacerts',
    #                                 certificate.request.private_key,
    #                                 certificate.x509,
    #                                 certificate.x509_fullchain)
    # File.write("cert.p12", pkcs12.to_der)
    %x(openssl pkcs12 -export -in cert.pem -inkey privkey.pem -out server.p12 -name kafkacerts -CAfile fullchain.pem  -caname root -password pass:passw0rd)
    %x(yes | keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass passw0rd -alias kafkacerts)
  end

  def main
    read_config

    if File.exists?('cert.pem')
      begin
        raw = File.read "cert.pem" # DER- or PEM-encoded
        certificate = OpenSSL::X509::Certificate.new raw
        print "Certificate needs renewal?  "
        if certificate.not_after < Time.now + 1*(60*60*24*30)
          puts "Certificate expires in less than 1 month... renewing"
          run(@config['domains'])
        else
          puts "It does not."
        end
      rescue OpenSSL::X509::CertificateError
        puts "Invalid certificate... generating new one"
        run(@config['domains'])
      end
    else
      puts "Certificate does not exist... generating one"
      run(@config['domains'])
    end
  end
end

# AcmeDns.new.main
puts AcmeDns.new.get_zone('kafka01.chi2.shopify.com')

# echo 'abc123' > password
# openssl pkcs12 -export -in cert.pem -inkey privkey.pem -out server.p12 -name kafkacerts -CAfile fullchain.pem  -caname root -password stdin < password
# keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass abc123 -alias kafkacerts

