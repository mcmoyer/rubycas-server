# encoding: UTF-8
require 'spec_helper'

describe "CASServer::Authenticators::ActiveDirectoryLDAP" do
  before do
    pending("Skip LDAP test due to missing gems") unless gem_available?("net-ldap")

    if $LOG.nil?
      load_server('default_config') # a lazy way to make sure the logger is set up
    end
    # Trigger autoload to load net ldap
    CASServer::Authenticators::ActiveDirectoryLDAP

    @ldap_entry = Net::LDAP::Entry.new

    @values = {
      objectguid: ["K1i\xBB\xC3\xC3\xF0F\xA4\xC8:U\x12+\xCC\xDA"],
      full_name: ['Bilbo Baggins'],
      address: ['The Shire']
    }
    
    @guid = "4b3169bbc3c3f046a4c83a55122bccda"

    @ldap_entry.instance_variable_set(:@myhash, @values)

    @ldap = mock(Net::LDAP)
    @ldap.stub!(:host=)
    @ldap.stub!(:port=)
    @ldap.stub!(:encryption)
    @ldap.stub!(:bind_as).and_return(true)
    @ldap.stub!(:authenticate).and_return(true)
    @ldap.stub!(:search).and_return([@ldap_entry])

    Net::LDAP.stub!(:new).and_return(@ldap)
  end

  describe '#validate' do

    it 'validate with preauthentication and with extra attributes' do
      auth = CASServer::Authenticators::ActiveDirectoryLDAP.new

      auth_config = HashWithIndifferentAccess.new(
        :ldap => {
          :host => "ad.example.net",
          :port => 389,
          :base => "dc=example,dc=net",
          :filter => "(objectClass=person)",
          :auth_user => "authenticator",
          :auth_password => "itsasecret"
        },
        :extra_attributes => [:full_name, :address, :objectguid]
      )

      auth.configure(auth_config.merge('auth_index' => 0))
      auth.validate(
        :username => 'validusername',
        :password => 'validpassword',
        :service =>  'test.service',
        :request => {}
      ).should == true

      auth.extra_attributes.should == @values.merge(guid: @guid)

    end

  end
end
