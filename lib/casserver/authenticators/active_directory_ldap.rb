# Slightly modified version of the LDAP authenticator for Microsoft's ActiveDirectory.
# The only difference is that the default_username_attribute for AD is 'sAMAccountName'
# rather than 'uid'.
class CASServer::Authenticators::ActiveDirectoryLDAP < CASServer::Authenticators::LDAP
  protected
  def default_username_attribute
    "sAMAccountName"
  end

  def extract_extra_attributes(ldap_entry)
    super(ldap_entry)
    objguid = @extra_attributes.keys.detect {|k| k.downcase == :objectguid}
    if objguid
      @extra_attributes[:guid] = @extra_attributes[objguid].first.unpack("H*").first
    end
    ldap_entry
  end
end
