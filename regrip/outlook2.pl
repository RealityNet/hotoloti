#------------------------------------------------------------------------------
# outlook2.pl
#   A step in the swampy MAPI
#   Plugin for RegRipper
#
# Change history
#   20130308 created
#   20130315 completed
#
# References
#   [1] http://www.windowsitpro.com/article/registry2/inside-mapi-profiles-45347
#   [2] http://msdn.microsoft.com/en-us/library/ms526356(v=exchg.10).aspx
#   [3] http://msdn.microsoft.com/en-us/library/ms526844%28v=exchg.10%29.aspx
#   [4] http://www.dimastr.com/redemption/enum_MAPITags.htm
#   [5] http://www.howto-outlook.com/howto/clearmru.htm
#
# Todo
#   Correlate with the exchange keys
#   Correlate with the Outlook catalog key
#
# copyright 2013 Realitynet System Solutions snc
# author: francesco picasso <francesco.picasso@gmail.com>
#------------------------------------------------------------------------------
package outlook2;
use strict;

use Parse::Win32Registry qw( unpack_windows_time
                             unpack_unicode_string
                             unpack_sid
                             unpack_ace
                             unpack_acl
                             unpack_security_descriptor );

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              osmask        => 22,
              version       => 20130315);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets MAPI (Outlook) settings";	
}
sub getDescr{}
sub getRefs {
    my %refs = (
        "Kevin Laahs - Inside MAPI Profiles" => 
            "http://www.windowsitpro.com/article/registry2/inside-mapi-profiles-45347",
		"MAPI Property Tags" =>
            "http://technet.microsoft.com/en-us/library/cc736412%28v=ws.10%29.aspx",
        "Microsoft Exchange Property Tags" =>
            "http://msdn.microsoft.com/en-us/library/ms526844%28v=exchg.10%29.aspx",
        "Outlook Redemption MAPI Tags" =>
            "http://www.dimastr.com/redemption/enum_MAPITags.htm",
        "Clear the Most Recently Used lists" =>
            "http://www.howto-outlook.com/howto/clearmru.htm"
    );
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %outlook_subkeys;

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching outlook2 v.".$VERSION);
    ::rptMsg("outlook2 v.".$VERSION);
    ::rptMsg("(".getHive().") ".getShortDescr()."\n");
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

    my $tab;
	my $key;
	my $key_path;
    my $outlook_key_path = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook';
    my $accounts_key_name = '9375CFF0413111d3B88A00104B2A6676';
    ::rptMsg("Working path is '$outlook_key_path'");
    ::rptMsg("");
    
    $key = $root_key->get_subkey($outlook_key_path);
    if (!$key) { ::rptMsg("Outlook key not found"); return; }
    my @subkeys = $key->get_list_of_subkeys();
    foreach my $s (@subkeys) { $outlook_subkeys{$s->get_name()} = $s; }

    # Accessing ACCOUNTS
    # This is the real "entry" point of the plugin
    # "Another well-known GUID is 9375CFF0413111d3B88A00104B2A6676, which is
    # used to hold details about all the accounts that are in use within the 
    # profile. Under this subkey, you will find a subkey per account.
    # For example, you'll typically find a subkey relating to the Outlook
    # Address Book (OAB) account, the Exchange account, an account for each PST
    # file that's been added to the profile, and any POP3/IMAP mail accounts
    # that are defined within the profile." Ref[1]
    $key_path = $outlook_key_path.'\\'.$accounts_key_name;
    $key = $root_key->get_subkey($key_path);
    if (!$key) { ::rptMsg("Accounts key '$accounts_key_name' not found"); return; }
    ::rptMsg("__key_ $accounts_key_name");
    ::rptMsg("_time_ ".gmtime($key->get_timestamp()));
    ::rptMsg("_desc_ accounts used within the profile");
    ::rptMsg("");
    
    delete($outlook_subkeys{$accounts_key_name});
    my @accounts_keys = $key->get_list_of_subkeys();
    foreach my $account_key (@accounts_keys)
    {
        $tab = '  ';
        ::rptMsg($tab.'---------------------------------------');
        ::rptMsg($tab.$account_key->get_name()." [".gmtime($account_key->get_timestamp())." UTC]");
        ::rptMsg($tab.'---------------------------------------');
        ::rptMsg($tab.get_unicode_string($account_key, 'Account Name'));
        ::rptMsg($tab.get_dword_string_long($account_key, 'MAPI provider'));
        ::rptMsg($tab.get_dword_string($account_key, 'Mini UID'));
        ::rptMsg($tab.get_unicode_string($account_key, 'Service Name'));
        ::rptMsg($tab.get_hex_string($account_key, 'Service UID'));

        my $service_id_key_name = $account_key->get_value('Service UID');
        if (!$service_id_key_name) { ::rptMsg(""); next; }
        
        ::rptMsg($tab.'\\');
        $tab = '   ';
        parse_service($root_key, $outlook_key_path, $service_id_key_name, $tab);
        $tab = '  ';
        ::rptMsg($tab.'/');

        ::rptMsg($tab.get_dword_string($account_key, 'XP Status'));
        ::rptMsg($tab.get_hex_string($account_key, 'XP Provider UID'));
        
        my $xp_id_key_name = $account_key->get_value('XP Provider UID');
        if (!$xp_id_key_name) { ::rptMsg(""); next; }
        ::rptMsg($tab.'\\');
        $tab = '   ';        
        parse_xp_service($root_key, $outlook_key_path, $xp_id_key_name, $tab);
        $tab = '  ';
        ::rptMsg($tab.'/');

        ::rptMsg("");
    }
    
    # Global Profile Section
    $tab = '';
    ::rptMsg("");
    my $global_profile_key_name = '13dbb0c8aa05101a9bb000aa002fc45a';
    $key_path = $outlook_key_path.'\\'.$global_profile_key_name;
    my $global_profile_key = $root_key->get_subkey($key_path);
    if (!$global_profile_key) { ::rptMsg("Global profile key not found!"); }
    else
    {
        delete($outlook_subkeys{$global_profile_key_name});
        ::rptMsg("__key_ $global_profile_key_name");
        ::rptMsg("_time_ ".gmtime($global_profile_key->get_timestamp()));
        ::rptMsg("_desc_ global profile section (data related to Profile)");
        ::rptMsg("");
        $tab = ' ';
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036600', 'Profile Version'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036601', 'Config Flags'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036604', 'Connect Flags'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036605', 'Transport Flags'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036606', 'UI State'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '00036619', 'Auth Package'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e6603', 'User'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e6602', 'Home Server'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e6608', 'Unresolved Server'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e6612', 'Home Server DN'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f662a', 'Internet Content'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e667c', 'MOAB GUID'));
        ::rptMsg(  $tab.get_ascii_string($global_profile_key, '001e6750', '*UNKNOWN*'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f3001', 'Display Name'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f6607', 'Unresolved Name'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f6610', 'OST Path'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f6620', '*UNKNOWN*'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f663d', '*UNKNOWN*'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f6641', '*UNKNOWN*'));
        ::rptMsg($tab.get_unicode_string($global_profile_key, '001f667b', '*UNKNOWN*'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '004067e2', 'Transmission time'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '00146686', 'Address timestamp'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '00406642', 'Oldest deleted'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '00406638', '*UNKNOWN* time'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '004065ed', '*UNKNOWN* time'));
        ::rptMsg(  $tab.get_windows_time($global_profile_key, '00406628', '*UNKNOWN* time'));
        
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '01023d00', 'Store Providers'));
        my $provider_id_key_name = $global_profile_key->get_value('01023d00');
        if (!$provider_id_key_name) { return; }
        ::rptMsg($tab.'\\');
        $tab = '  ';
        parse_provider($root_key, $outlook_key_path, $provider_id_key_name, $tab);
        $tab = ' ';
        ::rptMsg($tab.'/');
    
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '01023d01', 'AB Providers'));
        my $ab_provider_id_key_name = $global_profile_key->get_value('01023d01');
        if (!$ab_provider_id_key_name) { return; }
        ::rptMsg($tab.'\\');
        $tab = '  ';
        parse_provider($root_key, $outlook_key_path, $ab_provider_id_key_name, $tab, 'ab');
        $tab = ' ';
        ::rptMsg($tab.'/');
        
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '01023d02', 'Transport Providers'));
        ::rptMsg(    $tab.get_hex_string($global_profile_key, '01023d0c', 'Service UID'));
    }
    
    # MUID_PROFILE_INSTANCE
	# Well known section in a profile which contains a property (PR_SEARCH_KEY) which is unique
	# for any given profile.  Applications and providers can depend on this value as being
	# different for each unique profile. */
    ::rptMsg("\n");
    my $muid_profile_instance_key_name = '8503020000000000c000000000000046';
    $key_path = $outlook_key_path.'\\'.$muid_profile_instance_key_name;
    my $muid_profile_instance_key = $root_key->get_subkey($key_path);
    if (!$muid_profile_instance_key) { ::rptMsg("MUID profile key not found!"); }
    else
    {
        delete($outlook_subkeys{$muid_profile_instance_key_name});
        ::rptMsg("__key_ $muid_profile_instance_key_name");
        ::rptMsg("_time_ ".gmtime($muid_profile_instance_key->get_timestamp()));
        ::rptMsg("_desc_ MUID profile section");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }
    
    # MUIDEMSAB profile section
    ::rptMsg("\n");
    my $muidemsab_profile_key_name = 'dca740c8c042101ab4b908002b2fe182';
    $key_path = $outlook_key_path.'\\'.$muidemsab_profile_key_name;
    my $muidemsab_profile_key = $root_key->get_subkey($key_path);
    if (!$muidemsab_profile_key) { ::rptMsg("MUIDEMSAB key not found!"); }
    else
    {
        delete($outlook_subkeys{$muidemsab_profile_key_name});
        ::rptMsg("__key_ $muidemsab_profile_key_name");
        ::rptMsg("_time_ ".gmtime($muidemsab_profile_key->get_timestamp()));
        ::rptMsg("_desc_ MUIDEMSAB section");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }
    
    # [Dialup Networking]
    # SectionGUID=5acf76a3665511cea39a00aa004acafa
    # DialConnection=PT_BOOLEAN,0x6717
    #;       -- A boolean value indicating whether to dial the Exchange
    #;       server or use the existing connection.
    #;       If set to TRUE, Outlook will dial using the RAS profile choosen.
    #;       If FALSE, Outlook will use the existing connection.
    # DomainName=PT_STRING8,0x67f0
    # Password=PT_BINARY,0x67f1
    # UserName=PT_STRING8,0x67f2
    # ConnectionName=PT_STRING8,0x6710
    ::rptMsg("\n");
    my $dialup_networking_key_name = '5acf76a3665511cea39a00aa004acafa';
    $key_path = $outlook_key_path.'\\'.$dialup_networking_key_name;
    my $dialup_networking_key = $root_key->get_subkey($key_path);
    if (!$dialup_networking_key) { ::rptMsg("Dialup Networking key not found!"); }
    else
    {
        delete($outlook_subkeys{$dialup_networking_key_name});
        ::rptMsg("__key_ $dialup_networking_key_name");
        ::rptMsg("_time_ ".gmtime($dialup_networking_key->get_timestamp()));
        ::rptMsg("_desc_ DialUp Networking section");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }
    
    # todo 42acdf40ca5b11cdb7ba00aa003cf7f1
   ::rptMsg("\n");
    my $unknown_key_name = '42acdf40ca5b11cdb7ba00aa003cf7f1';
    $key_path = $outlook_key_path.'\\'.$unknown_key_name;
    my $unknown_key = $root_key->get_subkey($key_path);
    if (!$unknown_key) { ::rptMsg("key '$unknown_key_name' not found!"); }
    else
    {
        delete($outlook_subkeys{$unknown_key_name});
        ::rptMsg("__key_ $unknown_key_name");
        ::rptMsg("_time_ ".gmtime($unknown_key->get_timestamp()));
        ::rptMsg("_desc_ no description available");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }

   # todo 9207f3e0a3b11019908b08002b2a56c2
   ::rptMsg("\n");
    my $unknown2_key_name = '9207f3e0a3b11019908b08002b2a56c2';
    $key_path = $outlook_key_path.'\\'.$unknown2_key_name;
    my $unknown2_key = $root_key->get_subkey($key_path);
    if (!$unknown2_key) { ::rptMsg("key '$unknown2_key_name' not found!"); }
    else
    {
        delete($outlook_subkeys{$unknown2_key_name});
        ::rptMsg("__key_ $unknown2_key_name");
        ::rptMsg("_time_ ".gmtime($unknown2_key->get_timestamp()));
        ::rptMsg("_desc_ no description available");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }

    # Outlook settings and artifacts
   ::rptMsg("\n");
    my $outlook_key_name = '0a0d020000000000c000000000000046';
    $key_path = $outlook_key_path.'\\'.$outlook_key_name;
    my $outlook_key = $root_key->get_subkey($key_path);
    if (!$outlook_key) { ::rptMsg("Outlook key not found!"); }
    else
    {
        delete($outlook_subkeys{$outlook_key_name});
        ::rptMsg("__key_ $outlook_key_name");
        ::rptMsg("_time_ ".gmtime($outlook_key->get_timestamp()));
        ::rptMsg("_desc_ settings and artifacts related to Outlook");
        ::rptMsg('');
        ::rptMsg('  *** TODO ***');
    }

    $tab = '';
    ::rptMsg("\n");
    ::rptMsg("Outlook subkeys not direclty linked (WARNING: PARTIAL, plugin not complete!");
    foreach my $okey_name (keys %outlook_subkeys)
    {
        ::rptMsg($tab."$okey_name");
    }
}

sub parse_service
{
    my $root_key = shift;
    my $outlook_key_path = shift;
    my $ids = shift;
    my $tab = shift;

    $ids = $ids->get_raw_data();
    my $num_of_ids = length($ids) / 16;
    # Never seen more than one, contact author.
    if ($num_of_ids > 1) { ::rptMsg($tab."WARNING: expected only 1 Service ID, found $num_of_ids");}
    
    my $service_id_key_name = join('', unpack('(H2)16', $ids));
    my $service_id_key = $root_key->get_subkey($outlook_key_path.'\\'.$service_id_key_name);
    if (!$service_id_key) { ::rptMsg($tab.'WARNING: Service UID not found in Outlook path!'); return; }

    ::rptMsg($tab.$service_id_key_name.' ['.gmtime($service_id_key->get_timestamp()).' UTC]');
    ::rptMsg($tab.'--------------------------------');
        
    delete($outlook_subkeys{$service_id_key_name});

    ::rptMsg($tab.get_unicode_string($service_id_key, '001f3001', 'Display Name'));
    ::rptMsg($tab.get_unicode_string($service_id_key, '001f3d0a', 'Service DLL Name'));
    ::rptMsg($tab.get_unicode_string($service_id_key, '001f3d0b', 'DLL Entry Point'));
    ::rptMsg($tab.get_hex_string($service_id_key, '01023d00', 'Store provider'));
    
    my $provider_id_key_name = $service_id_key->get_value('01023d00');
    if (!$provider_id_key_name) { return; }
        
    ::rptMsg($tab.'\\');
    $tab = '    ';
    parse_provider($root_key, $outlook_key_path, $provider_id_key_name, $tab);
    $tab = '   ';
    ::rptMsg($tab.'/');
}

sub parse_provider
{
    my $root_key = shift;
    my $outlook_key_path = shift;
    my $ids = shift;
    my $tab = shift;
    my $type = shift; # if defined means AB

    $ids = $ids->get_raw_data();
    my $num_of_ids = length($ids) / 16;
    for (my $i = 0; $i < $num_of_ids; $i += 1)
    {
        my $provider_id_key_name = join('', unpack('(H2)16', $ids));
        $ids = substr($ids, 16);
        my $provider_id_key = $root_key->get_subkey($outlook_key_path.'\\'.$provider_id_key_name);
        if (!$provider_id_key)
        {
            ::rptMsg($tab.'WARNING: Provider ID not found in Outlook path!');
            if (($i+1) != $num_of_ids) { ::rptMsg($tab.'+'); }
            next;
        }       
        ::rptMsg($tab.$provider_id_key_name.' ['.gmtime($provider_id_key->get_timestamp()).' UTC]');
        ::rptMsg($tab.'--------------------------------');
        
        delete($outlook_subkeys{$provider_id_key_name});
        
        ::rptMsg($tab.get_unicode_string($provider_id_key, '001f3001', 'Display Name'));
        ::rptMsg($tab.get_unicode_string($provider_id_key, '001f3006', 'Provider Display'));
        ::rptMsg($tab.get_unicode_string($provider_id_key, '001f300a', 'Provider DLL Name'));
        ::rptMsg($tab.get_unicode_string($provider_id_key, '001f3d09', 'Service Name'));
        
        ::rptMsg(    $tab.get_hex_string($provider_id_key, '01023d0c', 'Service UID'));
        
        if ($type)
        {
        }
        else
        {
            ::rptMsg($tab.get_ascii_string($provider_id_key, '001e660b', 'Profile Mailbox'));
            ::rptMsg($tab.get_ascii_string($provider_id_key, '001e660c', 'Profile Server'));
            ::rptMsg($tab.get_ascii_string($provider_id_key, '001e6614', 'Profile Server DN'));
            ::rptMsg($tab.get_unicode_string($provider_id_key, '001f6700', 'PST Path'));
        }

        if (($i+1) != $num_of_ids) { ::rptMsg($tab.'+'); }
    }
}

sub parse_xp_service
{
    my $root_key = shift;
    my $outlook_key_path = shift;
    my $ids = shift;
    my $tab = shift;

    $ids = $ids->get_raw_data();
    my $num_of_ids = length($ids) / 16;
    for (my $i = 0; $i < $num_of_ids; $i += 1)
    {
        my $service_id_key_name = join('', unpack('(H2)16', $ids));
        $ids = substr($ids, 16);
        my $service_id_key = $root_key->get_subkey($outlook_key_path.'\\'.$service_id_key_name);
        if (!$service_id_key)
        {
            ::rptMsg($tab.'WARNING: XP Service UID not found in Outlook path!');
            if (($i+1) != $num_of_ids) { ::rptMsg($tab.'+'); }
            next;
        }       
        ::rptMsg($tab.$service_id_key_name.' ['.gmtime($service_id_key->get_timestamp()).' UTC]');
        ::rptMsg($tab.'--------------------------------');
        
        delete($outlook_subkeys{$service_id_key_name});

        ::rptMsg($tab.get_ascii_string($service_id_key, '001e660b', 'User'));
        ::rptMsg($tab.get_ascii_string($service_id_key, '001e6614', 'Server'));
        ::rptMsg($tab.get_ascii_string($service_id_key, '001e660c', 'Server Name'));
        ::rptMsg($tab.get_unicode_string($service_id_key, '001f3001', 'Display Name'));
        ::rptMsg($tab.get_unicode_string($service_id_key, '001f3006', 'Provider Display'));
        ::rptMsg($tab.get_unicode_string($service_id_key, '001f300a', 'Provider DLL Name'));

        if (($i+1) != $num_of_ids) { ::rptMsg($tab.'+'); }
    }
}

sub get_windows_time
{
    my $key = shift;
    my $value = shift;
    my $value_desc = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = gmtime(unpack_windows_time($data->get_raw_data())).' UTC';}
    else { $data = '<no value>'; }
    if (!$value_desc) { return sprintf("%-24s %s", $value.':', $data); }
    return sprintf("%s %-24s %s", $value, '['.$value_desc.']:', $data);    
}

sub get_hex_string
{
    my $key = shift;
    my $value = shift;
    my $value_desc = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = join('', unpack('(H2)*', $data->get_raw_data()));}
    else { $data = '<no value>'; }
    if (!$value_desc) { return sprintf("%-24s %s", $value.':', $data); }
    return sprintf("%s %-24s %s", $value, '['.$value_desc.']:', $data);    
}

sub get_dword_string
{
    my $key = shift;
    my $value = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = $data->get_data(); $data = sprintf('0x%08X', $data); }
    else { $data = '<no value>'; }
    return sprintf("%-24s %s", $value.':', $data);
}

sub get_dword_string_long
{
    my $key = shift;
    my $value = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = $data->get_data(); $data = sprintf('%u [0x%08X]', $data, $data); }
    else { $data = '<no value>'; }
    return sprintf("%-24s %s", $value.':', $data);
}

sub get_unicode_string
{
    my $key = shift;
    my $value = shift;
    my $value_desc = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = unpack_unicode_string($data->get_data()); }
    else { $data = '<no value>'; }
    if (!$value_desc) { return sprintf("%-24s %s", $value.':', $data); }
    return sprintf("%s %-24s %s", $value, '['.$value_desc.']:', $data);
}

sub get_ascii_string
{
    my $key = shift;
    my $value = shift;
    my $value_desc = shift;
    my $data = $key->get_value($value);
    if ($data) { $data = $data->get_data(); } else { $data = '<no value>'; }
    if (!$value_desc) { return sprintf("%-24s %s", $value.':', $data); }
    return sprintf("%s %-24s %s", $value, '['.$value_desc.']:', $data);
}

1;