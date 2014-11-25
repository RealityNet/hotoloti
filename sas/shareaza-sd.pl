#-----------------------------------------------------------------------------
# shareaza-sd.pl 
# parser of shareaza "partial.sd" file
# Currenlty in ALPHA version.
# Output goes to STDOUT
#
# Change History
#   20121119 * [fpi] created
#
# TODO
#   todo :)
#
# copyright 2012 Francesco Picasso <francesco.picasso@gmail.com>
#-----------------------------------------------------------------------------

use strict;
use warnings;
use Getopt::Long qw( :config no_ignore_case );
use Encode;

#------------------------------------------------------------------------------
# CDownload Serialize (SDL and version)
# --> CDownloadWithExtras ( todo )
# -----> CDownloadWithSearch (nothing)
# ----------> CDownloadWithTiger ( todo )
# ---------------> CDownloadWithTorrent ( todo )
# --------------------> CDownloadWithFile ( todo )
# -------------------------> CDownloadWithTransfers (nothing)
# -------------------------------> CDownloadWithSources (DONE)
# -------------------------------------> CDownloadBase (DONE)
#------------------------------------------------------------------------------

my $VERSION = '0.1.20120621';

my %config;
Getopt::Long::Configure( "prefix_pattern=(-|\/)" );
GetOptions( \%config, qw( file|f=s help|h ) );

if ($config{help} || !%config) { usage(); exit; }
die "MISSING -file|-f [filename]\n" if not $config{file};

my $file = $config{file} || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);
my $file_size = ( stat( $file ) )[ 7 ];

#------------------------------------------------------------------------------

my $data;
my $mini_header_len = 4;
my $str_len;
my $temp;

open( SDFH, "<", $file ) or die "Unable to open '$file':$!\n";
binmode( SDFH );
read( SDFH, $data, $file_size );
close( SDFH );

#------------------------------------------------------------------------------

my ( $magic, $version ) = unpack( "a3V", $data );
$data = substr( $data, 7 );

print "MAGIC:                          $magic\n";
print "VERSION:                        $version\n";

die "ERROR: magic value 'SDL' not found\n" unless ( $magic eq 'SDL' );
die "ERROR: actually only version greater than 11 is supported\n" unless ( $version >= 11 );
die "ERROR: actually only version less or equal to 42 is supported\n" unless ( $version <= 42 );

#------------------------------------------------------------------------------
# file name

$str_len = read_mini_header( $data );
$data = substr( $data, $mini_header_len );

$temp = substr( $data, 0, $str_len * 2 );
my $file_name = decode( 'UCS-2LE', $temp );
$data = substr( $data, $str_len * 2 );

print "FILE NAME:                      $file_name\n";

#------------------------------------------------------------------------------
# search terms

my $search_terms;

if ( $version >= 33 )
{
    $str_len = read_mini_header( $data );
    $data = substr( $data, $mini_header_len );
    
    if ( $str_len ) {
        $temp = substr( $data, 0, $str_len * 2 );
        $search_terms = decode( 'UCS-2LE', $temp );
        $data = substr( $data, $str_len * 2 );
    }
    else {
        $search_terms = "<none present>";
    }
}
else {
    $search_terms = "<not expected in this version>";
}

print "SEARCH TERMS:                   $search_terms\n";

#------------------------------------------------------------------------------
# file length

if ( $version >= 29 )
{
    my ( $file_len_low, $file_len_high ) = unpack( 'VV', $data );
    $data = substr( $data, 8 );

    print "FILE LENGTH (low 32bits):       $file_len_low\n";
    print "FILE LENGTH (high 32bits):      $file_len_high\n";
}
else
{
    my $file_len = unpack( 'V', $data );
    $data = substr( $data, 4 );
    
    print "FILE LENGTH:                    $file_len\n";
}

#------------------------------------------------------------------------------
# hash SHA1

print "--------------------------------\n";
my $sha1_valid_num = unpack( 'V', $data );
$data = substr( $data, 4 );

my $sha1_valid = 'no';
$sha1_valid = 'yes' if $sha1_valid_num;

my $sha1 = '';
if ( $sha1_valid_num )
{
    $sha1 = unpack( 'H40', $data );
    $data = substr( $data, 20 );
}

my $sha1_trust_num = unpack( 'V', $data );
$data = substr( $data, 4 );

my $sha1_trust = 'no';
$sha1_trust = 'yes' if $sha1_trust_num;

print "Hash SHA1 valid:                $sha1_valid\n";
print "Hash SHA1:                      $sha1\n";
print "Hash SHA1 Trusted:              $sha1_trust\n";

#------------------------------------------------------------------------------
# hash TIGER

print "--------------------------------\n";
my $tiger_valid_num = unpack( 'V', $data );
$data = substr( $data, 4 );

my $tiger_valid = 'no';
$tiger_valid = 'yes' if $tiger_valid_num;

my $tiger = '';
if ( $tiger_valid_num )
{
    $tiger = unpack( 'H48', $data );
    $data = substr( $data, 24 );
}

my $tiger_trust_num = unpack( 'V', $data );
$data = substr( $data, 4 );

my $tiger_trust = 'no';
$tiger_trust = 'yes' if $tiger_trust_num;

print "Hash TIGER valid:               $tiger_valid\n";
print "Hash TIGER:                     $tiger\n";
print "Hash TIGER Trusted:             $tiger_trust\n";

#------------------------------------------------------------------------------
# hash MD5

print "--------------------------------\n";
my $md5_valid_num;
my $md5_valid;
my $md5_trust_num;
my $md5_trust;
my $md5;

if ( $version >= 22 )
{
    $md5_valid_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $md5_valid = 'no';
    $md5_valid = 'yes' if $md5_valid_num;

    $md5 = '';
    if ( $md5_valid_num )
    {
        $md5 = unpack( 'H32', $data );
        $data = substr( $data, 16 );
    }

    $md5_trust_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $md5_trust = 'no';
    $md5_trust = 'yes' if $md5_trust_num;

    print "Hash MD5 valid:                 $md5_valid\n";
    print "Hash MD5:                       $md5\n";
    print "Hash MD5 Trusted:               $md5_trust\n";
}
else {
    print "Hash MD5:                       <not expected in this version>\n";
}

#------------------------------------------------------------------------------
# hash EDONKEY

print "--------------------------------\n";
my $edonkey_valid_num;
my $edonkey_valid;
my $edonkey_trust_num;
my $edonkey_trust;
my $edonkey;

if ( $version >= 13 )
{
    $edonkey_valid_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $edonkey_valid = 'no';
    $edonkey_valid = 'yes' if $edonkey_valid_num;

    $edonkey = '';
    if ( $edonkey_valid_num )
    {
        $edonkey = unpack( 'H32', $data );
        $data = substr( $data, 16 );
    }

    $edonkey_trust_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $edonkey_trust = 'no';
    $edonkey_trust = 'yes' if $edonkey_trust_num;

    print "Hash EDONKEY valid:             $edonkey_valid\n";
    print "Hash EDONKEY:                   $edonkey\n";
    print "Hash EDONKEY Trusted:           $edonkey_trust\n";
}
else {
    print "Hash EDONKEY:                   <not expected in this version>\n";
}

#------------------------------------------------------------------------------
# hash BTH

print "--------------------------------\n";
my $bth_valid_num;
my $bth_valid;
my $bth_trust_num;
my $bth_trust;
my $bth;

if ( $version >= 37 )
{
    $bth_valid_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $bth_valid = 'no';
    $bth_valid = 'yes' if $bth_valid_num;

    $bth = '';
    if ( $bth_valid_num )
    {
        $bth = unpack( 'H40', $data );
        $data = substr( $data, 20 );
    }

    $bth_trust_num = unpack( 'V', $data );
    $data = substr( $data, 4 );

    $bth_trust = 'no';
    $bth_trust = 'yes' if $bth_trust_num;

    print "Hash BitTorrent valid:          $bth_valid\n";
    print "Hash BitTorrent:                $bth\n";
    print "Hash BitTorrent Trusted:        $bth_trust\n";
}
else {
    print "Hash BitTorrent:                <not expected in this version>\n";
}

#------------------------------------------------------------------------------
# SOURCE

print "--------------------------------\n";
my $num_src = unpack( 'v', $data );
$data = substr( $data, 2 );

print "NUM of SOURCES:                 $num_src\n";

for ( $temp = 0; $temp < $num_src; $temp++ ) {
    print "\nDATA SOURCE                     [$temp]\n";
    if ( $version >= 21 ) {
        read_source( \$data, $version );
    }
    else {
        die "Reading sources from version < 21 not yet implented\n";
    }
}

#------------------------------------------------------------------------------
# subs
#------------------------------------------------------------------------------

sub read_source
{
    my $refdata = shift;
    my $version = shift;
    my $temp;
    
    my $ds_name_len = read_mini_header( $$refdata );
    $$refdata = substr( $$refdata, 4 );
    $temp = substr( $$refdata, 0, $ds_name_len * 2 );
    my $ds_name = decode( 'UCS-2LE', $temp );
    $$refdata = substr( $$refdata, $ds_name_len * 2 );
    print "DATA SOURCE URL:                $ds_name\n";
    
    my $protocol_id = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    
    print "Protocol:                       $protocol_id\n";
    
    my %protocol_name = (
        -1  =>  'PROTOCOL_ANY',
        0   =>  'PROTOCOL_NULL',
        1   =>  'PROTOCOL_G1',
        2   =>  'PROTOCOL_G2',
        3   =>  'PROTOCOL_ED2K',
        4   =>  'PROTOCOL_HTTP',
        5   =>  'PROTOCOL_FTP',
        6   =>  'PROTOCOL_BT',
        7   =>  'PROTOCOL_KAD',
        8   =>  'PROTOCOL_DC',
        9   =>  'PROTOCOL_LAST'
    );
    print "Protocol Name:                  ".$protocol_name{$protocol_id}."\n";
    
    my $guid_valid_num;
    my $guid_valid;
    my $guid;

    $guid_valid_num = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );

    $guid_valid = 'no';
    $guid_valid = 'yes' if $guid_valid_num;

    $guid = '';
    if ( $guid_valid_num )
    {
        $guid = unpack( 'H32', $$refdata );
        $$refdata = substr( $$refdata, 16 );
    }
    print "GUID valid:                     $guid_valid\n";
    print "GUID value:                     $guid\n";
   
    my $ds_port = unpack( 'v', $$refdata );
    $$refdata = substr( $$refdata, 2 );
    print "PORT:                           $ds_port\n";
      
    if ( $ds_port != 0 ) {
        # only IPv4 TBR
        my ( $ip1, $ip2, $ip3, $ip4 ) = unpack( 'CCCC', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "IP ADDRESS:                     $ip1.$ip2.$ip3.$ip4\n";   
    }
    
    my $server_port = unpack( 'v', $$refdata );
    $$refdata = substr( $$refdata, 2 );   
    print "SERVER PORT:                    $server_port\n";
    
    if ( $server_port != 0 ) {
        # only IPv4 TBR
        my ( $ip1, $ip2, $ip3, $ip4 ) = unpack( 'CCCC', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "SERVER IP ADDRESS:              $ip1.$ip2.$ip3.$ip4\n";   
    }
    
    my $server_name_len  = read_mini_header( $$refdata );
    $$refdata = substr( $$refdata, 4 );
    $temp = substr( $$refdata, 0, $server_name_len * 2 );
    my $server_name = decode( 'UCS-2LE', $temp );
    $$refdata = substr( $$refdata, $server_name_len * 2 );
    print "SERVER NAME:                    $server_name\n";
    
    my $index = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "INDEX:                          $index\n";
    
    my $hash_auth = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "HASH AUTH (boolean 0|1):        $hash_auth\n";

    my $use_sha1 = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Use SHA1 (boolean 0|1):         $use_sha1\n";
    
    my $use_tiger = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Use TIGER (boolean 0|1):        $use_tiger\n";

    my $use_edonkey = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Use EDONKEY (boolean 0|1):      $use_edonkey\n";
    
    if ( $version >= 37 ) 
    {
        my $use_bith = unpack( 'V', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "Use BITHash (boolean 0|1):      $use_bith\n";

        my $use_md5 = unpack( 'V', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "Use MD5 (boolean 0|1):          $use_md5\n";    
    }
    
    my $server_type = get_sd_string( $refdata );
    print "Server Type Name:               $server_type\n";
    
    my $nickname = '';
    if ( $version >= 24 )
    {
        $nickname = get_sd_string( $refdata );
        print "Nickname:                       $nickname\n";
    }
    
    my $country_code = '';
    if ( $version >= 36 ) {
        $country_code = get_sd_string( $refdata );
        print "Country Code:                   $country_code\n";
    }
    
    my $country_name = '';
    if ( $version >= 38 ) {
        $country_name = get_sd_string( $refdata );
        print "Country Name:                   $country_name\n";
    }
    
    my $speed = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "SPEED:                          $speed\n";
    
    my $push_only = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Push Only (boolean 0|1):        $push_only\n";
    
    my $close_conn = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Close Connection (boolean 0|1): $close_conn\n";
    
    my $read_content = unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    print "Read Content (boolean 0|1):     $read_content\n";
    
    my $file_time_low =  unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    my $file_time_high =  unpack( 'V', $$refdata );
    $$refdata = substr( $$refdata, 4 );
    my $last_seen = get_time( $file_time_low, $file_time_high );
    print "Last Seen UTC:                  ".gmtime($last_seen)."\n";
    
    # TBR TODO
    # SerializeIn2( ar, m_oPastFragments, nVersion );
    # skipping 2 bytes...
    my $frag_count = unpack( 'v', $$refdata );
    print "Number of past fragments:       $frag_count\n";
    $$refdata = substr( $$refdata, 2 );
    
    if ( $frag_count )
    {
        print "skipping fragments\n";
        for ( $temp = 0; $temp < $frag_count; $temp++ ) {
            $$refdata = substr( $$refdata, 8 ); # begin
            $$refdata = substr( $$refdata, 8 ); # length
        }
    }
        
    if ( $version >= 39 ) {
        my $client_extended = unpack( 'V', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "Client Extended (boolean 0|1):  $client_extended\n";
    }
    
    if ( $version >= 42 ) {
        my $meta_ignore = unpack( 'V', $$refdata );
        $$refdata = substr( $$refdata, 4 );
        print "Meta Ignore (boolean 0|1):      $meta_ignore\n";
    }
}

#------------------------------------------------------------------------------

sub get_sd_string
{
    my $refdata = shift;
    
    my $len = read_mini_header( $$refdata );
    $$refdata = substr( $$refdata, 4 );
    
    my $temp = substr( $$refdata, 0, $len * 2 );
    
    my $name = decode( 'UCS-2LE', $temp );
    
    $$refdata = substr( $$refdata, $len * 2 );
    
    return $name;
}

#------------------------------------------------------------------------------
    
sub read_mini_header
{
    my $ldata = shift;
    my ( $h1, $h2, $h3, $len ) = unpack( "CCCC", $ldata );
    die "ERROR: not found 'header' FF-FE-FF\n"
        unless ( $h1 == 0xFF and $h2 == 0xFE and $h3 == 0xFF );
    return $len;
}

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (2 DWORDS) to Unix time, to be passed
# to gmtime() or localtime()
#
# From Harlan Carvey:
# The code was borrowed from Andreas Schuster's excellent work
#-------------------------------------------------------------

sub get_time($$)
{
	my $lo = $_[0];
	my $hi = $_[1];
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}

#------------------------------------------------------------------------------

sub usage
{
	print<< "EOT";
    
shareaza-sd v.$VERSION
parser for shareaza partial.sd file
Currently in ALPHA version.
Parameters:

  -f|file    [file]..............input file name

copyright 2012 Francesco Picasso
EOT
}

#------------------------------------------------------------------------------
