#! c:\perl\bin\perl.exe
#------------------------------------------------------------------------------
# sdbp.pl 
# Tool to parse binary Windows Security Descriptors
#
# Version 0.2
#
# Changes
#   20111125 [fpi] % created
#   20111129 [fpi] * bugfix, wrong arguments when using  rptRights
#
# References
#	http://source.winehq.org/source/include/winnt.h
#   http://technet.microsoft.com/en-us/query/aa374847
#   http://technet.microsoft.com/en-us/query/aa374892
#   http://msdn.microsoft.com/en-us/library/windows/desktop/aa374919%28v=vs.85%29.aspx
#
# TODO
#   - cbAceAllowObj TO BE COMPLETED
#   - the first two bytes of third SID files (big endian 4bits) are set to 0
#     due to no external lib dependacies (usuallu they are 0, to be verified..)
#   - manage more ACE_TYPEs
#
# copyright 2011 F.Picasso, francesco.picasso@gmail.com
#------------------------------------------------------------------------------
use strict;

my $VERSION = "0.2";

#------------------------------------------------------------------------------

my %ACE_TYPE = (
    0  => \&cbAceAllow,     # ACCESS_ALLOWED_ACE_TYPE
    1  => \&cbAceDeny,      # ACCESS_DENIED_ACE_TYPE
    2  => \&cbAceAudit,     # SYSTEM_AUDIT_ACE_TYPE
    3  => \&cbAceAlarm,     # SYSTEM_ALARM_ACE_TYPE
    #define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
    5  => \&cbAceAllowObj   # ACCESS_ALLOWED_OBJECT_ACE_TYPE
    #define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
    #define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
    #define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
    #define ACCESS_MAX_MS_ACE_TYPE                  (0x8)
    #define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
    #define ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
    #define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
    #define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
    #define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
    #define SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
    #define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
    #define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)
    #define SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)
    #define ACCESS_MAX_MS_V5_ACE_TYPE               (0x11)
);

my %ACE_TYPE_STRING = (
    0  => 'ACCESS ALLOWED',
    1  => 'ACCESS DENIED',
    2  => 'SYSTEM AUDIT',
    3  => 'SYSTEM ALARM'
);

my %ACE_FLAGS = (
    0x1     => 'OBJECT_INHERIT',
    0x2     => 'CONTAINER_INHERIT',
    0x4     => 'NO_PROPAGATE_INHERIT',
    0x8     => 'INHERIT_ONLY',
    0x10    => 'INHERITED',
    0x40    => 'SUCCESS',
    0x80    => 'FAILURE'
);
my @ACE_FLAGS_VALUE = ( 0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x80 );

my %GENERIC_MASK = (
    0x80000000 => 'GENERIC READ',
    0x40000000 => 'GENERIC WRITE',
    0x20000000 => 'GENERIC EXECUTE',
    0x10000000 => 'GENERIC ALL'
);

my %STANDARD_MASK = (
    0x00010000 => 'DELETE',
    0x00020000 => 'READ CONTROL',
    0x00040000 => 'WRITE DAC',
    0x00080000 => 'WRITE OWNER',
    0x00100000 => 'SYNCHRONIZE'
);

my $ACCESS_SECURITY_MASK = 0x01000000;
my $MAXIMUM_ALLOWED_MASK = 0x02000000;

my %EVENT_SPECIFIC_MASK = (
    0x0001 => 'EVENT QUERY STATE',
    0x0002 => 'EVENT MODIFY STATE'
);

my %SEMAPHORE_SPECIFIC_MASK = (
    0x0002 => 'SEMAPHORE MODIFY STATE'
);

my %MUTEX_SPECIFIC_MASK = (
    0x0001 => 'MUTEX MODIFY STATE'
);

my %JOB_SPECIFIC_MASK = (
    0x0001 => 'JOB OBJECT ASSIGN PROCESS',
    0x0002 => 'JOB OBJECT SET ATTRIBUTES',
    0x0004 => 'JOB OBJECT QUERY',
    0x0008 => 'JOB OBJECT TERMINATE',
    0x0010 => 'JOB OBJECT SET SECURITY ATTRIBUTES'
);

my %TIMER_SPECIFIC_MASK = (
    0x0001 => 'TIMER QUERY_STATE',
    0x0002 => 'TIMER MODIFY STATE'
);

my %PROCESS_SPECIFIC_MASK = (
    0x0001 => 'PROCESS TERMINATE',
    0x0002 => 'PROCESS CREATE THREAD',
    0x0008 => 'PROCESS VM OPERATION',
    0x0010 => 'PROCESS VM READ',
    0x0020 => 'PROCESS VM WRITE',
    0x0040 => 'PROCESS DUP HANDLE',
    0x0080 => 'PROCESS CREATE PROCESS',
    0x0100 => 'PROCESS SET QUOTA',
    0x0200 => 'PROCESS SET INFORMATION',
    0x0400 => 'PROCESS QUERY INFORMATION',
    0x0800 => 'PROCESS SUSPEND RESUME',
    0x1000 => 'PROCESS QUERY LIMITED INFORMATION'
);

my %THREAD_SPECIFIC_MASK = (
    0x0001 => 'THREAD TERMINATE',
    0x0002 => 'THREAD SUSPED RESUME',
    0x0008 => 'THREAD GET CONTEXT',
    0x0010 => 'THREAD SET CONTEXT',
    0x0020 => 'THREAD SET INFORMATION',
    0x0040 => 'THREAD QUERY INFORMATION',
    0x0080 => 'THREAD SET THREAD TOKEN',
    0x0100 => 'THREAD IMPERSONIFICATE',
    0x0200 => 'THREAD DIRECT IMPERSONATION'
);

my %SECTION_SPECIFIC_MASK = (
    0x0001 => 'SECTION QUERY',
    0x0002 => 'SECTION MAP WRITE',
    0x0004 => 'SECTION MAP READ',
    0x0008 => 'SECTION MAP EXECUTE',
    0x0010 => 'SECTION EXTEND SIZE',
    0x0020 => 'SECTION MAP EXECUTE EXPLICIT',
);

my %FILE_SPECIFIC_MASK = (
    0x0001 => 'FILE READ DATA',
    0x0002 => 'FILE WRITE DATA',
    0x0004 => 'FILE APPEND DATA',
    0x0008 => 'FILE READ EA (PROPERTIES)',
    0x0010 => 'FILE WRITE EA (PROPERTIES)',
    0x0020 => 'FILE EXECUTE',
    0x0080 => 'FILE READ ATTRIBUTES',
    0x0100 => 'FILE WRITE ATTRIBUTES'
);

my %DIR_SPECIFIC_MASK = (
    0x0001 => 'DIR FILE LIST',
    0x0002 => 'DIR ADD FILE',
    0x0004 => 'DIR ADD SUBDIR',
    0x0008 => 'DIR READ EA (PROPERTIES)',
    0x0010 => 'DIR WRITE EA (PROPERTIES)',
    0x0020 => 'DIR TRAVERSE',
    0x0040 => 'DIR DELETE CHILD',
    0x0080 => 'DIR READ ATTRIBUTES',
    0x0100 => 'DIR WRITE ATTRIBUTES'
);

my %PIPE_SPECIFIC_MASK = (
    0x0001 => 'PIPE READ DATA',
    0x0002 => 'PIPE WRITE DATA',
    0x0004 => 'CREATE PIPE INSTANCE',
    0x0008 => 'PIPE READ EA (PROPERTIES)',
    0x0010 => 'PIPE WRITE EA (PROPERTIES)',
    0x0080 => 'PIPE READ ATTRIBUTES',
    0x0100 => 'PIPE WRITE ATTRIBUTES'
);

my %WELL_KNOWN_SIDS = (
    'S-1-0'         => 'Null Authority',
    'S-1-0-0'       => 'Nobody Authority',
    'S-1-1'         => 'World Authority',
    'S-1-1-0'       => 'Everyone',
    'S-1-2'         => 'Local Authority',
    'S-1-2-0'       => 'Local logged users group',
    'S-1-2-1'       => 'Console Logon',
    'S-1-3'         => 'Creator Authority',
    'S-1-3-0'       => 'Creator Owner',
    'S-1-3-1'       => 'Creator Group',
    'S-1-3-2'       => 'Creator Owner Server',
    'S-1-3-3'       => 'Creator Group Server',
    'S-1-3-4'       => 'Owner Rights (current object owner)',
    'S-1-4'         => 'Non-unique Authority (an identifier authority)',
    'S-1-5'         => 'NT Authority',
    'S-1-5-1'       => 'Dialup',
    'S-1-5-2'       => 'Network',
    'S-1-5-3'       => 'Batch',
    'S-1-5-4'       => 'Interactive (group of users logged interactively)',
    'S-1-5-5'       => 'Logon Session (-X-Y)',
    'S-1-5-6'       => 'Service',
    'S-1-5-7'       => 'Anonymous',
    'S-1-5-8'       => 'Proxy',
    'S-1-5-9'       => 'Enterprise Domain Controllers',
    'S-1-5-10'      => 'Principal Self',
    'S-1-5-11'      => 'Authenticated Users',
    'S-1-5-12'      => 'Restricted Code',
    'S-1-5-13'      => 'Terminal Server Users',
    'S-1-5-14'      => 'Remote Interactive Logon',
    'S-1-5-15'      => 'This Organization',
    'S-1-5-17'      => 'This Organization',
    'S-1-5-18'      => 'Local System',
    'S-1-5-19'      => 'NT Authority',
    'S-1-5-20'      => 'NT Authority',
    'S-1-5-32-544'  => 'Administrators (builtin)',
    'S-1-5-32-545'  => 'Users (builtin)',
    'S-1-5-32-546'  => 'Guests (builtin)',
    'S-1-5-32-547'  => 'Power Users (builtin)',
    'S-1-5-32-548'  => 'Account Operators (builtin)',
    'S-1-5-32-549'  => 'Server Operators (builtin)',
    'S-1-5-32-550'  => 'Print Operators (builtin)',
    'S-1-5-32-551'  => 'Backup Operators (builtin)',
    'S-1-5-32-552'  => 'Replicators (builtin)',
    'S-1-5-64-10'   => 'NTLM Authentication',
    'S-1-5-64-14'   => 'SChannel Authentication',
    'S-1-5-64-21'   => 'Digest Authentication',
    'S-1-5-80'      => 'NT Service',
    'S-1-16-0'      => 'Untrusted Mandatory Level',
    'S-1-16-4096'   => 'Low Mandatory Level',
    'S-1-16-8192'   => 'Medium Mandatory Level',
    'S-1-16-8448'   => 'Medium Plus Mandatory Level',
    'S-1-16-12288'  => 'High Mandatory Level',
    'S-1-16-16384'  => 'System Mandatory Level',
    'S-1-16-20480'  => 'Protected Process Mandatory Level',
    'S-1-16-28672'  => 'Secure Process Mandatory Level',
    'S-1-5-80-0'    => 'All Services',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' => 'Trusted Installer'
);

my $ACE_OBJECT_TYPE_PRESENT             = 0x00000001;
my $ACE_INHERITED_OBJECT_TYPE_PRESENT   = 0x00000002;

#------------------------------------------------------------------------------

print "sdbp.pl ".$VERSION." (BETA)\nA tool to parse binary Windows Security Descriptors\n";
print "Copyright 2011 F.Picasso\n\n";

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

#------------------------------------------------------------------------------

my @sdb;
my $sdbsize = 0;
my $align = "%-16s";

open( FH, "<", $file ) || die "Could not open $file: $!\n";
binmode( FH );
while ( not eof( FH ) ) {
    read( FH, $sdb[$sdbsize], 1 );
    $sdbsize++;
}
close( FH );

parseSD( \@sdb, 0, $align );

#------------------------------------------------------------------------------

sub parseSD
{
    my $ref = shift; my $of = shift; my $align = shift;
    my $owner; my $group; my $sacl; my $dacl;

    print "------- SECURITY DESCRIPTOR -------\n";
    print "STRUCTURE -------------------------\n";
    print sprintf( "$align = %s\n", 'Revision',   unpack( 'C', $ref->[$of] ) );
    print sprintf( "$align = %s\n", 'Padding16',  unpack( 'C', $ref->[$of+1] ) );
    print sprintf( "$align = %s\n", 'Control',    unpack( 'v', $ref->[$of+2].$ref->[$of+3] ) );

    $owner = unpack( 'V', $ref->[$of+4].$ref->[$of+5].$ref->[$of+6].$ref->[$of+7] );
    print sprintf( "$align = %s\n", 'Owner', $owner );

    $group = unpack( 'V', $ref->[$of+8].$ref->[$of+9].$ref->[$of+10].$ref->[$of+11] );
    print sprintf( "$align = %s\n", 'Group', $group );

    $sacl = unpack( 'V', $ref->[$of+12].$ref->[$of+13].$ref->[$of+14].$ref->[$of+15] );
    print sprintf( "$align = %s\n", 'SACL', $sacl );

    $dacl = unpack( 'V', $ref->[$of+16].$ref->[$of+17].$ref->[$of+18].$ref->[$of+19] );
    print sprintf( "$align = %s\n", 'DACL', $dacl );

    if ( $owner > 0 ) {
        parseSID( $ref, $owner, $align, 'OWNER' );
    }
    else { print sprintf( "$align = %s\n", 'OWNER', 'no owner?!'); }
    
    if ( $group > 0 ) {
        parseSID( $ref, $group, $align, 'GROUP' );
    }
    else { print sprintf( "$align = %s\n", 'GROUP', 'no owner?!'); }

    print "SACL ------------------------------\n";
    if ( $sacl > 0 ) {
        parseACL( $ref, $sacl, $align );
    }
    else { print "no SACL\n"; }

    print "DACL ------------------------------\n";
    if ( $dacl > 0 ) {
        parseACL( $ref, $dacl, $align );
    }
    else { print "no DACL\n"; }
    print "\n";
}

#------------------------------------------------------------------------------

sub parseACL
{
    my $ref = shift; my $of = shift; my $align = shift;
    my $pad16; my $acenum; my $size; my $pad32;
    
    print sprintf( "$align = %s\n", 'Revision',   unpack( 'C', $ref->[$of] ) );
    
    $pad16 = unpack( 'C', $ref->[$of+1] );
    print sprintf( "$align = %s\n", 'Padding16', $pad16 );
    
    $size = unpack( 'v', $ref->[$of+2].$ref->[$of+3] );
    print sprintf( "$align = %s\n", 'Size', $size );
    
    $acenum = unpack( 'v', $ref->[$of+4].$ref->[$of+5] );
    print sprintf( "$align = %s\n", 'AceCount', $acenum );
    
    $pad32 = unpack( 'v', $ref->[$of+6].$ref->[$of+7] );
    print sprintf( "$align = %s\n", 'Padding32', $pad32 );
    
    if ( not $acenum ) { return; }
    
    $of += 8;
    foreach my $i (0..$acenum-1) {
        print sprintf( "$align : %u  -------------\n", 'ACE number', ($i+1) );
        $of += parseACE( $ref, $of, $align, $size );
    }
}

#------------------------------------------------------------------------------

sub cbAceAllow
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $mask; my $sids;
    
    $mask = unpack( 'V', $ref->[$of+0].$ref->[$of+1].$ref->[$of+2].$ref->[$of+3] );
    parseSID( $ref, $of+4, $align, 'TRUSTEE' );
    #$sids = unpack( 'V', $ref->[$of+4].$ref->[$of+5].$ref->[$of+6].$ref->[$of+7] );
    parseMask( $mask, undef, $align ); 
}

sub cbAceDeny
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $mask;
    
    $mask = unpack( 'V', $ref->[$of+0].$ref->[$of+1].$ref->[$of+2].$ref->[$of+3] );
    parseSID( $ref, $of+4, $align, '(deny) TRUSTEE' );
    parseMask( $mask, undef, $align );
}

sub cbAceAudit
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $mask;
    
    $mask = unpack( 'V', $ref->[$of+0].$ref->[$of+1].$ref->[$of+2].$ref->[$of+3] );
    parseSID( $ref, $of+4, $align, '(audit) TRUSTEE' );
    parseMask( $mask, undef, $align );
}

sub cbAceAlarm
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $mask;
    
    $mask = unpack( 'V', $ref->[$of+0].$ref->[$of+1].$ref->[$of+2].$ref->[$of+3] );
    parseSID( $ref, $of+4, $align, '(alarm) TRUSTEE' );
    parseMask( $mask, undef, $align );
}

sub cbAceAllowObj
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $mask; my $flag;
    
    $mask = unpack( 'V', $ref->[$of+0].$ref->[$of+1].$ref->[$of+2].$ref->[$of+3] );
    $flag = unpack( 'V', $ref->[$of+4].$ref->[$of+5].$ref->[$of+6].$ref->[$of+7] );
    $of += 8;
    
    if ( $flag & $ACE_OBJECT_TYPE_PRESENT ) {
    }
    
    if ( $flag & $ACE_INHERITED_OBJECT_TYPE_PRESENT ) {
    }
    
    parseSID( $ref, $of, $align, '(alarm) TRUSTEE' );
    parseMask( $mask, undef, $align );
}
   
#------------------------------------------------------------------------------

sub parseMask
{
    my $mask = shift; my $objtype = shift; my $align = shift;
    my $specific; my $standard; my $generic; my $maxallow;
    my $key; my $tab = '  ';
    
    $specific = ( $mask & 0x0000FFFF );
    $standard = ( $mask & 0x00FF0000 );
    $maxallow = ( $mask & 0x02000000 );
    $generic  = ( $mask & 0xF0000000 );
          
    if ( $mask & $ACCESS_SECURITY_MASK ) {
        print "ACCESS SECURITY is SET\n";
    }
    
    if ( $mask & $MAXIMUM_ALLOWED_MASK ) {
        print "MAXIMUM ALLOWED is SET\n";
    }

    if ( $generic > 0 ) {
        print "Generic rights\n";
        rptRights( \%GENERIC_MASK, $generic, $tab );
    }

    if ( $standard > 0 ) {
        print "Standard rights\n";
        rptRights( \%STANDARD_MASK, $standard, $tab );
    }

    if ( $specific > 0 ) {
        print "Specific rights\n";
        if ( defined $objtype ) {
            print "TODO TODO TODO\n";
        }
        else {
            print "No OBJECT specified, printing FILE and DIRECTORIES rights\n";
            rptRights( \%FILE_SPECIFIC_MASK, $specific, $tab );
            rptRights( \%DIR_SPECIFIC_MASK, $specific, $tab );
        }
    }
    
    print sprintf( "%s 0x%08X ", 'MASK is', $mask );
    print sprintf( "(specific 0x%04X, standard 0x%01X, generic 0x%X)\n", 
        $specific, $standard >> 16, $generic >> 28 );
}

sub rptRights
{
    my $ref = shift; my $mask = shift; my $tab = shift;
    
    foreach my $key ( sort( keys %{$ref} ) ) {
        if ( int($key) & int($mask) ) {
            print $tab.$ref->{ $key }."\n";
        }
    }
}

#------------------------------------------------------------------------------

sub parseACE
{
    my $ref = shift; my $of = shift; my $align = shift; my $maxsize = shift;
    my $type; my $flag; my $size; my $acecb; my $flagstr;
    
    $type = unpack( 'C', $ref->[$of] );
    $flag = unpack( 'C', $ref->[$of+1] );
    $size = unpack( 'v', $ref->[$of+2].$ref->[$of+3] );
    $of += 4;
    
    ( $size <= $maxsize ) or die "Invalid ACE size: [$size greater than maxsize [$maxsize]!\n";
    
    $flagstr = getFlagString( $flag );
    
    $acecb = $ACE_TYPE{ $type };
    if ( defined $acecb ) {
        print sprintf( "$align %s\n", $ACE_TYPE_STRING{ $type }, "( $flagstr)" );
        $acecb->( $ref, $of, $align, $maxsize );
    }
    else {
        print "Unmanaged ACE type [$type]!\n";
    }
        
    return $size;
}

#------------------------------------------------------------------------------

sub getFlagString
{
    my $flag = shift;
    my $i; my $val; my $str = '';
    
    if ( not $flag ) {
        return "no inheritance ";
    }
    
    foreach my $i (@ACE_FLAGS_VALUE) {
        $val = $i & $flag;
        if ( $val ) {
            $str .= $ACE_FLAGS{ $val }." ";
        }
    }
    return $str;
}

#------------------------------------------------------------------------------

sub parseSID
{
    my $ref = shift; my $of = shift; my $align = shift; my $desc = shift;
    my $version; my $ndh; my $tmp; my $i; my $sid; my $wns;
    
    $sid = "S-".unpack( 'C', $ref->[$of] )."-";
    $ndh = unpack( 'C', $ref->[$of+1] );
    # TBR fpi 48bit integer next, but usually msb are 0..
    $sid .= unpack( 'N', $ref->[$of+4].$ref->[$of+5].$ref->[$of+6].$ref->[$of+7] );
    $sid .= "$tmp";
    $i = $of+8;
    while ( $ndh ) {
        $tmp = unpack( 'V', $ref->[$i].$ref->[$i+1].$ref->[$i+2].$ref->[$i+3] );
        $sid .= "-$tmp";
        $i += 4;
        $ndh--;
    }
    
    if ( defined $WELL_KNOWN_SIDS{ $sid } ) {
        $sid .= '  [ '.$WELL_KNOWN_SIDS{ $sid }.' ]';
    }
    
    if ( defined $desc ){ $desc.= " SID"; print sprintf( "$align = %s\n", $desc, $sid ); }
    else { print sprintf( "$align = %s\n", 'SID', $sid ); }
}

#------------------------------------------------------------------------------

#sub parseGUID

#------------------------------------------------------------------------------
1;