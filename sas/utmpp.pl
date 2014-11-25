#-----------------------------------------------------------------------------
# utmpp.pl 
# parser and timeline creator for Linux WTMP/WTMPX files.
# Currenlty in ALPHA version.
# Output goes to STDOUT
#
# Change History
#   20120621 * [fpi] first release v0.1.20120621
#
# TODO
#   - add IPv6 support
#
# copyright 2012 Francesco Picasso <francesco.picasso@gmail.com>
#-----------------------------------------------------------------------------

use strict;
use warnings;
use Getopt::Long qw( :config no_ignore_case );

#------------------------------------------------------------------------------

my %UT_TYPES = (
    0   => "empty",         # No valid user accounting information
    1   => "Run Level",     # The system's runlevel
    2   => "Boot Time",     # Time of system boot
    3   => "New Time", 	    # Time after system clock changed
    4   => "Old Time",      # Time when system clock changed
    5   => "Init",          # Process spawned by the init process
    6   => "Login",         # Session leader of a logged in user
    7   => "User Process",  # Normal process
    8   => "Process End",   # Terminated process
    9   => "Accounting"     # Accouting
);

#------------------------------------------------------------------------------

my $VERSION = '0.1.20120621';

my %config;
Getopt::Long::Configure( "prefix_pattern=(-|\/)" );
GetOptions( \%config, qw( mactime|m file|f=s detailed|d btmp|b help|h ) );

if ($config{help} || !%config) { usage(); exit; }
die "MISSING -file|-f [filename]\n" if not $config{file};

my $data;
my $file = $config{file} || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

#------------------------------------------------------------------------------

# struct utmp
#   short int   ut_type;
#   pid_t       pid;                            /* PID of login process */
#   char        PAD[2]                          /* NOT SURE HERE */
#   char        ut_line[ UT_LINESIZE = 32 ]     /* Device name of tty - "/dev/" */
#   char        ut_id[ 4 ]                      /* Terminal name suffix or inittab(5) ID */
#   char        ut_user[ UT_NAMESIZE = 32 ]
#   char        ut_host[ UT_HOSTSIZE = 256 ];   /* Hostname or  kernel version */
#   struct exit_status ut_exit {
#       short int e_termination;                /* Process termination status */
#       short int e_exit;                       /* Process exit status */
#   } ut_exit;
#   int32_t     ut_session;                     /* Session ID (getsid(2)) used for windowing */
#   struct {
#       int32_t tv_sec;           /* Seconds */
#       int32_t tv_usec;          /* Microseconds */
#   } ut_tv;                      /* Time entry was made */
#   int32_t ut_addr_v6[4];        /* Internet address of remote host; IPv4 address uses just ut_addr_v6[0] */
#   char    __unused[20]

my $uTemp = "L L A32 A4 A32 A256 S S L L L L4 A20";
#            4 4  32  4  32  256 2 2 4 4 4 16  20
my $eSize = length(pack($uTemp,(  )));
my $entry;

open( UTMPFH, "<", $file ) or die "Unable to open '$file':$!\n";
binmode( UTMPFH );

die "Expected utmp entry size of 384 bytes, found '$eSize'!"
    if $eSize != 384;

my %TTY = ();
while (read(UTMPFH, $entry, $eSize))
{
    my $desc = '';
    my $note = '()';
    my $temp;
    my ($utType, $pid, $utLine, $utId,
        $utUser, $utHost, $exTerm, $exExit,
        $utSession, $tvSec, $tvUsec, $utAddr,
        $unused) = unpack($uTemp, $entry);

    if ( 1 == $utType ) {
        #RunLevel
        die "ERROR: RunLevel but user '$utUser' is not [runlevel|shutdown]!"
            if ( $utUser ne 'runlevel' and $utUser ne 'shutdown' );
        if ( $utLine eq '~' and $utUser eq 'shutdown') {
            $note = '( ';
        	for my $key (keys %TTY) {
            	my $delta = $tvSec - $TTY{$key}[1];
                my $deltaMin = int($delta/60);  my $deltaSec = $delta % 60;
           		$note .= "user=$TTY{$key}[0] line=$key DOWN session=$deltaMin:$deltaSec; ";
			}
            $note .= ')';
			%TTY = ();
            $desc = 'DOWN  ';
    	}
        if ( $utUser eq 'runlevel' ) {  next unless $config{detailed}; }
    }
    elsif ( 2 == $utType ) {
        #BootTime
        die "ERROR: BootTime but user '$utUser' is not [reboot]!\n" if ( $utUser ne 'reboot' );
		if ( $utLine eq '~' and $utUser eq 'reboot') {
            $note = '( system boot; ';
        	for my $key (keys %TTY) {
            	my $delta = $tvSec - $TTY{$key}[1];
                my $deltaMin = int($delta/60);  my $deltaSec = $delta % 60;
           		$note .= "user=$TTY{$key}[0] line=$key PURGED session=$deltaMin:$deltaSec; ";
			}
            $note .= ')';
			%TTY = ();
            $desc = 'BOOT  ';
        }
    }
    elsif ( 3 == $utType or 4 == $utType ) {
        #NewTime,OldTime TODO
    }
    elsif ( 5 == $utType ) {
        #Init
    }
    elsif ( 6 == $utType ) {
        #Login
        if ( $utHost eq '' and $utUser eq 'LOGIN' ) {  next unless $config{detailed}; }
    }
    elsif ( 7 == $utType ) {
        #User Process
		my $key = $utLine;
        die "ERROR: '$utUser' logged on '$utLine' used by $TTY{$key}[0]!" if $TTY{$key};
        $TTY{$key} = [ "$utUser\@$utHost", $tvSec ];
        $note = "( user=$utUser\@$utHost logged in on line=$key; ";
        $note .= 'now=';
        for $key (keys %TTY) { $note .= "$TTY{$key}[0]_$key "; }
        $note .= ')';
        $desc = 'LOGIN ';
    }
    elsif ( 8 == $utType ) {
    	#Process End
        my $key = $utLine;
        if ( $TTY{$key} ) {
           	die "ERROR '$key' never logged in ???!"	if $TTY{$key}[1] == 0;
            my $delta = $tvSec - $TTY{$key}[1];
            my $deltaMin = int($delta/60);  my $deltaSec = $delta % 60;
           	$note = "( user=$TTY{$key}[0] logged out from line=$key session=$deltaMin:$deltaSec; ";
            delete $TTY{$key};
            $note .= 'now=';
            for $key (keys %TTY) { $note .= "$TTY{$key}[0]_$key "; }
            $note .= ')';
        }
        else {
            if ( $utHost eq '' and $utUser eq '' ) { next unless $config{detailed}; }
            else { $note = "( user='$utUser' on line='$utLine' logged out WITHOUT login; )"; }
        }
        $desc = 'LOGOUT';
    }
    elsif ( 9 == $utType ) {
        #Accounting
    }
    else { die "Unexpected ut_type '$utType'!\n"; }
    
    if ( $config{btmp} ) {
        %TTY = ();
        $desc = "FAIL  ";
        $note = "( user=$utUser\@$utHost login failed on line=$utLine; )"
    }
    
    my $utTypeString = $UT_TYPES{$utType};
    $utTypeString = "unknown" unless defined $utTypeString;
    my $ipv4String = join ".", map { (($utAddr>>8*($_))&0xFF) } 0..3;
    my $timeString = scalar gmtime($tvSec);
       
    # MACTIME 3.x
    # MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    if ( $config{mactime} ) {
        my $nameString;
        $nameString  = "[$desc] $note type=$utTypeString line=$utLine user=$utUser ";
        $nameString .= "host=$utHost ipv4=$ipv4String (file: $file)";
        $temp  = '0|';                  #MD5
        $temp .= "$nameString|";        #name
        $temp .= '0|';                  #inode
        $temp .= '0|';                  #mode_as_string
        $temp .= '0|';                  #UID
        $temp .= '0|';                  #GID
        $temp .= '0|';                  #size
        $temp .= "$tvSec|";             #atime
        $temp .= "$tvSec|";             #mtime
        $temp .= "$tvSec|";             #ctime
        $temp .= "$tvSec";              #crttime
        print $temp."\n";
    }
    else {
        printf( "type = [0x%04X] %s\n", $utType, $utTypeString);
        printf( "pid = %d [0x%04X]\n", $pid, $pid);
        printf( "line = %s\n", $utLine);
        #printf( "id = %s\n", $utId);
        printf( "user = %s\n", $utUser);
        printf( "host = %s\n", $utHost);
        #printf( "e_term = %d\n", $exTerm);
        #printf( "e_exit = %d\n", $exExit);
        #printf( "ut_session = %d\n", $utSession);
        printf( "tv_sec  = %u (%s)\n", $tvSec, $timeString);
        printf( "tv_usec = %u\n", $tvUsec);
        printf( "ut_addr_v6 string = %s\n", $utAddr);
        printf( "ut_addr_v6 IPV4 = %s\n", $ipv4String );
        printf( "NOTE = %s %s\n", $desc, $note ) if $note ne '()';
        print "-----------------------\n";
    }
}
close(UTMPFH);

#------------------------------------------------------------------------------

sub usage
{
	print<< "EOT";
utmpp v.$VERSION - parser and timeline creator for Linux WTMP/WTMPX files.
Currenlty in ALPHA version.
Parameters:

  -f|file    [file]..............input file name
  -m|mactime ....................mactime output 3.x
  -d|detailed ...................output every file entry, otherwise skipped
  -b|btmp .......................input file contains failed logins

copyright 2012 Francesco Picasso
EOT
}

#------------------------------------------------------------------------------
