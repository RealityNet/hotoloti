#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------------------
# evtxcheck.pl
# Perl script to makes some predefined checks on EVTX files
#
# usage: evtxcheck.pl <path to EVTX file>
# 
# NOTE: Requires the use of Microsoft LogParser (in PATH)
#
# copyright 2012 F.Picasso, francesco.picasso@gmail.com
#-----------------------------------------------------------------------------

use strict;

#-----------------------------------------------------------------------------

my $VERSION = "20120331";

print "EVenTX CHECKer version $VERSION\n";
print "using Microsoft LogParser, makes basic checks on EVTX files\n";
print "copyright 2012 Francesco Picasso\n";

my $infile = shift || die "You must enter a filename.\n";
die "$infile not found.\n" unless (-e $infile);

#-----------------------------------------------------------------------------

my $data;
my @lines;
my $line;
# RECORDS
my $firstRecord = undef;
my $lastRecord  = undef;
my $prevRecord  = 0;
my $recordWarnN = 0;
my @recordW     = [];
# TIME
my $prevTime    = 0;
my $timeWarnN   = 0;
my @timeW       = [];
my $TIMEDELTA   = 60; # 1 minute;
# EVENT
my $prevEvt     = 0;
my $prevprevEvt = 0;
# COMPUTERNAME
my $compNameNum = 0;
my $compName    = '';
my @compNames   = [];
my @compNameW   = [];
my $recordCount = 0;

my $PIPE = "|";
my $BASE_CMD = "LogParser -i:evt -o:CSV ";

my $SELECT_MAIN  = "\"SELECT RecordNumber,TO_UTCTIME(TimeGenerated),TO_INT(TO_UTCTIME(TimeGenerated)),";
   $SELECT_MAIN .= "EventID,ComputerName FROM \"$infile\" ORDER BY RecordNumber\"";

#-----------------------------------------------------------------------------

$data = fystem( $BASE_CMD.$SELECT_MAIN.$PIPE );
@lines = map { "$_\n" } split /\n/, $data;
shift(@lines);
foreach $line (@lines) {
    local $/ = "\r\n";
    chomp( $line );
    my @fields = split( /,/, $line );
    last unless ( @fields == 5 );
    $recordCount++;
    my ($record,$timegen,$timenum,$evtid,$compname ) = @fields;
    
    if ( not defined $firstRecord ) {
        $firstRecord = $record;
        $prevRecord  = $record;
    }
    else {
        if ( $record != $prevRecord + 1 ) {
            # avoid false positive when SuppressDuplicate is in action
            if ( $evtid != 4625 ) {
                $recordW[ $recordWarnN++ ] = sprintf( "Missing [%u] records before ".
                    "RecordNumber: %s, Event: %s, Time: %s",
                    ( $record - $prevRecord - 1 ), $record, $evtid, $timegen );
            }
        }
        $prevRecord = $record;
        $lastRecord = $record;
    }

    if ( ( $timenum + $TIMEDELTA ) < $prevTime ) {
        # avoid false positive when SuppressDuplicate is in action
        if ( $prevEvt != 4625 and $prevprevEvt != 4625 ) {
            $timeW[ $timeWarnN++ ] = sprintf( "Back in time at ".
                "RecordNumber: %s, Event: %s, Time: %s", $record, $evtid, $timegen );
        }
    }
    $prevTime = $timenum;
    
    $compname = lc( $compname );
    if ( $compname ne $compName ) {
        $compName = $compname;
        $compNames[ $compNameNum ] = $compName;
        $compNameW[ $compNameNum ] = sprintf( "Set to '$compName' at ".
            "RecordNumber: %s, Event: %s, Time: %s", $record, $evtid, $timegen );
        $compNameNum++;
    }
    
    # Event, last two records memory
    $prevprevEvt = $prevEvt;
    $prevEvt = $evtid;
}

print "\nTotal Records in '$infile': $recordCount\n";

print "\n";
print "----- Missing Records Detection -----\n\n";
print "First Record Number: $firstRecord\n";
print "Last  Record Number: $lastRecord\n";
if ( $recordWarnN > 0 ) {
    print "\nDETECTED $recordWarnN anomalies\n";
    foreach my $a (@recordW) {
        print "- $a\n";
    }
}
else {
    print "\nno missing records detected\n";
}

print "\n";
print "----- Back in Time Detection (Tolerance: $TIMEDELTA secs) -----\n\n";
if ( $timeWarnN > 0 ) {
    print "\nDETECTED $timeWarnN anomalies\n";
    foreach my $a (@timeW) {
        print "- $a\n";
    }
}
else {
    print "no back time jumps detected\n";
}

print "\n----- ComputerName(s) -----\n\n";
print "ComputerNames(s) used: $compNameNum\n";
foreach my $a (@compNames) {
    print "$a\n";
}
if ( $compNameNum > 1 ) {
    print "\nDETECTED ".($compNameNum - 1)." changes\n";
    foreach my $a (@compNameW) {
        print "- $a\n";
    }
}
print "\n----------------------------------\n\n";

#-----------------------------------------------------------------------------

sub fystem
{
    my $cmd = shift;
    my $data = '';
    open(ICAT, $cmd) or die "can't fork: $!";
    binmode(ICAT);
    while(<ICAT>) { $data .= $_; }
    close ICAT or die "error executing command '$cmd': [$!] [$?]";
    return $data;
}

#-----------------------------------------------------------------------------
1;
