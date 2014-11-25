#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------------------
# evtxrpt.pl
# Perl script obtain statistics from EVTX files
# Should provide an output similar to H.Carvey evtrpt.pl
#
# usage: evtxrpt.pl <path to EVTX file>
# 
# NOTE: Requires the use of Microsoft LogParser (in PATH)
#
# copyright 2012 F.Picasso, francesco.picasso@gmail.com
#-----------------------------------------------------------------------------

use strict;

#-----------------------------------------------------------------------------

my $VERSION = "20120331";

print "EVenTX RePorT version $VERSION\n";
print "using Microsoft LogParser, summarize EVTX files\n";
print "copyright 2012 Francesco Picasso\n";

my $infile = shift || die "You must enter a filename.\n";
die "$infile not found.\n" unless (-e $infile);

my $data;
my @lines;
my $line;

#-----------------------------------------------------------------------------

my $PIPE = "|";
my $BASE_CMD = "LogParser -i:evt -o:CSV ";

my $SELECT_STAT  = "\"SELECT SourceName,EventID,COUNT(*) FROM \"$infile\" ";
   $SELECT_STAT .= "GROUP BY EventID,SourceName ORDER BY SourceName,EventID\"";
   
my $SELECT_RANGE1  = "\"SELECT TOP 1 TO_UTCTIME(TimeGenerated) as TimeGen FROM ";
   $SELECT_RANGE1 .= "\"$infile\" ORDER BY TimeGen ASC \"";
my $SELECT_RANGE2  = "\"SELECT TOP 1 TO_UTCTIME(TimeGenerated) as TimeGen FROM ";
   $SELECT_RANGE2 .= "\"$infile\" ORDER BY TimeGen DESC \"";

my $SELECT_TIMELINE  = "\"SELECT TO_STRING(TO_UTCTIME(TimeGenerated),'yyyy') as Year, ";
   $SELECT_TIMELINE .= "TO_STRING(TO_UTCTIME(TimeGenerated),'MM') as Month from ";
   $SELECT_TIMELINE .= "\"$infile\" ORDER BY Year,Month\"";

#-----------------------------------------------------------------------------

$data = fystem( $BASE_CMD.$SELECT_STAT.$PIPE );
@lines = map { "$_\n" } split /\n/, $data;
shift(@lines);

print "\n";
printf( "%-48s %-8s %s\n", 'Source Name', 'Event ID', 'Count' );
printf( "%-48s %-8s %s\n", '-----------', '--------', '-----' );
foreach $line (@lines) {
    my @fields = split( /,/, $line );
    last unless (@fields == 3 );
    printf( "%-48s %-8s %u\n", $fields[0], $fields[1], $fields[2] );
}

#-----------------------------------------------------------------------------

printf( "\n-------------------- Data Range (UTC) ------------------\n");

$data = fystem( $BASE_CMD.$SELECT_RANGE1.$PIPE );
@lines = map { "$_\n" } split /\n/, $data;
shift(@lines);

my $oldest = shift(@lines);

$data = fystem( $BASE_CMD.$SELECT_RANGE2.$PIPE );
my @lines = map { "$_\n" } split /\n/, $data;
shift(@lines);

my $newest = shift(@lines);

print "$oldest"."to\n"."$newest";

#-----------------------------------------------------------------------------

printf( "\n--------- Year/Month distribution -------------\n" );

$data = fystem( $BASE_CMD.$SELECT_TIMELINE.$PIPE );
@lines = map { "$_\n" } split /\n/, $data;
shift(@lines);
my %hoh;
foreach $line (@lines) {
    local $/ = "\r\n";
    chomp( $line );
    my @fields = split( /,/, $line );
    last unless ( @fields == 2 );
    if ( not defined $hoh{$fields[0]} ) {
            $hoh{$fields[0]}{'01'} = 0; $hoh{$fields[0]}{'02'} = 0; $hoh{$fields[0]}{'03'} = 0;
            $hoh{$fields[0]}{'04'} = 0; $hoh{$fields[0]}{'05'} = 0; $hoh{$fields[0]}{'06'} = 0;
            $hoh{$fields[0]}{'07'} = 0; $hoh{$fields[0]}{'08'} = 0; $hoh{$fields[0]}{'09'} = 0;
            $hoh{$fields[0]}{'10'} = 0; $hoh{$fields[0]}{'11'} = 0; $hoh{$fields[0]}{'12'} = 0;
    }
    $hoh{$fields[0]}{$fields[1]} += 1;
}

print "\nYear Month Count\n";
for my $year ( sort keys %hoh ) {
    print "$year\n";
    for my $month ( sort keys %{ $hoh{$year} } ) {
         print "       $month   $hoh{$year}{$month}\n";
    }
    print "\n";
}

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
