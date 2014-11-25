#! c:\perl\bin\perl.exe
#------------------------------------------------------------------------------
# zipdump.pl 
# Tool to parse the ZIP file metadata
#
# Version 1.0 [06-may-2011]
#
# Changes
#
# References
#	http://www.pkware.com/documents/casestudies/APPNOTE.TXT
#	http://www.winzip.com/aes_info.htm
#
# TODO
#	check and try ZIP64 files (not managed now)
#	add verify logic (need to save in structures local/central file headers)
#	manage NT SECURITY DESCRIPTOR ACL
#
# copyright 2011 F.Picasso, francesco.picasso@gmail.com
#------------------------------------------------------------------------------

use strict;
no strict "refs";

my $VERSION = "1.0";

print "zipdump ".$VERSION."\nA library-free script perl to parse ZIP metadata\n";
print "Copyright 2011 F.Picasso\n\n";

my $zipf = shift || die "You must enter a filename.\n";
die "$zipf not found.\n" unless (-e $zipf);

#------------------------------------------------------------------------------

my $pksignature = 0x04034b50;
my $cdsignature = 0x02014b50;
my $digitalsign = 0x05054b50;
my $endofcentdr = 0x06054b50;

# Extra Field Header ID
my %efhid = (	0x0001 => "Zip64 extended information extra field",
				0x0007 => "AV Info",
				0x0008 => "Reserved for extended language encoding data (PFS)",
				0x0009 => "OS/2",
				0x000a => "NTFS",
				0x000c => "OpenVMS",
				0x000d => "UNIX",
				0x000e => "Reserved for file stream and fork descriptors",
				0x000f => "Patch Descriptor",
				0x0014 => "PKCS#7 Store for X.509 Certificates",
				0x0015 => "X.509 Certificate ID and Signature for individual file",
				0x0016 => "X.509 Certificate ID for Central Directory",
				0x0017 => "Strong Encryption Header",
				0x0018 => "Record Management Controls",
				0x0019 => "PKCS#7 Encryption Recipient Certificate List",
				0x0065 => "IBM S/390 (Z390), AS/400 (I400) attributes - uncompressed",
				0x0066 => "Reserved for IBM S/390 (Z390), AS/400 (I400) attributes - compressed",
				0x4690 => "POSZIP 4690 (reserved)",
				0x07c8 => "Macintosh",
				0x2605 => "ZipIt Macintosh",
				0x2705 => "ZipIt Macintosh 1.3.5+",
				0x2805 => "ZipIt Macintosh 1.3.5+",
				0x334d => "Info-ZIP Macintosh",
				0x4341 => "Acorn/SparkFS ",
				0x4453 => "Windows NT security descriptor (binary ACL)",
				0x4704 => "VM/CMS",
				0x470f => "MVS",
				0x4b46 => "FWKCS MD5 (see below)",
				0x4c41 => "OS/2 access control list (text ACL)",
				0x4d49 => "Info-ZIP OpenVMS",
				0x4f4c => "Xceed original location extra field",
				0x5356 => "AOS/VS (ACL)",
				0x5455 => "extended timestamp",
				0x554e => "Xceed unicode extra field",
				0x5855 => "Info-ZIP UNIX (original, also OS/2, NT, etc)",
				0x6375 => "Info-ZIP Unicode Comment Extra Field",
				0x6542 => "BeOS/BeBox",
				0x7075 => "Info-ZIP Unicode Path Extra Field",
				0x756e => "ASi UNIX",
				0x7855 => "Info-ZIP UNIX (new)",
				0xa220 => "Microsoft Open Packaging Growth Hint",
				0x9901 => "AES Encryption",
				0xfd4a => "SMS/QDOS"
);

# Extra Field Header ID callbacks
my %efhidfn = (	0x0001 => "EFH_ZIP64e",
				0x000a => "EFH_NTFS",
				0x4453 => "EFH_Windows_ACL",
				0x554e => "EFH_XCEED_UNICODE",
				0x9901 => "EFH_AES"
);


#------------------------------------------------------------------------------

my $signature;
my $fsize;
my $fdata;
my $lfhflag;
my $lfhcnt;
my $cfhflag;
my $cfhcnt;
my $skipsize;
my $endsize;

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------

$fsize = ( stat( $zipf ) )[ 7 ];
print "ZIP file: <".$zipf."> (".$fsize." bytes)\n";
print "\n";

open( ZFH, "<", $zipf ) || die "Could not open $zipf: $!\n";
binmode( ZFH );

print "LOCAL FILE HEADER START -------------------------------------------\n\n";

$lfhflag = 1;
$lfhcnt = 0;

do {
	( 4 == read( ZFH, $fdata, 4 ) ) or die "Error reading file!\n";
	$signature = unpack( "V", $fdata );

	if ( $signature != $pksignature ) {
		$lfhflag = 0;
	}
	else {
		$lfhcnt++;
		print "LOCAL FILE HEADER ------------- ".$lfhcnt." (pos: ".sprintf( "%u - 0x%X", tell( ZFH ), tell( ZFH ) ).")\n";
		$skipsize = readLocalHeader( \*ZFH );
		seek( ZFH, $skipsize, 1 );
		print "\n";
	}
} while ( $lfhflag );

print "LOCAL FILE HEADER END ---------------------------------------------\n\n";

if ( $cdsignature != $signature ) {
	print "Missing Central Directory Signature!\n";
	die;
}
seek( ZFH, -4, 1 );

print "CENTRAL DIRECTORY START -------------------------------------------\n\n";

$cfhflag = 1;
$cfhcnt = 0;

do {
	( 4 == read( ZFH, $fdata, 4 ) ) or die "Error reading file!\n";
	$signature = unpack( "V", $fdata );

	if ( $signature != $cdsignature ) {
		$cfhflag = 0;
	}
	else {
		$cfhcnt++;
		print "CENTRAL FILE HEADER ----------- ".$cfhcnt." (pos: ".sprintf( "%u - 0x%X", tell( ZFH ), tell( ZFH ) ).")\n";
		readCentralHeader( \*ZFH );
		print "\n";
	}
} while ( $cfhflag );

print "CENTRAL DIRECTORY END ---------------------------------------------\n\n";

if ( $digitalsign == $signature ) {
	readDigitalSignature( \*ZFH );

	( 4 == read( ZFH, $fdata, 4 ) ) or die "Error reading file!\n";
	$signature = unpack( "V", $fdata );	
}
else {
	print "- The ZIP file has not a Digital Signature.\n\n";
}

if ( $endofcentdr == $signature) {
	# TODO: we should check if call the ZIP64 version!
	readEndOfCentralDir( \*ZFH );
	print "\n";
}

$endsize = tell( ZFH );
if ( $endsize != $fsize ) {
	$endsize = $fsize - $endsize;
	print "The tool is missing some bytes (".$endsize.") at the end of the ZIP file!\n";
	readRaw( \*ZFH,  $endsize, "Missing RAW data:\t\t" );
	print "\n";
}
else {
	print "The parsing finished successfully. Enjoy results.\n";
}
		
close( ZFH );

#------------------------------------------------------------------------------
# Readers
#------------------------------------------------------------------------------

sub readEndOfCentralDir {
	my $file = shift;
	my $data;
	my $disk_number;
	my $disk_number_with_cd;
	my $total_num_of_entry;
	my $total_num_of_entry_in_cd;
	my $size_of_cd;
	my $offset_of_cd;
	my $comment_len;
	my $comment;
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$disk_number = unpack( "v", $data );
	print "- Disk number:\t\t\t\t".sprintf( "0x%04x\t\t%u", $disk_number, $disk_number )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$disk_number_with_cd = unpack( "v", $data );
	print "- Disk number with Central Dir:\t\t".sprintf( "0x%04x\t\t%u", $disk_number_with_cd, $disk_number_with_cd )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$total_num_of_entry = unpack( "v", $data );
	print "- Total num of entries in zip:\t\t".sprintf( "0x%04x\t\t%u", $total_num_of_entry, $total_num_of_entry )."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$total_num_of_entry_in_cd = unpack( "v", $data );
	print "- Total num of entries in Central Dir:\t".sprintf( "0x%04x\t\t%u", $total_num_of_entry_in_cd, $total_num_of_entry_in_cd )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$size_of_cd = unpack( "V", $data );
	print "- Size of Central Directory:\t\t".sprintf( "0x%08x\t%u", $size_of_cd, $size_of_cd )."\n";	

	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$offset_of_cd = unpack( "V", $data );
	print "- Offset of Central Directory:\t\t".sprintf( "0x%08x\t%u", $offset_of_cd, $offset_of_cd )."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$comment_len = unpack( "v", $data );
	print "- Archive Comment Length:\t\t".sprintf( "0x%04x\t\t%u", $comment_len, $comment_len )."\n";
	
	( $comment_len == read( $file, $data, $comment_len ) ) or die "Error reading file!\n";
	$comment = $data;
	print "- Comment:\t\t\t".sprintf( "%s", $comment )."\n";	
}

#------------------------------------------------------------------------------

sub readEndOfCentralDir64 {
	my $file = shift;
	my $data;
	
	#TODO!
}

#------------------------------------------------------------------------------

sub readDigitalSignature {
	my $file = shift;
	my $data;
	my $dssize;
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$dssize = unpack( "v", $data );
	print "Digital Signature Size:\t\t".sprintf( "0x%04x\t\t%u", $dssize, $dssize )."\n";
	
	readRaw( $file, $dssize, "Digital Signature Data:\t\t" );
}
	
#------------------------------------------------------------------------------

sub readCentralHeader {
	my $file = shift;
	my $data;
	my $version_made_by;
	my $version_needed_to_extract;
	my $general_purpose_bit_flag;
	my $compression_method;
	my $last_mod_file_time;
	my $last_mod_file_date;
	my $crc_32;
	my $compressed_size;
	my $uncompressed_size;
	my $file_name_length;
	my $extra_field_length;
	my $file_comment_length;
	my $disk_number_start;
	my $internal_file_attributes;
	my $external_file_attributes;
	my $roffset_of_local_header;
	my $filename;
	my $comment;
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$version_made_by = unpack( "v", $data );
	print "Version made by:\t\t".sprintf( "0x%04x\t\t%u", $version_made_by, $version_made_by )."\n";
	print "---> ".TR_version_made_by( $version_made_by )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$version_needed_to_extract = unpack( "v", $data );
	print "Version needed to extract:\t".sprintf( "0x%04x\t\t%u", $version_needed_to_extract, $version_needed_to_extract )."\n";
	print "---> ".TR_version_needed_to_extract( $data )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$general_purpose_bit_flag = unpack( "v", $data );
	print "General purpose bit flag:\t".sprintf( "0x%04x\t\t%u", $general_purpose_bit_flag, $general_purpose_bit_flag )."\n";
	print "---> ".TR_general_purpose_bit_flag( $general_purpose_bit_flag )."\n";	
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$compression_method = unpack( "v", $data );
	print "Compression method:\t\t".sprintf( "0x%04x\t\t%u", $compression_method, $compression_method )."\n";
	print "---> ".TR_compression_method( $compression_method )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$last_mod_file_time = unpack( "v", $data );
	print "Last mod file time:\t\t".sprintf( "0x%04x\t\t%u", $last_mod_file_time, $last_mod_file_time )."\n";
	print "---> ".TR_time( $last_mod_file_time )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$last_mod_file_date = unpack( "v", $data );
	print "last mod file date:\t\t".sprintf( "0x%04x\t\t%u", $last_mod_file_date, $last_mod_file_date )."\n";
	print "---> ".TR_date( $last_mod_file_date )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$crc_32 = unpack( "V", $data );
	print "CRC 32:\t\t\t\t".sprintf( "0x%08x\t%u", $crc_32, $crc_32 )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$compressed_size = unpack( "V", $data );
	print "Compressed size:\t\t".sprintf( "0x%08x\t%u", $compressed_size, $compressed_size )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$uncompressed_size = unpack( "V", $data );
	print "Uncompressed size:\t\t".sprintf( "0x%08x\t%u", $uncompressed_size, $uncompressed_size )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$file_name_length = unpack( "v", $data );
	print "File name lenght:\t\t".sprintf( "0x%04x\t\t%u", $file_name_length, $file_name_length )."\n";	
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$extra_field_length = unpack( "v", $data );
	print "Extra field length:\t\t".sprintf( "0x%04x\t\t%u", $extra_field_length, $extra_field_length )."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$file_comment_length = unpack( "v", $data );
	print "File Comment length:\t\t".sprintf( "0x%04x\t\t%u", $file_comment_length, $file_comment_length )."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$disk_number_start = unpack( "v", $data );
	print "Disk number start:\t\t".sprintf( "0x%04x\t\t%u", $disk_number_start, $disk_number_start )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$internal_file_attributes = unpack( "v", $data );
	print "Internal file attributes:\t".sprintf( "0x%04x\t\t%u", $internal_file_attributes, $internal_file_attributes )."\n";
	print "---> ".TR_internal_file_attributes( $internal_file_attributes )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$external_file_attributes = unpack( "V", $data );
	print "External file attributes:\t".sprintf( "0x%08x\t%u", $external_file_attributes, $external_file_attributes )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$roffset_of_local_header = unpack( "V", $data );
	print "Relative offset local header:\t".sprintf( "0x%08x\t%u", $roffset_of_local_header, $roffset_of_local_header )."\n";	

	( $file_name_length == read( $file, $data, $file_name_length ) ) or die "Error reading file!\n";
	$filename = $data;
	print "File name:\t\t\t".sprintf( "%s", $filename )."\n";
	
	if ( $extra_field_length > 0 ) {
		EFhandler( $file, $extra_field_length, "central" );
	}
	
	( $file_comment_length == read( $file, $data, $file_comment_length ) ) or die "Error reading file!\n";
	$comment = $data;
	print "Comment:\t\t\t".sprintf( "%s", $comment )."\n";
	
	return $compressed_size;
}

#------------------------------------------------------------------------------

sub readLocalHeader {
	my $file = shift;
	my $data;
	my $version_needed_to_extract;
	my $general_purpose_bit_flag;
	my $compression_method;
	my $last_mod_file_time;
	my $last_mod_file_date;
	my $crc_32;
	my $compressed_size;
	my $uncompressed_size;
	my $file_name_length;
	my $extra_field_length;
	my $filename;
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$version_needed_to_extract = unpack( "v", $data );
	print "Version needed to extract:\t".sprintf( "0x%04x\t\t%u", $version_needed_to_extract, $version_needed_to_extract )."\n";
	print "---> ".TR_version_needed_to_extract( $data )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$general_purpose_bit_flag = unpack( "v", $data );
	print "General purpose bit flag:\t".sprintf( "0x%04x\t\t%u", $general_purpose_bit_flag, $general_purpose_bit_flag )."\n";
	print "---> ".TR_general_purpose_bit_flag( $general_purpose_bit_flag )."\n";	
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$compression_method = unpack( "v", $data );
	print "Compression method:\t\t".sprintf( "0x%04x\t\t%u", $compression_method, $compression_method )."\n";
	print "---> ".TR_compression_method( $compression_method )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$last_mod_file_time = unpack( "v", $data );
	print "Last mod file time:\t\t".sprintf( "0x%04x\t\t%u", $last_mod_file_time, $last_mod_file_time )."\n";
	print "---> ".TR_time( $last_mod_file_time )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$last_mod_file_date = unpack( "v", $data );
	print "last mod file date:\t\t".sprintf( "0x%04x\t\t%u", $last_mod_file_date, $last_mod_file_date )."\n";
	print "---> ".TR_date( $last_mod_file_date )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$crc_32 = unpack( "V", $data );
	print "CRC 32:\t\t\t\t".sprintf( "0x%08x\t%u", $crc_32, $crc_32 )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$compressed_size = unpack( "V", $data );
	print "Compressed size:\t\t".sprintf( "0x%08x\t%u", $compressed_size, $compressed_size )."\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$uncompressed_size = unpack( "V", $data );
	print "Uncompressed size:\t\t".sprintf( "0x%08x\t%u", $uncompressed_size, $uncompressed_size )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$file_name_length = unpack( "v", $data );
	print "File name lenght:\t\t".sprintf( "0x%04x\t\t%u", $file_name_length, $file_name_length )."\n";	
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$extra_field_length = unpack( "v", $data );
	print "Extra field length:\t\t".sprintf( "0x%04x\t\t%u", $extra_field_length, $extra_field_length )."\n";
	
	( $file_name_length == read( $file, $data, $file_name_length ) ) or die "Error reading file!\n";
	$filename = $data;
	print "File name:\t\t\t".sprintf( "%s", $filename )."\n";
	
	if ( $extra_field_length > 0 ) {
		#readRaw( $file, $extra_field_length, "Extra Field RAW data:\t\t" );
		EFhandler( $file, $extra_field_length, "local" );
	}
	
	return $compressed_size;
}

#------------------------------------------------------------------------------
# Generic "raw" reader
#------------------------------------------------------------------------------

sub readRaw {
	my $file = shift;
	my $size = shift;
	my $ostr = shift;
	my $rawh;
	my $data;
	
	if ( $size <= 0 ) {
		return;
	}
	
	( $size == read( $file, $data, $size ) ) or die "Error reading file!\n";
	$rawh = unpack( "H*", $data );
	
	print $ostr.sprintf( "0x%s", $rawh )."\n";
}

#------------------------------------------------------------------------------
# Extra Field mainloop handler
#------------------------------------------------------------------------------

sub EFhandler {
	my $file = shift;
	my $size = shift;
	my $where = shift;
	my $cursize;
	my $data;
	my $header_id;
	my $header_desc;
	my $header_fn;
	my $ehflag;
	my $ehcnt;
	my $ehsize;
	
	$cursize = 0;
	$ehcnt = 0;
	
	print "\tEXTRA FIELD DATA ------------------------\n";

	do {
		( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
		$header_id = unpack( "v", $data );
		$cursize += 2;
		
		$header_desc = $efhid{$header_id};
		if ( not defined( $header_desc ) ) {
			$header_desc = "Unknown";
		}
		
		$ehcnt++;
		print "\tExtra Field Number -------------------- ".$ehcnt."\n";
		
		print "\tHeader ID:\t\t".sprintf( "0x%02X", $header_id )."\t\t".$header_desc."\n";

		( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
		$ehsize = unpack( "v", $data );
		$cursize += 2;

		print "\tExtra Field size:\t".sprintf( "0x%04X\t\t%u", $ehsize, $ehsize )."\n";
		
		$header_fn = $efhidfn{$header_id};
			if ( not defined( $header_fn ) ) {
			$header_fn = "EFdefault";
		}
		
		&$header_fn( $file, $ehsize, $where );
		$cursize += $ehsize;

	} while ( $cursize < $size );
	
	print "\tEXTRA FIELD DATA END --------------------\n";
}

#------------------------------------------------------------------------------
# Extra Field handlers
#------------------------------------------------------------------------------

sub EFdefault {
	my $file = shift;
	my $size = shift;
	my $data;
	my $rawh;

	( $size == read( $file, $data, $size ) ) or die "Error reading file!\n";
	$rawh = unpack( "H*", $data );

	print "\tExtra Field RAW data:\t".sprintf( "0x%s", $rawh )."\n";	
}
	
#------------------------------------------------------------------------------

sub EFH_ZIP64e {
	my $file = shift;
	my $size = shift;
	my $data;
	my $rawh;

	( $size == read( $file, $data, $size ) ) or die "Error reading file!\n";
	$rawh = unpack( "H*", $data );

	print "\tExtra Field RAW data:\t".sprintf( "0x%s", $rawh )."\n";	
}

#------------------------------------------------------------------------------

sub EFH_AES {
	my $file = shift;
	my $size = shift;
	my $data;
	my $version;
	my $vendorid;
	my $aesversion;
	my $tmp;
	my $ctype;

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$version = unpack( "v", $data );
	if ( $version == 0x01 ) { $tmp = "AE-1"; }
	elsif ( $version == 0x02 ) { $tmp = "AE-2"; }
	else { $tmp = "unknown!"; }
	print "\tVersion:\t\t".sprintf( "0x%04X\t\t%u (%s)", $version, $version, $tmp )."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$vendorid = unpack( "v", $data );
	print "\tVendor ID:\t\t".sprintf( "0x%04X\t\t%u (%s)", $vendorid, $vendorid, $data )."\n";
	
	( 1 == read( $file, $data, 1 ) ) or die "Error reading file!\n";
	$aesversion = unpack( "C", $data );
	if ( $aesversion == 0x01 ) { $tmp = "128bit"; }
	elsif ( $aesversion == 0x02 ) { $tmp = "192bit"; }
	elsif ( $aesversion == 0x03 ) { $tmp = "256bit"; }
	else { $tmp = "unknown!"; }
	print "\tAES Strength:\t\t".sprintf( "0x%04X\t\t%u (%s)", $aesversion, $aesversion, $tmp )."\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$ctype = unpack( "v", $data );
	print "\tComp. Type:\t\t".sprintf( "0x%04X\t\t%u", $ctype, $ctype )."\n";
	print "\t---> ".TR_compression_method( $ctype )."\n";
}

#------------------------------------------------------------------------------

sub EFH_NTFS{
	my $file = shift;
	my $size = shift;
	my $cursize = 0;
	my $tagcnt = 0;
	my $data;
	my $rawh;
	my $tag;
	my $tagsize;
	my $tagdata;
	my $filetime;
	my ( $Mtime, $Ctime, $Atime );

	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$rawh = unpack( "V", $data );
	print "\t\tNTFS reserved RAW data:\t".sprintf( "0x%04X", $rawh )."\n";
	$cursize += 4;
	
	while ( $cursize < $size ) {
		( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
		$tag = unpack( "v", $data );
		$cursize += 2;
		
		$tagcnt++;
		print "\t\tTAG Number -------------------- ".$tagcnt."\n";
		
		print "\t\tTag\t\t".sprintf( "0x%04X", $tag )."\t\t".$tag."\n";

		( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
		$tagsize = unpack( "v", $data );
		$cursize += 2;

		print "\t\tTag size:\t".sprintf( "0x%04X\t\t%u", $tagsize, $tagsize )."\n";
		
		( $tagsize == read( $file, $data, $tagsize ) ) or die "Error reading file!\n";
		$tagdata = unpack( "H*", $data );
		print "\t\tTag Data:\t".sprintf( "%s", $tagdata )."\n";
		$cursize += $tagsize;
		
		if ( $tagsize == 24 ) {
			$filetime = substr( $data, 0, 8 );
			$Mtime = TR_NTFS_filetime( $filetime );
			print "\t\tModified time:\t".$Mtime." (local time)\n";
			$filetime = substr( $data, 8, 8 );
			$Atime = TR_NTFS_filetime( $filetime );
			print "\t\tAccess time:\t".$Atime." (local time)\n";
			$filetime = substr( $data, 16, 8 );
			$Ctime = TR_NTFS_filetime( $filetime );
			print "\t\tCreation time:\t".$Ctime." (local time)\n";			
		}
		else {
			print "\t\tUnrecognized NTFS Tag Data!";
		}
	}	
}

#------------------------------------------------------------------------------

sub EFH_XCEED_UNICODE {
	my $file = shift;
	my $size = shift;
	my $where = shift;
	my $data;
	my $xsign;
	my $tmp;
	my $fnlen;
	my $commentlen = 0;
	my $fnameU;
	my $commentU;
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$xsign = unpack( "V", $data );
	if ( $xsign == 0x5843554E ) { $tmp = "correct"; } else { $tmp = "not correct!"; }
	print "\t\tSignature:\t".sprintf( "0x%08X", $xsign )."\t".$xsign." (".$tmp.")\n";
	
	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$fnlen = unpack( "v", $data );
	print "\t\tName Lenght:\t".sprintf( "0x%08X", $fnlen )."\t".$fnlen."\n";
	$fnlen *= 2;
	
	if ( $where eq "central" ) {
		( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
		$commentlen = unpack( "v", $data );
		print "\t\tComment Lenght:\t".sprintf( "0x%08X", $commentlen )."\t".$commentlen."\n";
		$commentlen *= 2;
	}
	
	( $fnlen == read( $file, $data, $fnlen ) ) or die "Error reading file!\n";
	use Encode;
	$fnameU = decode( "UCS-2LE", $data );
	print "\t\tName (UCS-2LE):\t".$fnameU."\n";
	
	if ( $where eq "central" ) {
		( $commentlen == read( $file, $data, $commentlen ) ) or die "Error reading file!\n";
		use Encode;
		$commentU = decode( "UCS-2LE", $data );
		print "\t\tCom. (UCS-2LE):\t".$commentU."\n";
	}
}

#------------------------------------------------------------------------------

sub EFH_Windows_ACL {
	my $file = shift;
	my $size = shift;
	my $where = shift;
	my $data;
	my $tmpsize;
	my $bsize;
	my $version;
	my $ctype;
	my $eacrc;
	my $sddata;
	my $tmp;
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$bsize = unpack( "V", $data );
	print "\t\tUnC. SD size:\t".sprintf( "0x%08X", $bsize )."\t".$bsize."\n";
	
	if ( $where eq "central" ) {
		return;
	}

	( 1 == read( $file, $data, 1 ) ) or die "Error reading file!\n";
	$version = unpack( "C", $data );
	print "\t\tSD Version:\t".sprintf( "0x%02X", $version )."\t\t".$version."\n";

	( 2 == read( $file, $data, 2 ) ) or die "Error reading file!\n";
	$ctype = unpack( "v", $data );
	if ( $ctype == 0 ) { $tmp = "stored"; } else { $tmp = "unknown"; }
	if ( $ctype == 8 ) { $tmp = "deflated"; } else { $tmp = "unknown"; }
	print "\t\tComp. Type:\t".sprintf( "0x%04X", $ctype )."\t\t".$ctype." (".$tmp.")\n";
	
	( 4 == read( $file, $data, 4 ) ) or die "Error reading file!\n";
	$eacrc = unpack( "V", $data );
	print "\t\tCRC for SD:\t".sprintf( "0x%08X", $eacrc )."\t".$eacrc."\n";	

	if ( ( $size > 11 ) and ( $bsize > 0 ) ) {
		$tmpsize = $size - 11;
		( $tmpsize == read( $file, $data, $tmpsize ) ) or die "Error reading file!\n";
		if ( $ctype == 0 ) {
			$sddata = unpack( "H*", $data );
			print "\t\tSD RAW data:\t".sprintf( "0x%s", $sddata )."\n";
		}
		else {
			$sddata = unpack( "H*", $data );
			print "\t\tSD RAW data:\t".sprintf( "0x%s", $sddata )."\n";
		}
	}
	else {
		print "\t\tERROR, no more SD data?!\n";
	}
}

#------------------------------------------------------------------------------
# Translators
#------------------------------------------------------------------------------

sub TR_NTFS_filetime {
	my $data = shift;
	my $lo;
	my $hi;
	my $nanosecs;
	my $retstr;

    ( $lo, $hi ) = unpack( 'V2', $data );
    $nanosecs =  $hi * 2**32 + $lo;
    $retstr = scalar localtime( ( ( $nanosecs - 116444736010000000) / 1E7 ) );
	
	return $retstr;
}

#------------------------------------------------------------------------------

sub TR_version_needed_to_extract {
	my $data = shift;
	my $lowb;
	my $highb;
	my $retstr;
		
	$highb, $lowb = unpack( "C", $data );
		
	if ( $lowb == 10 ) {
		$retstr = "Default value";
	}
	elsif ( $lowb == 11 ) {
		$retstr = "File is a volume label";
	}
	elsif ( $lowb == 20 ) {
		$retstr = "File is compressed using Deflate compression, maybe encrypted";
	}
	elsif ( $lowb == 21 ) {
		$retstr = "File is compressed using Deflate64(tm)";
	}
	elsif ( $lowb == 25 ) {
		$retstr = "File is compressed using PKWARE DCL Implode ";
	}
	elsif ( $lowb == 27 ) {
		$retstr = "File is a patch data set ";
	}
	elsif ( $lowb == 45 ) {
		$retstr = "File uses ZIP64 format extensions";
	}
	elsif ( $lowb == 46 ) {
		$retstr = "File is compressed using BZIP2 compression*";
	}
	elsif ( $lowb == 50 ) {
		$retstr = "File is encrypted using DES|3DES|RC2";
	}
	elsif ( $lowb == 51 ) {
		$retstr = "File is encrypted using AES encryption OR corrected RC2 Encryption";
	}
	elsif ( $lowb == 52 ) {
		$retstr = "File is encrypted using corrected RC2-64 encryption";
	}
	elsif ( $lowb == 61 ) {
		$retstr = "File is encrypted using non-OAEP key wrapping";
	}
	elsif ( $lowb == 62 ) {
		$retstr = "Central directory encryption";
	}
	elsif ( $lowb == 63 ) {
		$retstr = "File is compressed using LZMA|PPMd+|Blowfish|Twofish";
	}
	else {
		$retstr = "Unknown version";
	}
	
	if ( $highb ) {
		$retstr .= " - High byte set, usually is zero.";
	}

	return $retstr;
}

#------------------------------------------------------------------------------

sub TR_general_purpose_bit_flag {
	my $data = shift;
	my $retstr = "File:";
	
	if ( $data & 0x0001 ) {
		$retstr .= " encrypted;";
	}
	
	if ( $data & 0x0002 ) {
		if ( $data & 0x0004 ) {
			$retstr .= " (if comp 8,9)SuperFast compression;";
		}
		else {
			$retstr .= " (if comp 8,9)Maximum compression;";
		}
	}
	else {
		if ( $data & 0x0004 ) {
			$retstr .= " (if comp 8,9)Fast compression;";
		}
		else {
			$retstr .= " (if comp 8,9)Normal compression;";
		}	
	}

	if ( $data & 0x0008 ) {
		$retstr .= " local CRC+sizes are 0;";
	}
	
	if ( $data & 0x0010 ) {
		$retstr .= " (if comp. 8)enhanced deflate;";
	}
	
	if ( $data & 0x0020 ) {
		$retstr .= " patched data (need PKZIP >= 2.70);";
	}
	
	if ( $data & 0x0040 ) {
		$retstr .= " strong encrypted;";
	}
	
	if ( $data & 0x0400 ) {
		$retstr .= " using UTF8;";
	}

	if ( $data & 0x0800 ) {
		$retstr .= " PKWARE enhanced compression;";
	}
	
	if ( $data & 0x2000 ) {
		$retstr .= " central dir encrypted and local hdr masked.";
	}

	return $retstr;
}

#------------------------------------------------------------------------------

sub TR_compression_method {
	my $data = shift;
	my $retstr;
	
	if ( $data == 0 ) {
		$retstr = "Stored";
	}
	elsif ( $data == 1 ) {
		$retstr = "Shrunk";
	}
	elsif ( $data == 2 ) {
		$retstr = "Reduced with compression factor 1";
	}
	elsif ( $data == 3 ) {
		$retstr = "Reduced with compression factor 2";
	}
	elsif ( $data == 4 ) {
		$retstr = "Reduced with compression factor 3";
	}
	elsif ( $data == 5 ) {
		$retstr = "Reduced with compression factor 4";
	}
	elsif ( $data == 6 ) {
		$retstr = "Imploded";
	}
	elsif ( $data == 7 ) {
		$retstr = "Reserved for Tokenizing compression algorithm";
	}
	elsif ( $data == 8 ) {
		$retstr = "Deflated";
	}
	elsif ( $data == 9 ) {
		$retstr = "Enhanced Deflating using Deflate64";
	}
	elsif ( $data == 10 ) {
		$retstr = "PKWARE Data Compression Library Imploding (old IBM TERSE)";
	}
	elsif ( $data == 11 ) {
		$retstr = "Reserved by PKWARE";
	}
	elsif ( $data == 12 ) {
		$retstr = "File is compressed using BZIP2 algorithm";
	}
	elsif ( $data == 13 ) {
		$retstr = "Reserved by PKWARE";
	}
	elsif ( $data == 14 ) {
		$retstr = "LZMA (EFS)";
	}
	elsif ( $data == 15 ) {
		$retstr = "Reserved by PKWARE";
	}
	elsif ( $data == 16 ) {
		$retstr = "Reserved by PKWARE";
	}
	elsif ( $data == 17 ) {
		$retstr = "Reserved by PKWARE";
	}
	elsif ( $data == 18 ) {
		$retstr = "File is compressed using IBM TERSE";
	}
	elsif ( $data == 19 ) {
		$retstr = "IBM LZ77 z Architecture (PFS)";
	}
	elsif ( $data == 97 ) {
		$retstr = "WavPack compressed data";
	}
	elsif ( $data == 98 ) {
		$retstr = "PPMd version I, Rev 1";
	}
	elsif ( $data == 99 ) {
		$retstr = "AES encrypted";
	}
	
	return $retstr;
}

#------------------------------------------------------------------------------

sub TR_time {
	my $data = shift;
	my $second;
	my $minute;
	my $hour;
	
	$second = $data & 0x001F;
	$minute = ( $data >> 5 ) & 0x003F;
	$hour = ( $data >> 11 ) & 0x001F;
	
	return sprintf( "%02u:%02u:%02u", $hour, $minute, $second );
}

#------------------------------------------------------------------------------

sub TR_date {
	my $data = shift;
	my $day;
	my $month;
	my $year;
	
	$day = $data & 0x001F;
	$month = ( $data >> 5 ) & 0x000F;
	$year = (( $data >> 9 ) & 0x007F ) + 1980;
	
	return sprintf( "%02u/%02u/%04u", $day, $month, $year );
}

#------------------------------------------------------------------------------

sub TR_internal_file_attributes {
	my $data = shift;
	my $retstr;
	
	if ( $data & 0x0001 ) {
		$retstr = "probably a text file.";
	}
	else {
		$retstr = "probably a binary file.";
	}
	
	return $retstr;
}

#------------------------------------------------------------------------------

sub TR_version_made_by {
	my $data = shift;
	my $retstr;
	my $hi;
	my $lo;
	
	$hi = $data >> 8;
	$lo = $data & 0x00FF;
	
	$retstr = "Compatibility: ";
	
	if ( $hi == 0 ) {
		$retstr .= "MSDOS(FAT) or OS2";
	}
	elsif ( $hi == 1) {
		$retstr .= "Amiga";
	}
	elsif ( $hi == 2 ) {
		$retstr .= "OpenVMS";
	}
	elsif ( $hi == 3 ) {
		$retstr .= "Unix";
	}
	elsif ( $hi == 4 ) {
		$retstr .= "VM|CMS";
	}
	elsif ( $hi == 5 ) {
		$retstr .= "Atari ST";
	}
	elsif ( $hi == 6 ) {
		$retstr .= "OS2 HPFS";
	}
	elsif ( $hi == 7 ) {
		$retstr .= "Macintosh";
	}
	elsif ( $hi == 8 ) {
		$retstr .= "Z-System";
	}
	elsif ( $hi == 9 ) {
		$retstr .= "CP-M";
	}
	elsif ( $hi == 10 ) {
		$retstr .= "Windows NTFS";
	}
	elsif ( $hi == 11 ) {
		$retstr .= "MVS";
	}
	elsif ( $hi == 12 ) {
		$retstr .= "VSE";
	}
	elsif ( $hi == 13 ) {
		$retstr .= "Acorn Risc";
	}
	elsif ( $hi == 14 ) {
		$retstr .= "VFAT";
	}
	elsif ( $hi == 15 ) {
		$retstr .= "Alternate MVS";
	}
	elsif ( $hi == 16 ) {
		$retstr .= "BeOS";
	}
	elsif ( $hi == 17 ) {
		$retstr .= "Tandem";
	}
	elsif ( $hi == 18 ) {
		$retstr .= "OS400";
	}
	elsif ( $hi == 19 ) {
		$retstr .= "OSX Darwin";
	}
	else {
		$retstr .= "Unknown";
	}
	
	$retstr .= sprintf( "; Version is %u.%u", ( $lo / 10 ),( $lo % 10 ) );
	return $retstr;
}

#------------------------------------------------------------------------------