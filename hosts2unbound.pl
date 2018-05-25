#!/usr/bin/perl

=pod

=head1 NAME

hosts2unbound - extends the unbound blocklist with simple host file(s), unbound config file(s) or single host(s)

=head1 SYNOPSIS

B<hosts2unbound> -o|--output-file I<file> [-i|--input-file I<file>] [-h|--host I<string>]

=head1 DESCRIPTION

hosts2unbound is used as a helper script together with a working unbound configuration. It requires a separate unbound include file which stores only blocked sites, respectively. This so called output file will be overwritten during runtime. One or more input files can be also added with simple hosts file syntax or with the complex unbound syntax. The input file(s) will be interpreted and merged together with the content of the output file.

Also one or more single hosts with domain ending can be added as well.

When all the files and hosts are processed, the script can reload the unbound configuration with the C<unbound-control reload> command, if needed. After the reload all modifications are applied.

The script requires almost as much memory as the size of the files, since the hostnames with domain name will be stored in memory, before they are flused with the appropriate unbound deny syntax to the output file.

=head1 OPTIONS

=over 12

=item B<-o|--output-file> file

Unbound include file, which contains a blocked list. Only one can be used. Unbound should be configured to use this file. This parameter is obligatory.

=item B<-i|--input-file> file

Simple host file, or blocklist with unbound syntax. This file will be merged together with the output file content and written to the output file.

=item B<-h|--host> hostname

Single hostname with domain ending, which will be added to the output file.

=back

=head1 EXAMPLES

hosts2unbound -o /var/unbound/etc/ads.conf -i new_ads -i dangerous_sites.txt --host deny.org -h deny2.com

Unbound configuration file is loaded as output file. The content of two new files C<new_ads> and C<dangerous_sites.txt> will be processed. Two sites added as well: C<deny.org> and C<deny2.com>

hosts2unbound --output-file /var/unbound/etc/ads.conf

Only the unbound configuration file is loaded. At least duplicates removed if any.

=head1 SEE ALSO

I<unbound>(8), I<unbound.conf>(5)

=head1 AUTHOR

Kiss Zoltan Laszlo, email: laszlo.zoltan.kiss@gmail.com

=head1 HISTORY

Created: 2018.03.07

Last modification: 2018.03.08

=cut

use strict;
use warnings;
use Getopt::Long qw(GetOptions);

my $output_file;   # simple/unbound hosts file which will contain the unbound hosts file
my @input_files;   # simple/unbound hosts files to parse, but will not hold the parsed
my @new_hostnames; # separately given new hostnames

GetOptions(	'output-file|o=s' => \$output_file,
		'input-file|i=s' => \@input_files,
		'host|h=s' => \@new_hostnames);

my $parsed_output_hash; # hostname as key and zero string as value, will contain complete list

if ($output_file && -e $output_file) {
	$parsed_output_hash = get_hosts ($output_file);
} else { die "Usage: $0 -o|--output-file I<file> [-i|--input-file I<file>] [-h|--host I<string>]\n" };

if (@input_files) {
	my @input_hosts_list; # list of the hashes of the hosts from the input files
	foreach my $input_file (@input_files) {
		my $input_ref=get_hosts ($input_file);
		push @input_hosts_list, $input_ref;
	}
	$parsed_output_hash = join_hashes ($parsed_output_hash, @input_hosts_list);
}

if (@new_hostnames) {
	foreach my $host (@new_hostnames) {
		$$parsed_output_hash {$host} = '';
	}
}

write_output($parsed_output_hash, $output_file);

print "Would you like to reload unbound? ";
my $key;
do {
  print "(y)es or (n)o\n";
  open(TTY, "+</dev/tty") or die "no tty: $!";
  system "stty -echo cbreak </dev/tty >/dev/tty 2>&1";
  sysread(TTY, $key, 1);
  system "stty echo -cbreak </dev/tty >/dev/tty 2>&1";
} until ( ($key eq 'y') or ($key eq 'n') );

if ($key eq 'y') {
 my $unbound_response = `unbound-control reload`;
 print "Unbound reload: " . $unbound_response . "\n";
} else {
 print "Unbound is not reloaded!\n";
}

sub get_hosts {
	my $filename = shift;
	my %hosts;
	open (my $fh, "<", $filename) or die "Could not open '$filename' $!";
	while (my $row = <$fh>) {
		chomp $row; # removing line feed
	        $row =~ s/\015//g; # removing  carriage return
	        $row =~ s/\t+/ /g; # replacing tab with single space
	        $row =~ s/\s+/ /g; # replacing multiple space with single
		if ($row =~ m/^0.0.0.0/ or $row =~ m/^127.0.0.1/) {
			my $host = (split / /, $row)[1];
			$hosts{$host} = '';
		}
		if ($row =~ m/^local-zone/) {
			my $host = (split /\"/, $row)[1];
			$hosts{$host} = '';
		}
	}
	close $fh;
	return \%hosts;
}

sub join_hashes {
 	my $hash_ref1 = shift;
	while (my $hash_ref2 = shift) {
 		%$hash_ref1 = (%$hash_ref1, %$hash_ref2);
 	};
 	return $hash_ref1;
}

sub write_output {
	my $hosts_ref = shift;
	my $filename = shift;
	open (my $fh, ">", $filename) or die "Could not open '$filename' $!";
	foreach my $host (keys %$hosts_ref) {
			print $fh "local-zone: \"$host\" redirect\n";
			print $fh "local-data: \"$host A 0.0.0.0\"\n";
	}
	close $fh;
}
