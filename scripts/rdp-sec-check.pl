#!/usr/bin/perl
# rdp-sec-check
# Copyright (C) 2014 Mark lowe (mrl@portcullis-security.com)
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then 
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as 
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at mrl@portcullis-security.com
#
# Dependencies:
#
# CPAN module Encoding::BER.  As root:
#   # cpan
#   cpan[1]> install Encoding::BER
#
# References:
#
# [MS-RDPBCGR]: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting Specification
# http://msdn.microsoft.com/en-us/library/cc240445(v=prot.10).aspx
# 
use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long;
use Encoding::BER;

my %rdp_neg_type;
$rdp_neg_type{"01"} = "TYPE_RDP_NEG_REQ";
$rdp_neg_type{"02"} = "TYPE_RDP_NEG_RSP";
$rdp_neg_type{"03"} = "TYPE_RDP_NEG_FAILURE";

my %rdp_neg_rsp_flags;
$rdp_neg_rsp_flags{"00"} = "NO_FLAGS_SET";
$rdp_neg_rsp_flags{"01"} = "EXTENDED_CLIENT_DATA_SUPPORTED";
$rdp_neg_rsp_flags{"02"} = "DYNVC_GFX_PROTOCOL_SUPPORTED";

my %rdp_neg_protocol;
$rdp_neg_protocol{"00"} = "PROTOCOL_RDP";
$rdp_neg_protocol{"01"} = "PROTOCOL_SSL";
$rdp_neg_protocol{"02"} = "PROTOCOL_HYBRID";

my %rdp_neg_failure_code;
$rdp_neg_failure_code{"01"} = "SSL_REQUIRED_BY_SERVER";
$rdp_neg_failure_code{"02"} = "SSL_NOT_ALLOWED_BY_SERVER";
$rdp_neg_failure_code{"03"} = "SSL_CERT_NOT_ON_SERVER";
$rdp_neg_failure_code{"04"} = "INCONSISTENT_FLAGS";
$rdp_neg_failure_code{"05"} = "HYBRID_REQUIRED_BY_SERVER";
$rdp_neg_failure_code{"06"} = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";

my %encryption_level;
$encryption_level{"00000000"} = "ENCRYPTION_LEVEL_NONE";
$encryption_level{"00000001"} = "ENCRYPTION_LEVEL_LOW";
$encryption_level{"00000002"} = "ENCRYPTION_LEVEL_CLIENT_COMPATIBLE";
$encryption_level{"00000003"} = "ENCRYPTION_LEVEL_HIGH";
$encryption_level{"00000004"} = "ENCRYPTION_LEVEL_FIPS";

my %encryption_method;
$encryption_method{"00000000"} = "ENCRYPTION_METHOD_NONE";
$encryption_method{"00000001"} = "ENCRYPTION_METHOD_40BIT";
$encryption_method{"00000002"} = "ENCRYPTION_METHOD_128BIT";
$encryption_method{"00000008"} = "ENCRYPTION_METHOD_56BIT";
$encryption_method{"00000010"} = "ENCRYPTION_METHOD_FIPS";

my %version_meaning;
$version_meaning{"00080001"} = "RDP 4.0 servers";
$version_meaning{"00080004"} = "RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, and 8.0 servers";

my $enc = Encoding::BER->new(warn => sub{});
my %config;

my $VERSION = "0.9-beta";
my $usage = "Starting rdp-sec-check v$VERSION ( http://labs.portcullis.co.uk/application/rdp-sec-check/ )
Copyright (C) 2014 Mark Lowe (mrl\@portcullis-security.com)

$0 [ options ]  ( --file hosts.txt | host | host:port )

options are:

  --file hosts.txt	targets, one ip:port per line
  --outfile out.log	output logfile
  --timeout sec		receive timeout (default 10s)
  --retries times	number of retries after timeout
  --verbose				
  --debug
  --help
        
Example:
         $0 192.168.1.1
         $0 --file hosts.txt --timeout 15 --retries 3
         $0 --outfile rdp.log 192.168.69.69:3389
         $0 --file hosts.txt --outfile rdp.log --verbose

";

my $debug    = 0;
my $verbose  = 0;
my $help = 0;
my $hostfile = undef;
my $outfile = undef;
my @targets = ();

my $global_recv_timeout = 10;
my $global_connect_fail_count = 5;
my $global_connection_count = 0;

my $result = GetOptions (
         "verbose"   => \$verbose,
         "debug"     => \$debug,
         "help"      => \$help,
         "file=s"    => \$hostfile,
         "outfile=s" => \$outfile,
         "timeout=i" => \$global_recv_timeout,
         "retries=i" => \$global_connection_count,
);

if ($help) {
	print $usage;
	exit 0;
}

if ($debug) {
	use Data::Dumper;
	use warnings FATAL => 'all';
	use Carp qw(confess);
	$SIG{ __DIE__ } = sub { confess( @_ ) };
}

if (defined($outfile)){
        # http://stackoverflow.com/questions/1631873/copy-all-output-of-a-perl-script-into-a-file
        use Symbol;
        my @handles = (*STDOUT);
        my $handle = gensym( );
        push(@handles, $handle);
        open $handle, ">$outfile" or die "[E] Can't write to $outfile: $!\n"; #open for write, overwrite; 
        tie *TEE, "Tie::Tee", @handles;
        select(TEE);
        *STDERR = *TEE;
}

if (defined($hostfile)) {
        open HOSTS, "<$hostfile" or die "[E] Can't open $hostfile: $!\n";
        while (<HOSTS>) {
                chomp; chomp;
                my $line = $_;
                my $port = 3389;
                my $host = $line;
                if ($line =~ /\s*(\S+):(\d+)\s*/) {
                        $host = $1;
                        $port = $2;
                }
                my $ip = resolve($host);
                if (defined($ip)) {
                        push @targets, { ip => $ip, hostname => $host, port => $port };
                } else {
                        print "[W] Unable to resolve host $host.  Ignoring line: $line\n";
                }
        }
        close(HOSTS);

} else {
        my $host = shift or die $usage;
        my $port = 3389;
        if ($host =~ /\s*(\S+):(\d+)\s*/) {
                $host = $1;
                $port = $2;
        }
        my $ip = resolve($host);
        unless (defined($ip)) {
                die "[E] Can't resolve hostname $host\n";
        }
        push @targets, { ip => $ip, hostname => $host, port => $port };
}

# flush after every write
$| = 1;

my $global_starttime = time;
printf "Starting rdp-sec-check v%s ( http://labs.portcullis.co.uk/application/rdp-sec-check/ ) at %s\n", $VERSION, scalar(localtime);
printf "\n[+] Scanning %s hosts\n", scalar @targets;
print Dumper \@targets if $debug > 0;

foreach my $target_addr (@targets) {
        scan_host($target_addr->{hostname}, $target_addr->{ip}, $target_addr->{port});
}

print "\n";
printf "rdp-sec-check v%s completed at %s\n", $VERSION, scalar(localtime);
print "\n";

sub scan_host {
	my ($host, $ip, $port) = @_;
	print "\n";
	print "Target:    $host\n";
	print "IP:        $ip\n";
	print "Port:      $port\n";
	print "\n";
	print "[+] Connecting to $ip:$port\n" if $debug > 1;
	my $socket;
	my @response;

	print "[+] Checking supported protocols\n\n";
	print "[-] Checking if RDP Security (PROTOCOL_RDP) is supported...";
	$socket = get_socket($ip, $port);
	@response = test_std_rdp_security($socket);
	if (scalar @response == 19) {
		my $type = $rdp_neg_type{sprintf "%02x", ord($response[11])};
		if ($type eq "TYPE_RDP_NEG_FAILURE") {
			printf "Not supported - %s\n", $rdp_neg_failure_code{sprintf("%02x", ord($response[15]))};
			$config{"protocols"}{"PROTOCOL_RDP"} = 0;
		} else {
			if ($rdp_neg_protocol{sprintf("%02x", ord($response[15]))} eq "PROTOCOL_RDP") {
				print "Supported\n";
				$config{"protocols"}{"PROTOCOL_RDP"} = 1;
			} else {
				printf "Not supported.  Negotiated %s\n", $rdp_neg_protocol{sprintf("%02x", ord($response[15]))};
			}
		}
	} elsif (scalar @response == 11) {
		printf "Negotiation ignored - old Windows 2000/XP/2003 system?\n";
		$config{"protocols"}{"PROTOCOL_RDP"} = 1;
	} else {
		print "Not supported - unexpected response\n";
		$config{"protocols"}{"PROTOCOL_RDP"} = 1;
	}

	print "[-] Checking if TLS Security (PROTOCOL_SSL) is supported...";
	$socket = get_socket($ip, $port);
	@response = test_tls_security($socket);
	if (scalar @response == 19) {
		my $type = $rdp_neg_type{sprintf "%02x", ord($response[11])};
		if ($type eq "TYPE_RDP_NEG_FAILURE") {
			printf "Not supported - %s\n", $rdp_neg_failure_code{sprintf("%02x", ord($response[15]))};
			$config{"protocols"}{"PROTOCOL_SSL"} = 0;
		} else {
			if ($rdp_neg_protocol{sprintf("%02x", ord($response[15]))} eq "PROTOCOL_SSL") {
				print "Supported\n";
				$config{"protocols"}{"PROTOCOL_SSL"} = 1;
			} else {
				printf "Not supported.  Negotiated %s\n", $rdp_neg_protocol{sprintf("%02x", ord($response[15]))};
			}
		}
	} elsif (scalar @response == 11) {
		printf "Negotiation ignored - old Windows 2000/XP/2003 system?\n";
		$config{"protocols"}{"PROTOCOL_SSL"} = 0;
	} else {
		print "Not supported - unexpected response\n";
		$config{"protocols"}{"PROTOCOL_SSL"} = 0;
	}

	print "[-] Checking if CredSSP Security (PROTOCOL_HYBRID) is supported [uses NLA]...";
	$socket = get_socket($ip, $port);
	@response = test_credssp_security($socket);
	if (scalar @response == 19) {
		my $type = $rdp_neg_type{sprintf "%02x", ord($response[11])};
		if ($type eq "TYPE_RDP_NEG_FAILURE") {
			printf "Not supported - %s\n", $rdp_neg_failure_code{sprintf("%02x", ord($response[15]))};
			$config{"protocols"}{"PROTOCOL_HYBRID"} = 0;
		} else {
			if ($rdp_neg_protocol{sprintf("%02x", ord($response[15]))} eq "PROTOCOL_HYBRID") {
				print "Supported\n";
				$config{"protocols"}{"PROTOCOL_HYBRID"} = 1;
			} else {
				printf "Not supported.  Negotiated %s\n", $rdp_neg_protocol{sprintf("%02x", ord($response[15]))};
			}
		}
	} elsif (scalar @response == 11) {
		printf "Negotiation ignored - old Windows 2000/XP/2003 system??\n";
		$config{"protocols"}{"PROTOCOL_HYBRID"} = 0;
	} else {
		print "Not supported - unexpected response\n";
		$config{"protocols"}{"PROTOCOL_HYBRID"} = 0;
	} 
	print "\n";
	print "[+] Checking RDP Security Layer\n\n";
	foreach my $enc_hex (qw(00 01 02 08 10)) {
		printf "[-] Checking RDP Security Layer with encryption %s...", $encryption_method{"000000" . $enc_hex};
		$socket = get_socket($ip, $port);
		@response = test_classic_rdp_security($socket);
	
		if (scalar @response == 11) {
			my @response_mcs = test_mcs_initial_connect($socket, $enc_hex);
			unless (scalar(@response_mcs) > 8) {
				print "Not supported\n";
				next;
			}
			my $length1 = ord($response_mcs[8]);
			my $ber_encoded = join("", splice @response_mcs, 7);
			my $ber = $enc->decode($ber_encoded);
			my $user_data = $ber->{value}->[3]->{value};
			my ($sc_core, $sc_sec) = $user_data =~ /\x01\x0c..(.*)\x02\x0c..(.*)/s;
			
			my ($version, $client_requested_protocols, $early_capability_flags) = $sc_core =~ /(....)(....)?(....)?/;
			my ($encryption_method, $encryption_level, $random_length, $server_cert_length) = $sc_sec =~ /(....)(....)(....)(....)/;
			my $server_cert_length_i = unpack("V", $server_cert_length);
			my $random_length_i = unpack("V", $random_length);
			if ("000000" . $enc_hex eq sprintf "%08x", unpack("V", $encryption_method)) {
				printf "Supported.  Server encryption level: %s\n", $encryption_level{sprintf "%08x", unpack("V", $encryption_level)};
				$config{"encryption_level"}{$encryption_level{sprintf "%08x", unpack("V", $encryption_level)}} = 1;
				$config{"encryption_method"}{$encryption_method{sprintf "%08x", unpack("V", $encryption_method)}} = 1;
				$config{"protocols"}{"PROTOCOL_RDP"} = 1; # This is the only way the script detects RDP support on 2000/XP
			} else {
				printf "Not supported.  Negotiated %s.  Server encryption level: %s\n", $encryption_method{sprintf "%08x", unpack("V", $encryption_method)}, $encryption_level{sprintf "%08x", unpack("V", $encryption_level)};
				$config{"encryption_level"}{$encryption_level{sprintf "%08x", unpack("V", $encryption_level)}} = 0;
				$config{"encryption_method"}{$encryption_method{sprintf "%08x", unpack("V", $encryption_method)}} = 0;
			}
			my $random = substr $sc_sec, 16, $random_length_i;	
			my $cert = substr $sc_sec, 16 + $random_length_i, $server_cert_length_i;	
		} else {
			print "Not supported\n";
		}
	}

	if ($config{"protocols"}{"PROTOCOL_HYBRID"}) {
		if ($config{"protocols"}{"PROTOCOL_SSL"} or $config{"protocols"}{"PROTOCOL_RDP"}) {	
			$config{"issues"}{"NLA_SUPPORTED_BUT_NOT_MANDATED_DOS"} = 1;
		}
	} else {
		# is this really a problem?
		$config{"issues"}{"NLA_NOT_SUPPORTED_DOS"} = 1;
	}

	if ($config{"protocols"}{"PROTOCOL_RDP"}) {
		if ($config{"protocols"}{"PROTOCOL_SSL"} or $config{"protocols"}{"PROTOCOL_HYBRID"}) {	
			$config{"issues"}{"SSL_SUPPORTED_BUT_NOT_MANDATED_MITM"} = 1;
		} else {
			$config{"issues"}{"ONLY_RDP_SUPPORTED_MITM"} = 1;
		}

		if ($config{"encryption_method"}{"ENCRYPTION_METHOD_40BIT"} or $config{"encryption_method"}{"ENCRYPTION_METHOD_56BIT"}) {
			$config{"issues"}{"WEAK_RDP_ENCRYPTION_SUPPORTED"} = 1;
		}

		if ($config{"encryption_method"}{"ENCRYPTION_METHOD_NONE"}) {
			$config{"issues"}{"NULL_RDP_ENCRYPTION_SUPPORTED"} = 1;
		}

		if ($config{"encryption_method"}{"ENCRYPTION_METHOD_FIPS"} and ($config{"encryption_method"}{"ENCRYPTION_METHOD_NONE"} or $config{"encryption_method"}{"ENCRYPTION_METHOD_40BIT"} or $config{"encryption_method"}{"ENCRYPTION_METHOD_56BIT"} or $config{"encryption_method"}{"ENCRYPTION_METHOD_128BIT"})) {
			$config{"issues"}{"FIPS_SUPPORTED_BUT_NOT_MANDATED"} = 1;
		}
	}

	print "\n";
	print "[+] Summary of protocol support\n\n";
	foreach my $protocol (keys(%{$config{"protocols"}})) {
		printf "[-] $ip:$port supports %-15s: %s\n", $protocol, $config{"protocols"}{$protocol} ? "TRUE" : "FALSE";
	}

	print "\n";
	print "[+] Summary of RDP encryption support\n\n";
	foreach my $encryption_level (sort keys(%{$config{"encryption_level"}})) {
		printf "[-] $ip:$port has encryption level: %s\n", $encryption_level;
	}
	foreach my $encryption_method (sort keys(%encryption_method)) {
		printf "[-] $ip:$port supports %-25s: %s\n", $encryption_method{$encryption_method}, (defined($config{"encryption_method"}{$encryption_method{$encryption_method}}) and $config{"encryption_method"}{$encryption_method{$encryption_method}}) ? "TRUE" : "FALSE";
	}

	print "\n";
	print "[+] Summary of security issues\n\n";
	foreach my $issue (keys(%{$config{"issues"}})) {
		print "[-] $ip:$port has issue $issue\n";
	}

	print Dumper \%config if $debug;
}

sub test_std_rdp_security {
	my ($socket) = @_;
	my $string = get_x224_crq_std_rdp_security();
	return do_handshake($socket, $string);
}

sub test_tls_security {
	my ($socket) = @_;
	my $string = get_x224_crq_tls_security();
	return do_handshake($socket, $string);
}

sub test_credssp_security {
	my ($socket) = @_;
	my $string = get_x224_crq_credssp_security();
	return do_handshake($socket, $string);
}

sub test_classic_rdp_security {
	my ($socket) = @_;
	my $string = get_x224_crq_classic();
	return do_handshake($socket, $string);
}

sub test_mcs_initial_connect {
	my ($socket, $enc_hex) = @_;
	my $string = get_mcs_initial_connect($enc_hex);
	return do_handshake($socket, $string);
}

sub do_handshake {
	my ($socket, $string) = @_;
	print "[+] Sending:\n" if $debug > 1;
	hdump($string) if $debug > 1;
	
	print $socket $string;
	
        my $data;

        local $SIG{ALRM} = sub { die "alarm\n" };
        eval {
            alarm($global_recv_timeout);
            $socket->recv($data,4);
            alarm(0);
        };
        if ($@) {
            print "[W] Timeout on recv.  Results may be unreliable.\n";
        }

	if (length($data) == 4) {
		print "[+] Received from Server :\n" if $debug > 1;
		hdump($data) if $debug > 1;
		my @data = split("", $data);
		my $length = (ord($data[2]) << 8) + ord($data[3]);
		printf "[+] Initial length: %d\n", $length if $debug > 1;
		my $data2 = "";
		while (length($data) < $length) {
                        local $SIG{ALRM} = sub { die "alarm\n" };
                        eval {
                            alarm($global_recv_timeout);
                            $socket->recv($data2,$length - 4);
                            alarm(0);
                        };
                        if ($@) {
                            print "[W] Timeout on recv.  Results may be unreliable.\n";
                        }
			print "[+] Received " . length($data2) . " bytes from Server :\n" if $debug > 1;
			hdump($data2) if $debug > 1;
			$data .= $data2;
		}
		return split "", $data;
	} else {
		return undef;
	}
}

# http://www.perlmonks.org/?node_id=111481
sub hdump {
        my $offset = 0;
        my(@array,$format);
        foreach my $data (unpack("a16"x(length($_[0])/16)."a*",$_[0])) {
                my($len)=length($data);
                if ($len == 16) {
                        @array = unpack('N4', $data);
                        $format="0x%08x (%05d)   %08x %08x %08x %08x   %s\n";
                } else {
                        @array = unpack('C*', $data);
                        $_ = sprintf "%2.2x", $_ for @array;
                        push(@array, '  ') while $len++ < 16;
                        $format="0x%08x (%05d)" .
                           "   %s%s%s%s %s%s%s%s %s%s%s%s %s%s%s%s   %s\n";
                } 
                    $data =~ tr/\0-\37\177-\377/./;
                    printf $format,$offset,$offset,@array,$data;
                    $offset += 16;
        }
}

sub get_x224_crq_std_rdp_security {
	return get_x224_connection_request("00");
}

sub get_x224_crq_tls_security {
	return get_x224_connection_request("01");
}

sub get_x224_crq_credssp_security {
	return get_x224_connection_request("03");
}

sub get_x224_crq_classic {
	return get_old_connection_request();
}

# enc_hex is bitmask of:
# 01 - 40 bit
# 02 - 128 bit
# 08 - 56 bit
# 10 - fips
#
# common value sniffed from wireshark: 03
sub get_mcs_initial_connect {
	my $enc_hex = shift;
	my @packet_hex = qw(
	03 00  01 a2 02 f0 80 7f 65 82
	01 96 04 01 01 04 01 01  01 01 ff 30 20 02 02 00
	22 02 02 00 02 02 02 00  00 02 02 00 01 02 02 00
	00 02 02 00 01 02 02 ff  ff 02 02 00 02 30 20 02
	02 00 01 02 02 00 01 02  02 00 01 02 02 00 01 02
	02 00 00 02 02 00 01 02  02 04 20 02 02 00 02 30
	20 02 02 ff ff 02 02 fc  17 02 02 ff ff 02 02 00
	01 02 02 00 00 02 02 00  01 02 02 ff ff 02 02 00
	02 04 82 01 23 00 05 00  14 7c 00 01 81 1a 00 08
	00 10 00 01 c0 00 44 75  63 61 81 0c 01 c0 d4 00
	04 00 08 00 20 03 58 02  01 ca 03 aa 09 04 00 00
	28 0a 00 00 68 00 6f 00  73 00 74 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 04 00 00 00  00 00 00 00 0c 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	01 ca 01 00 00 00 00 00  18 00 07 00 01 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	04 c0 0c 00 09 00 00 00  00 00 00 00 02 c0 0c 00
	);
	push @packet_hex, $enc_hex;
	push @packet_hex, qw(00 00 00 00 00 00 00  03 c0 20 00 02 00 00 00
	63 6c 69 70 72 64 72 00  c0 a0 00 00 72 64 70 64
	72 00 00 00 80 80 00 00                         
	);
	my $string = join("", @packet_hex);
	$string =~ s/(..)/sprintf("%c", hex($1))/ge;
	return $string;
}

# MS-RDPBCGR
sub get_x224_connection_request {
	my $sec = shift;
	my @packet_hex;
	push @packet_hex, qw(03); # tpktHeader - version
	push @packet_hex, qw(00); # tpktHeader - reserved
	push @packet_hex, qw(00 13); # tpktHeader - length
	push @packet_hex, qw(0e); # x224Crq - length
	push @packet_hex, qw(e0); # x224Crq - connection request
	push @packet_hex, qw(00 00); # x224Crq - ??
	push @packet_hex, qw(00 00); # x224Crq - src-ref
	push @packet_hex, qw(00); # x224Crq - class
	push @packet_hex, qw(01); # rdpNegData - type
	push @packet_hex, qw(00); # rdpNegData - flags
	push @packet_hex, qw(08 00); # rdpNegData - length
	push @packet_hex, ($sec, qw(00 00  00)); # rdpNegData - requestedProtocols.  bitmask, little endian: 0=standard rdp security, 1=TLSv1, 2=Hybrid (CredSSP)

	my $string = join("", @packet_hex);
	$string =~ s/(..)/sprintf("%c", hex($1))/ge;
	return $string;
}

sub get_old_connection_request {
	my @packet_hex = qw(
		03 00  00 22 1d e0 00 00 00 00
		00 43 6f 6f 6b 69 65 3a  20 6d 73 74 73 68 61 73
		68 3d 72 6f 6f 74 0d 0a                        
	);
	my $string = join("", @packet_hex);
	$string =~ s/(..)/sprintf("%c", hex($1))/ge;
	return $string;
}

sub get_socket {
	my ($ip, $port) = @_;
	my $socket = undef;
	my $failcount = 0;
	while (!defined($socket)) {
		$global_connection_count++;
		eval {
			local $SIG{ALRM} = sub { die "alarm\n" };
			alarm($global_recv_timeout);
			$socket = new IO::Socket::INET (
				PeerHost => $ip,
				PeerPort => $port,
				Proto => 'tcp',
			) or print "WARNING in Socket Creation : $!\n";
			alarm(0);
		};
		if ($@) {
			print "[W] Timeout on connect.  Retrying...\n";
			return undef;
		}
		unless (defined($socket)) {
			$failcount++;
		}
		if ($failcount > $global_connect_fail_count) {
			die "ERROR: failed to connect $global_connect_fail_count times\n";
		}
	}
	return $socket;
}

sub print_section {
        my ($string) = @_;
        print "\n=== $string ===\n\n";
}

sub resolve {
        my $hostname = shift;
        print "[D] Resolving $hostname\n" if $debug > 0;
        my $ip =  gethostbyname($hostname);
        if (defined($ip)) {
                return inet_ntoa($ip);
        } else {
                return undef;
        }
}

# Perl Cookbook, Tie Example: Multiple Sink Filehandles
package Tie::Tee;

sub TIEHANDLE {
        my $class = shift;
        my $handles = [@_];
        bless $handles, $class;
        return $handles;
}

sub PRINT {
        my $href = shift;
        my $handle;
        my $success = 0;
        foreach $handle (@$href) {
                $success += print $handle @_;
        }
        return $success == @$href;
}

sub PRINTF {
        my $href = shift;
        my $handle;
        my $success = 0;
        foreach $handle (@$href) {
                $success += printf $handle @_;
        }
        return $success == @$href;
}

1;

