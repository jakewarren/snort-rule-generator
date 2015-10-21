#!/usr/bin/perl
#todo add ssl cert


use Getopt::Long;

my $type = -1;
my $value = -1;


usage(),exit if (@ARGV <1 or !GetOptions ("type=s" => \$type,
    "value=s" => \$value,
    "help"=>\$help) or defined $help);


#validate command line arguments
usage("Error: Missing required parameters."),exit() if $type==-1;

usage("Error: Rule value was not provided"),exit() if($type!=-1 && $value==-1);

generateDNSQueryRule($value) if $type eq "dns-query";
generateDNSReplyIPRule($value) if $type eq "dns-reply";
generateHTTPReqRule($value) if $type eq "http-req-domain";
generateHTTPFileNameRule($value) if $type eq "http-file-name";
generateSSLCertCommonNameRule($value) if $type eq "ssl-cert-common-name";

sub generateHTTPReqRule()
{
    my $domain = shift;
    my $domainLength = length($domain);

    print 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP Request to domain - '.$domain.'"; flow:established,to_server; content:"Host|3a 20|'.$domain.'|0d 0a|"; http_header; ';

    if ($domainLength <= 12)
    {
        print "fast_pattern:only;";
    }
    elsif ($domainLength <=20)
    {
        print "fast_pattern:6,$domainLength;";
    }
    elsif ($domainLength > 20)
    {
        print "fast_pattern:6,20;";
    }

    print ' classtype:trojan-activity; sid:xxxx; rev:1;)';
    print "\n";
}


sub generateHTTPFileNameRule()
{
    my $fileName = shift;
    my $fileRegex = quotemeta $fileName;
    my $fileNameLength = length($fileName);

    print 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP Request with filename - '.$fileName.'"; flow:established,to_server; content:"'.$fileName.'"; http_uri; ';

    if($fileNameLength <= 20)
    {
        print "fast_pattern:only;";
    }
    else
    {
        print "fast_pattern:0,20;";
    }

    print ' pcre:"/'.$fileRegex.'$/U"; classtype:trojan-activity; sid:xxxx; rev:1;)';
    print "\n";
}

sub generateDNSQueryRule()
{
    my @domain = split(/\./,shift);

    print 'alert udp $HOME_NET any -> any 53 (msg:""; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"';
    foreach $token (@domain)
    {
        my $length = length($token);
        print "|". sprintf("%02x",$length). "|$token";

    }

    print '|00|"; fast_pattern; nocase; distance:0; classtype:trojan-activity; sid:xxxx; rev:1;)';
    print "\n";
}

sub generateDNSReplyIPRule
{
    my $ip = shift;

    print 'alert udp any 53 -> $HOME_NET any (msg:"DNS Reply - IP - '.$ip.'"; content:"|00 01 00 01|"; content:"|00 04 ';

    my @octets = split(/\./,$ip);
    my $index = $#octets;
    foreach (@octets)
    {
        print uc sprintf("%02x",$_);
        print " " unless !$index--;
    }

    print '|"; distance:4; within:'.($#octets+3).'; classtype:trojan-activity; sid:xxxx; rev:1;)';
    print "\n";

}

sub generateSSLCertCommonNameRule
{
    my $field = shift;

    print 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"SSL Cert - '.$field.'"; content:"|16|"; content:"|0b|"; distance:2; within:8; content:"|55 04 03|"; distance:0; content:"';
    my $length = length($field);
    print "|". sprintf("%02x",$length). "|$field";


    print '"; distance:1; within:'.($length+1).'; classtype:trojan-activity; sid:xxxx; rev:1;)';
    print "\n";

    
}


sub usage()
{
    my $msg = shift;

    if(defined($msg))
    {
        print "$msg\n";
    }

    print "\nValid Options:\n";
    print "--type => required parameter, specify type of signature you want to generate.\n";
    print "\tdns-query | dns query for a domain\n";
    print "\tdns-reply | match a dns reply containing a specified IP/CIDR\n";
    print "\thttp-req-domain | http request for a specific domain\n";
    print "\thttp-file-name | http request for a specific file name\n";
    print "\tssl-cert-common-name | download of SSL cert with specific CN (common name) field value\n";
    print "--value => required parameter, contains the key value you want to generate the signature for.\n";
    print "--help => print usage information\n";
}
