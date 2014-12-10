snort-rule-generator
====================

This script can quickly generate Snort rules for common network behaviors from IOCs. Best effort is made to make the rules efficient. 

######Usage:

```
./snort_rule_generator.pl -h

Valid Options:
--type => required parameter, specify type of signature you want to generate.
        dns-query | dns query for a domain
        dns-reply | match a dns reply containing a specified IP/CIDR
        http-req-domain | http request for a specific domain
        http-file-name | http request for a specific file name
--value => required parameter, contains the key value you want to generate the signature for.
--help => print usage information
```

######DNS queries:

```
./snort_rule_generator.pl --type dns-query --value google.com
alert udp $HOME_NET any -> any 53 (msg:""; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|06|google|03|com|00|"; fast_pattern; nocase; distance:0; classtype:trojan-activity; sid:xxxx; rev:1;)
```

######DNS replies:

```
#ip address
 ./snort_rule_generator.pl --type dns-reply --value 12.3.4.56
alert udp any 53 -> $HOME_NET any (msg:"DNS Reply - IP - 12.3.4.56"; content:"|00 01 00 01|"; content:"|00 04 0C 03 04 38|"; distance:4; within:6; classtype:trojan-activity; sid:xxxx; rev:1;)

#class c cidr
./snort_rule_generator.pl --type dns-reply --value 1.2.3
alert udp any 53 -> $HOME_NET any (msg:"DNS Reply - IP - 1.2.3."; content:"|00 01 00 01|"; content:"|00 04 01 02 03|"; distance:4; within:5; classtype:trojan-activity; sid:xxxx; rev:1;)
```

######HTTP domains:

```
./snort_rule_generator.pl --type http-req-domain --value google.com
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP Request to domain - google.com"; flow:established,to_server; content:"Host|3a 20|google.com|0d 0a|"; http_header; fast_pattern:only; classtype:trojan-activity; sid:xxxx; rev:1;)
```

######HTTP requests containing a file name:

```
./snort_rule_generator.pl --type http-file-name --value malware.exe
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP Request with filename - malware.exe"; flow:established,to_server; content:"malware.exe"; http_uri; fast_pattern:only; pcre:"/malware\.exe$/U"; classtype:trojan-activity; sid:xxxx; rev:1;)
```
