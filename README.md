# Everything-IP
Check Detailed information for Ip Address.

This script is quick hack to check everything about ip at work place. 
Ip address will be resolved to Hostname, will be checked in world's famous security search engine Shodan for results. 

A realtime Blacklist check is done, comparing nearly 90+ realtime Blacklist services against the given IP. 
Data Like when was this ip reported (If reported abused by users) , the first time it got reported to what was the recent report date and time including numbers of users/ times IP got commented as abused by users.
Virustotal API is used to lookup all the domain names IP ever holded.

Signup for Shodan and Virustotal to Gain free API keys and input them in script (Place Holder where API keys has to replaced are written has 'API_KEY_HERE') 1st appreance of API_KEY_HERE to be replaced with SHODAN api followed by Virustotal.

USAGE:

python IP_eve.py <IP_ADDRESS_HERE>
