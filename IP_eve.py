import socket
import shodan
import time
import sys
import json
import urllib
import requests
import re
import os,sys
#import conf
import unicodedata
import string
SHODAN_API_KEY = "API_KEY_HERE"
api = shodan.Shodan(SHODAN_API_KEY)
i=sys.argv[1]
try:
    print("------------------>>> Fully Qualified Domain Name <<<------------------\n\n")
    print(socket.gethostbyaddr(i))
except Exception as e:
       print("No FQDN Found.")
def g():
    time.sleep(3)
    try:
        print("\n\n------------------>>> Shodan Results <<<------------------\n\n")
        host = api.host(i)

# Print general info
        print ("""
            IP: %s
            Organization: %s
            Operating System: %s
        """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

# Print all banners
        for item in host['data']:
            print ("""
        Open Ports on IP: %s            \n""" % (item['port']))
            continue
    except Exception as e:
            print(e)

cookies = {
    'cookiebanner-accepted': '1',
    'optinmodal': 'shown',
    '__utmt': '1',
    '__utma': '67803593.580391096.1496747284.1497281718.1497345596.7',
    '__utmb': '67803593.1.10.1497345596',
    '__utmc': '67803593',
    '__utmz': '67803593.1496747284.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)',
}

headers = {
    'Origin': 'http://www.ipvoid.com',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.8',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Cache-Control': 'max-age=0',
    'Referer': 'http://www.ipvoid.com/',
    'Connection': 'keep-alive',
}
def check(i):
        print("\n\n------------------>>> Blacklist Databse Check <<<------------------\n\n")
        data = [('ip', i),]
        g=requests.post('http://www.ipvoid.com/ip-blacklist-check/', headers=headers, cookies=cookies, data=data)
	
        string1 = unicodedata.normalize('NFKD', g.text).encode('ascii','ignore')
        r = string1.translate(string.maketrans("\n\t\r", "   "))
        print("Blacklist Status : 90+ Realtime Blist db check: [empty set represnts not yet reported]")
        print(str(i)+ str(re.findall(r'BLACKLISTED \d+\/\d+',str(r))))


def abuse(i):
    print("\n\n------------------>>> Abuse Ip DB <<<------------------\n\n")
    g=requests.get("https://www.abuseipdb.com/check/"+i).text
    x=re.findall(r"This IP address has been reported a total of <b>(\d+)",g)
    y=re.findall(r"was first reported on (.*?\d\d\d\d)",g)
    z=re.findall(r"The most recent report was <b>(\d+.*?ago)</b>.",g)
    if not x:
        print("Ip was never reported on abuseipDB")
    else:
        print("Ip was reported"+str(x)+"times. This was first reported on"+str(y)+". Most Recent report was"+str(z))

def Vir(i):
    print("\n\n------------------>>> VirusTotal Scans For IP Assignement<<<------------------\n\n")
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip':i, 'apikey': 'API_KEY_HERE'}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    res=re.findall(r"last_resolved\": \"(.*?)\".*?: \"(.*?)\"",response)
    res=sorted(res,reverse=True)
    if res.count(None) == len(res):
       print("Nothing Found regarding That Ip Addres.")
    else:
         for i in res:
             print(str(i))
g()
check(i)
abuse(i)
Vir(i)
