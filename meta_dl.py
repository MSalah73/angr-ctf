import requests
import sys
from bs4 import BeautifulSoup
if len(sys.argv) != 4:
    print("Usage: python meta_dl.py <hostname> <username> <password>")
    print("E.g  : python meta_dl.py malware.oregonctf.org gse0 malware")
    exit(0)
hostname = sys.argv[1]
username = sys.argv[2]
passwd = sys.argv[3]
sets = ['Ch01-2','Ch3.1-3.5','Ch3.6-3.8','Ch3.9-3.11','Ch5-8','Extra-FormatStr']
s = requests.Session()
url='https://'+hostname+'/login/'
resp = s.post(url,data={'username':username,'passwd':passwd})
url='https://'+hostname+'/download/'
resp = s.get(url)
soup = BeautifulSoup(resp.text,'html.parser')
input_tags = soup.find_all('input',{'type':'radio'})
for input_tag in input_tags:
    setname = input_tag.attrs['value']
    resp = s.post(url,data={'setname':setname})
    if resp.status_code == 200:
        with open(setname+'.zip','wb') as f:
            f.write(resp.content)
            f.close()
