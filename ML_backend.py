import pandas as pd
from xgboost import XGBClassifier
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import wget
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import requests

wget.download('http://data.phishtank.com/data/online-valid.csv', './online-valid.csv')

datasetphish = pd.read_csv(r"./online-valid.csv")
datasetphish.head()

phishurldata = datasetphish.sample(n = 5000, random_state = 12).copy()
phishurldata = phishurldata.reset_index(drop=True)
phishurldata.head()

datasetlegi = pd.read_csv(r"./Benign_list_big_final.csv")
datasetlegi.columns = ['URLs']
datasetlegi.head()

legiurldata = datasetlegi.sample(n = 5000, random_state = 12).copy()
legiurldata = legiurldata.reset_index(drop=True)
legiurldata.head()

def Domainextract(url):  
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
	       domain = domain.replace("www.","")
  return domain

def IPextract(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

def AtSignextract(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at

def Lengthextract(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length

def Depthextract(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

def urlredirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

def gethttpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"                       r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"                       r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"                       r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"                       r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"                       r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"                       r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"                       r"tr\.im|link\.zip\.net"

def gettinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

def extractprefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            
    else:
        return 0           

def getweb_traffic(url):
  try:
    #Filling the whitespaces in the URL if any
    url = urllib.parse.quote(url)
    rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
        "REACH")['RANK']
    rank = int(rank)
  except TypeError:
        return 1
  if rank <100000:
    return 1
  else:
    return 0

def getAgedomain(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

def getEnddomain(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

def getiframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1

def getmouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

def getrightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

def getforwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1

def featureExtraction(url,label):

  featuresdata = []
  featuresdata.append(Domainextract(url))
  featuresdata.append(IPextract(url))
  featuresdata.append(AtSignextract(url))
  featuresdata.append(Lengthextract(url))
  featuresdata.append(Depthextract(url))
  featuresdata.append(urlredirection(url))
  featuresdata.append(gethttpDomain(url))
  featuresdata.append(gettinyURL(url))
  featuresdata.append(extractprefixSuffix(url))
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
    
  except:
    dns = 1

  featuresdata.append(dns)
  featuresdata.append(getweb_traffic(url))
  featuresdata.append(1 if dns == 1 else getAgedomain(domain_name))
  featuresdata.append(1 if dns == 1 else getEnddomain(domain_name))
  
  try:
    response = requests.get(url)
  except:
    response = ""
  featuresdata.append(getiframe(response))
  featuresdata.append(getmouseOver(response))
  featuresdata.append(getrightClick(response))
  featuresdata.append(getforwarding(response))
  featuresdata.append(label)
  
  return featuresdata

def callabale_info(url, predict_legi_features: list):
  label = 0

  predict_legi_features.append(featureExtraction(url,label))
  
  feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                          'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                          'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

  legitimate = pd.DataFrame(predict_legi_features, columns= feature_names)
  legitimate.head()

  datada = pd.read_csv(r"./urldata.csv")
  datada.head()
      
  datadone = datada.drop(['Domain'], axis = 1).copy()
  datadone.head()

  legitimate_final = legitimate.drop(['Domain'], axis = 1).copy()
  legitimate_finalend = legitimate_final.drop(['Label'], axis = 1).copy()
  legitimate_finalend.head()

  y = datadone['Label']
  X = datadone.drop('Label',axis=1)


  X_train, X_test, y_train, y_test = train_test_split(X, y,test_size = 0.2, random_state = 12)
                                                      
  xgbvar = XGBClassifier(learning_rate=0.4,max_depth=7)
  xgbvar.fit(X_train, y_train)



  y_test_xgb = xgbvar.predict(legitimate_finalend)
  y_train_xgb = xgbvar.predict(legitimate_finalend)
  value = ""
  if(y_test_xgb==0 and y_train_xgb==0):
      value = "The Given URL is legitimate"
  else:
      value = "The Given URL is Phishing"

  return (predict_legi_features, value, feature_names)