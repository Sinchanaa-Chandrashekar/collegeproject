#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
from xgboost import XGBClassifier
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split

# In[3]:


data0 = pd.read_csv(r"./online-valid.csv")
data0.head()
    


# In[4]:


phishurl = data0.sample(n = 5000, random_state = 12).copy()
phishurl = phishurl.reset_index(drop=True)
phishurl.head()


# In[6]:


data1 = pd.read_csv(r"./Benign_list_big_final.csv")
data1.columns = ['URLs']
data1.head()


# In[7]:


legiurl = data1.sample(n = 5000, random_state = 12).copy()
legiurl = legiurl.reset_index(drop=True)
legiurl.head()


# In[8]:





# In[9]:


def getDomain(url):  
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
	       domain = domain.replace("www.","")
  return domain


# In[10]:


def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip


# In[11]:


def haveAtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at


# In[12]:


def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length


# In[13]:


def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth


# In[14]:


def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0


# In[15]:


def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


# In[16]:


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"                       r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"                       r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"                       r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"                       r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"                       r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"                       r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"                       r"tr\.im|link\.zip\.net"


# In[17]:


def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0


# In[18]:


def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate


# In[22]:




# In[23]:




# In[24]:


def web_traffic(url):
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


# In[25]:


def domainAge(domain_name):
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


# In[26]:


def domainEnd(domain_name):
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


# In[27]:


import requests


# In[28]:


def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1


# In[29]:


def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0


# In[30]:


def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1


# In[31]:


def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1


# In[32]:


def featureExtraction(url,label):

  features = []
  #Address bar based features (10)
  features.append(getDomain(url))
  
  features.append(havingIP(url))
  

  features.append(haveAtSign(url))
  
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))
  
  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
    
  except:
    dns = 1

  features.append(dns)
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  
  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  features.append(label)
  
  return features
  


# In[33]:


legiurl.shape


# In[34]:



def callabale_info(url, predict_legi_features: list):
  label = 0

  predict_legi_features.append(featureExtraction(url,label))
  


# In[35]:


  feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                          'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                          'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

  legitimate = pd.DataFrame(predict_legi_features, columns= feature_names)
  legitimate.head()


  # In[ ]:





  # In[ ]:





  # In[ ]:



    


  # In[ ]:





  # In[ ]:





  # In[ ]:





  # In[ ]:





  # In[ ]:





  # In[39]:


  datada = pd.read_csv(r"./urldata.csv")
  datada.head()
      


  # In[40]:




  # In[ ]:





  # In[41]:


  data = datada.drop(['Domain'], axis = 1).copy()
  data.head()


  # In[42]:


  legitimate_final = legitimate.drop(['Domain'], axis = 1).copy()
  legitimate_finalend = legitimate_final.drop(['Label'], axis = 1).copy()
  legitimate_finalend.head()


  # In[43]:


  y = data['Label']
  X = data.drop('Label',axis=1)
  X.shape, y.shape


  # In[45]:



  X_train, X_test, y_train, y_test = train_test_split(X, y, 
                                                      test_size = 0.2, random_state = 12)
  X_train.shape, X_test.shape


  # In[46]:



  #XGBoost Classification model

  # instantiate the model
  xgb = XGBClassifier(learning_rate=0.4,max_depth=7)
  #fit the model
  xgb.fit(X_train, y_train)


  # In[47]:


  y_test_xgb = xgb.predict(legitimate_finalend)
  y_train_xgb = xgb.predict(legitimate_finalend)
  value = ""
  if(y_test_xgb==0 and y_train_xgb==0):
      value = "The Given URL is legitimate"
  else:
      value = "The Given URL is Phishing"

  return (predict_legi_features, value)


# In[44]:





# In[ ]:




