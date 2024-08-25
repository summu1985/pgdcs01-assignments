#!/var/ossec/framework/python/bin/python3
import json
import requests
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import re
from urllib.parse import urlparse
#import whois
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)
# Global vars
debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

domain_name = ""

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    debug("# File location")
    debug(alert_file_location)
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
    # Request urlhaus info
    msg = request_phishchecker_info(json_alert)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file,"a")
        f.write(msg)
        f.close()

# 2.Checks the presence of @ in URL (Have_At)
def havingAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# 1.Checks for IP address in URL (Have_IP)
def is_ip_address_in_url(url):
    # Parse the URL to extract the host
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    print("host = ", host)

    # Regular expression patterns for IPv4 and IPv6 addresses
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6_pattern = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')

    # Check if the host matches the IPv4 or IPv6 patterns
    if ipv4_pattern.match(host) or ipv6_pattern.match(host):
        return 1
    return 0

# 3.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length

# 4.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 5.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 6.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

# 7. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 8.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate

#9. Domain based features
def checkInvalidDomain(url):
  dns = 0
  try:
    domain_name = whois.query(urlparse(url).netloc)
    #domain_name = whois.query('https://www.google.com')
    print("domain_name = ", domain_name.name)
  except:
    dns = 1
  return dns

# 10.Survival time of domain: The difference between termination time and creation time (Domain_Age)
#def domainAge(domain_name):
#  creation_date = domain_name.creation_date
#  expiration_date = domain_name.expiration_date
#  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
#    try:
#      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
#      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
#    except:
#      return 1
#  if ((expiration_date is None) or (creation_date is None)):
#      return 1
#  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
#      return 1
#  else:
#    #ageofdomain = abs((expiration_date - creation_date).days)
#    #ageofdomain = abs((expiration_date - creation_date.replace(tzinfo=timezone.utc)).days)
#    ageofdomain = abs((expiration_date.replace(tzinfo=timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days)
#    if ((ageofdomain/30) < 6):
#      age = 1
#    else:
#      age = 0
#  return age
#
## 11.End time of domain: The difference between termination time and current time (Domain_End)
#def domainEnd(domain_name):
#  expiration_date = domain_name.expiration_date
#  if isinstance(expiration_date,str):
#    try:
#      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
#    except:
#      return 1
#  if (expiration_date is None):
#      return 1
#  elif (type(expiration_date) is list):
#      return 1
#  else:
#    today = datetime.now()
#    end = abs((expiration_date.replace(tzinfo=timezone.utc) - today.replace(tzinfo=timezone.utc)).days)
#    if ((end/30) < 6):
#      end = 0
#    else:
#      end = 1
#  return end

def query_api(url):

    # Define the URL
    model_url = "http://174.138.122.252:8000/predict"
    url_to_check = url
    print("URL to check phishing status: ", url_to_check)
    
    # Extract feature
    features = []
    haveIp = is_ip_address_in_url(url_to_check)
    print("Have IP : ", haveIp)
    features.append(haveIp)

    haveAtSign = havingAtSign(url_to_check)
    print("Have @ sign : ", haveAtSign)
    features.append(haveAtSign)

    haveSafeLength = getLength(url_to_check)
    print("Safe length : ", haveSafeLength)
    features.append(haveSafeLength)

    haveSafeDepth = getDepth(url_to_check)
    print("Safe depth : ", haveSafeDepth)
    features.append(haveSafeDepth)

    haveRedirection = redirection(url_to_check)
    print("Have redirection: ", haveRedirection)
    features.append(haveRedirection)

    haveHttpsInDomain = httpDomain(url_to_check)
    print("Have HTTPS in domain: ", haveHttpsInDomain)
    features.append(haveHttpsInDomain)

    haveURLShortening = tinyURL(url_to_check)
    print("Using url shortening service: ", haveURLShortening)
    features.append(haveURLShortening)

    haveDashInDomain = prefixSuffix(url_to_check)
    print("Is domain separated by dash: ", haveDashInDomain)
    features.append(haveDashInDomain)

    #haveInvalidDomain = checkInvalidDomain(url_to_check)
    dns = 0
    #try:
    #  domain_name = whois.query(urlparse(url_to_check).netloc)
    #  #domain_name = whois.query('https://www.google.com')
    #  print("domain_name = ", domain_name.name)
    #except:
    #  dns = 1
    haveInvalidDomain = dns
    print("Is domain invalid: ", haveInvalidDomain)
    features.append(haveInvalidDomain)

    #haveInvalidDomainAge = 1 if dns == 1 else domainAge(domain_name)
    haveInvalidDomainAge = 0
    print("Having Invalid Domain Age: ", haveInvalidDomainAge)
    features.append(haveInvalidDomainAge)

    #haveUnexpiringDomain = 1 if dns == 1 else domainEnd(domain_name)
    haveUnexpiringDomain = 0
    print("Having unexpiring domain: ", haveUnexpiringDomain)
    features.append(haveUnexpiringDomain)

    print("features:", features)
  
    # Create the JSON array
    input_data = {
                "features":[features]
                }
    # Convert the list to JSON format
    json_data = json.dumps(input_data)

    # Send the POST request
    response = requests.post(model_url, data=json_data, headers={'Content-Type': 'application/json'})


    # Create the JSON array
    data = {
            "features":[features]
            }

    # Convert the list to JSON format
    json_data = json.dumps(data)
    print("json_data: ", json_data)

    # Send the POST request
    response = requests.post(model_url, data=json_data, headers={'Content-Type': 'application/json'})

    # Print the response
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)

    json_response = response.json()
    if response.status_code == 200 :
        response_data = {}

        phish_prediction = json_response['predictions'][0]
        yes_probability = json_response['probabilities'][0][0]
        no_probability = json_response['probabilities'][0][1]
        if yes_probability < no_probability :
            response_data['prediction'] = "phishing_url"
            response_data['probability'] = no_probability
        else :
            response_data['prediction'] = "safe_url"
            response_data['probability'] = yes_probability
        
        #response_data['prediction'] = "Phishing URL" if json_response['predictions'][0] == 1 else "Safe URL"
        #response_data['probability'] = json_response['probabilities'][0][0]
        print("probability: ",response_data['probability'])
        print("prediction: ",response_data['prediction'])
        #return data

        #response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', params)
        debug(response_data)
        return response_data
    else:
        alert_output = {}
        alert_output["phishchecker"] = {}
        alert_output["integration"] = "custom-phishchecker"
        json_response = response.json()
        debug("# Error: The phishchecker integration encountered an error")
        alert_output["phishchecker"]["error"] = response.status_code
        alert_output["phishchecker"]["description"] = json_response["errors"][0]["detail"]
        send_event(alert_output)
        debug(alert_output)
        exit(0)

def request_phishchecker_info(alert):
    alert_output = {}
    # If there is no url address present in the alert. Exit.
    if alert["data"]["http"]["hostname"] == None:
      return(0)
    # Request info using ML based phishing checker API
    url = alert["data"]["app_proto"]+"://"+alert["data"]["http"]["hostname"]+alert["data"]["http"]["url"]
    data = query_api(url)
    # Create alert
    alert_output["phishchecker"] = {}
    alert_output["integration"] = "custom-phishchecker"
    alert_output["phishchecker"]["found"] = 0
    alert_output["phishchecker"]["source"] = {}
    alert_output["phishchecker"]["source"]["alert_id"] = alert["id"]
    alert_output["phishchecker"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["phishchecker"]["source"]["description"] = alert["rule"]["description"]
    alert_output["phishchecker"]["source"]["url"] = url
    #url = alert["data"]["http"]["redirect"]
    alert_output["phishchecker"]["model-url"] = "http://174.138.122.252:8000/predict"
    alert_output["phishchecker"]["ml-model"] = "gradient-tree-boost"
    alert_output["phishchecker"]["prediction"] = data["prediction"]
    alert_output["phishchecker"]["probability"] = data["probability"]
#    # Check if urlhaus has any info about the url
#    if in_database(data, url):
#      alert_output["urlhaus"]["found"] = 1
#    # Info about the url found in urlhaus
#    if alert_output["urlhaus"]["found"] == 1:
#        urlhaus_reference, url_status, url_date_added, url_threat, url_blacklist_spamhaus, url_blacklist_surbl, url_tags = collect(data)
#        # Populate JSON Output object with urlhaus request
#        alert_output["urlhaus"]["urlhaus_reference"] = urlhaus_reference
#        alert_output["urlhaus"]["url_status"] = url_status
#        alert_output["urlhaus"]["url_date_added"] = url_date_added
#        alert_output["urlhaus"]["url_threat"] = url_threat
#        alert_output["urlhaus"]["url_blacklist_spamhaus"] = url_blacklist_spamhaus
#        alert_output["urlhaus"]["url_blacklist_surbl"] = url_blacklist_surbl
#        alert_output["urlhaus"]["url_tags"] = url_tags
    debug(alert_output)
    return(alert_output)

def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:phishchecker:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->phishchecker:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True
        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()
        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)
        # Main function
        main(sys.argv)
    except Exception as e:
        debug(str(e))
        raise
