import requests 
import json
from Crypto.Hash import MD5, SHA256
import secrets
import base64
import hmac
import hashlib
import yaml
import argparse

userName = ""
deviceId = ""
password = ""
servicetoken = None
def encodePassword(password):
    hash = MD5.new()
    hash.update(password.encode("utf8"))
    return hash.hexdigest().upper()

def parseJson(jsonContent):
    if("&&&START&&&" in jsonContent):
        replaced = jsonContent.replace("&&&START&&&", "")
        return json.loads(replaced)
    else:
        return json.loads(jsonContent)

def login():
    headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-9D28921C354D7 APP/xiaomi.smarthome APPV/62830',
            'Cookie': f"sdkVersion=accountsdk-18.8.15; userId={userName}; deviceId={deviceId}",
            'Accept-Encoding': "identity, deflate, compress, gzip"
            }
    response = requests.get(
        'https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true',
        headers = headers,
        #verify=False
    )
    if(response.status_code == 200):
        content = parseJson(response.text)
        payload = {
                    'sid': "xiaomiio",
                    'hash': encodePassword(password),
                    'callback': "https://sts.api.io.mi.com/sts",
                    'qs': "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                    'user': userName,
                    '_sign': content['_sign'],
                    '_json': "true"
        }
        headers['Cookie'] = f"sdkVersion=accountsdk-18.8.15; deviceId={deviceId}"
        loginResponse = requests.post(
            'https://account.xiaomi.com/pass/serviceLoginAuth2',
            headers=headers,
            data=payload,
            #verify=False
        )
        if (loginResponse.status_code == 200):
            jsonData = parseJson(loginResponse.text)
            if(jsonData["code"] != 0):
                print("Login failed")
                exit
            global ssecurity
            ssecurity = jsonData["ssecurity"]
            global userId
            userId = jsonData["userId"]
            cUserId = jsonData["cUserId"]
            global session
            session = requests.Session()
            sessionResp = session.get(jsonData["location"],
            headers=headers,
            #verify=False
            )
            if (sessionResp.status_code == 200):
                if sessionResp.cookies["serviceToken"]:
                    global servicetoken
                    servicetoken = sessionResp.cookies["serviceToken"]
                    found = True

def HashHmacSHA256(data, secret):
    signature = hmac.new(bytearray(secret, 'utf-8'), msg = data.encode(), digestmod = hashlib.sha256)
    return base64.b64encode(signature.digest()).decode()

def generateSignature(path, params):
    nonce = secrets.token_urlsafe(12)

    hash = SHA256.new()
    hash.update(base64.b64decode(nonce) + base64.b64decode(ssecurity))
    signature = base64.b64encode(hash.digest())

    paramsArray=[]
    if(path):
        paramsArray.append(path)
    paramsArray.append(signature.decode())
    paramsArray.append(nonce)
    if(len(params) > 0):
        for param in params:
            paramsArray.append(f"{param}={params[param]}")
    else:
        paramsArray.append("data=")

    postData = "&".join(paramsArray)

    body = {
    "signature": HashHmacSHA256(postData, signature.decode()),
    "_nonce": nonce
    }
    for param in params:
        body[param] = params[param]
    return body

    
def getMapURL(mapName):
    login()
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
      'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-9D28921C354D7 APP/xiaomi.smarthome APPV/62830'
    }
    Mycookie = {
        "userId":str(userId),
        "yetAnotherServiceToken": servicetoken,
        "serviceToken": servicetoken,
        "locale": "de_DE",
        "timezone": "GMT%2B01%3A00",
        "is_daylight": "1",
        "dst_offset": "3600000",
        "channel": "MI_APP_STORE"
    }
    params = { 
      "data": '{"obj_name":"'+mapName+'"}'
    }
    body = generateSignature("/home/getmapfileurl", params)
    response = session.post(
            'https://de.api.io.mi.com/app/home/getmapfileurl',
            headers=headers,
            data=body,
            cookies = Mycookie,
            #proxies={"http": "http://127.0.0.1:8888","https":"http:127.0.0.1:8888"},verify=False
    )
    if(response.status_code == 200):
        print("woehoe")
#     request(options, function (error, response, body) {
#       if (!error && response.statusCode === 200) {
#         var json = JSON.parse(response.body);
        
#         if(json.message == "ok") {
#           resolve(json);
#         }
#         else {
#           console.log("Error when receiving mapurl")
#           servicetoken = undefined;
#           reject(json.message);
#         }
#         return;
#       }

#       var json = JSON.parse(response.body);
#       servicetoken = undefined;
#       console.log(response);

#       reject(json.message);
#     });
#   });
# }

def _parser():
    """Generate argument parser"""
    parser = argparse.ArgumentParser()
    parser.add_argument("settings", help="path to the settings file")
    return parser
if __name__ == '__main__':
    args = _parser().parse_args()
    with open(args.settings, 'r') as stream:
        try:
            settings = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    userName = settings["username"]
    deviceId = settings["deviceId"]
    password = settings["password"]
    getMapURL("robomap%2F261700991%2F0")    
