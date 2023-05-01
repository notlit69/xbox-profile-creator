import requests
import json
import threading
import sys
import re
import os

from colorama import Fore,init

thread_lock = threading.Lock()
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
request_exceptions = (requests.exceptions.ProxyError,requests.exceptions.Timeout,requests.exceptions.SSLError)
cfg = json.load(open('config.json'))
success = 0
fail = 0 
def update_console():
     while True:
          os.system(f'title XBOX profile creator success : {str(success)} failed : {str(fail)}')
threading.Thread(target=update_console).start()

def sprint(content, status: str="c") -> None:
    thread_lock.acquire()
    if status=="y":
        colour = Fore.LIGHTYELLOW_EX
    elif status=='r':
        colour = Fore.LIGHTRED_EX
    elif status=="g":
        colour = Fore.LIGHTGREEN_EX
    sys.stdout.write(
            f"{colour}{content}"
            + "\n"
            + Fore.RESET
        )    
    thread_lock.release()

def remove_content(filename: str, delete_line: str) -> None:
        with open(filename, "r+") as io:
            content = io.readlines()
            io.seek(0)
            for line in content:
                if not (delete_line in line):
                    io.write(line)
            io.truncate()
def make(ms_creds : str):
    global success
    global fail
    s = requests.session()
    if not cfg['proxies']=='':
         s.proxies = {'https':cfg['proxies']}
    email = ms_creds.split('|')[0]
    password = ms_creds.split('|')[1]
    headers = {

    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'identity',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}

    while True:
        try:
            response = s.get('https://login.live.com/ppsecure/post.srf', headers=headers,timeout=20).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(str(e),"r")
            return
    try:
        ppft = response.split(''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        log_url = response.split(",urlPost:'")[1].split("'")[0]
    except:
        sprint("[-] Unknown Error (Proxies probably banned)")
        return
    log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
            }  
    while True:
        try:
            response = s.post(log_url,timeout=20,data=log_data,headers=headers).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return


    try:
        ppft2 = re.findall("sFT:'(.+?(?=\'))", response)[0],
        url_log2 = re.findall("urlPost:'(.+?(?=\'))", response)[0]
    except:
        sprint("[-] Invalid microsoft acc!","y")
        remove_content("accs.txt",ms_creds)
        fail += 1
        return


    log_data2 = {
    "LoginOptions": "3",
    "type": "28",
    "ctx": "",
    "hpgrequestid": "",
    "PPFT": ppft2,
    "i19": "19130"
}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://login.live.com',
        'Referer': log_url,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
    }
    while True:
        try:
            midAuth2 = s.post(url_log2,timeout=20,data=log_data2,headers=headers).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    while "fmHF" in midAuth2:
        midAuth2 = {
"fmHF": midAuth2.split('name="fmHF" id="fmHF" action="')[1].split('"')[0],
"pprid": midAuth2.split('type="hidden" name="pprid" id="pprid" value="')[1].split('"')[0],
"nap": midAuth2.split('type="hidden" name="NAP" id="NAP" value="')[1].split('"')[0],
"anon": midAuth2.split('type="hidden" name="ANON" id="ANON" value="')[1].split('"')[0],
"t": midAuth2.split('<input type="hidden" name="t" id="t" value="')[1].split('"')[0]} 
        data = {
    'pprid': midAuth2["fmHF"],
    'NAP': midAuth2['nap'],
    'ANON': midAuth2['anon'],
    't': midAuth2['t'],
}
        loda_lund = midAuth2['fmHF']
        while True:
            try:
                midAuth2 = s.post(loda_lund,data=data,headers={
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}).text     
                break
            except request_exceptions:
                continue
            except Exception as e:
                sprint(e,"r")
                return
    heads = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}
    while True:
        try:
            response = s.get("https://account.xbox.com/",timeout=20,headers=heads).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    try:
        xbox_json = {
"fmHF": response.split('id="fmHF" action="')[1].split('"')[0],
"pprid": response.split('id="pprid" value="')[1].split('"')[0],
"nap": response.split('id="NAP" value="')[1].split('"')[0],
"anon": response.split('id="ANON" value="')[1].split('"')[0],
"t": response.split('id="t" value="')[1].split('"')[0]} 
    except:
        sprint("IP banned on https://account.xbox.com/","y")
        return
    heads = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}
    while True:
        try:
            verify_token = s.post(xbox_json['fmHF'],timeout=20, headers={
        'Content-Type': 'application/x-www-form-urlencoded',
    },data={
        "pprid": xbox_json['pprid'],
        "NAP": xbox_json['nap'],
        "ANON": xbox_json['anon'],
        "t": xbox_json['t']
    }).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    

    reqVerifytoken = verify_token.split('name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
    heads={
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': 'https://account.xbox.com',
    'Referer': xbox_json['fmHF'],
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'X-Requested-With': 'XMLHttpRequest',
    '__RequestVerificationToken': reqVerifytoken,
}
    while True:
        try:
            make_acc = s.post("https://account.xbox.com/en-us/xbox/account/api/v1/accountscreation/CreateXboxLiveAccount",timeout=20, headers=heads,data={
        "partnerOptInChoice": "false",
        "msftOptInChoice": "false",
        "isChild": "true",
        "returnUrl": "https://www.xbox.com/en-US/?lc=1033"
    })
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    if not make_acc.ok:
        sprint("[-] Failed to create XBOX profile!",'y')
        fail += 1
        remove_content('accs.txt',ms_creds)
        return
    success += 1
    sprint(f'[+] Successfully created XBOX profile -> {email}','g')
    remove_content('accs.txt',ms_creds)
    open('success.txt','a').write(ms_creds+'\n')
init()
thread_count = int(input(Fore.LIGHTBLUE_EX+'[!] Enter amount of threads : '))
emails_list = open("accs.txt").read().splitlines()
while len(emails_list) > 0:
	try:
		local_threads = []
		for x in range(thread_count):
			email = emails_list[0]
			start_thread = threading.Thread(target=make, args=(email,))
			local_threads.append(start_thread)
			start_thread.start()
			try:
				emails_list.pop(0)
			except:
				pass
		for thread in local_threads:
			thread.join()
	except IndexError:
		break
	except:
		pass
    
sprint('[+] Finished!','y')
