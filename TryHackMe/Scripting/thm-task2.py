######################################################################
# Vadim Polovnikov
# Date: 24-10-2020
# Platform: TryHackMe
# Challenge: 'Scripting'
# Description:
'''
The following Python script aims for:"
1. Connection to a server's web-page
2. Extracting the info regarding a dynamically changing port number
3. Connection to the next port and execution of the specified command
4. The described cycle repetition until final result calculation
'''
######################################################################

from bs4 import BeautifulSoup
import requests
import socket
import time

address = input('Enter the IP-address: ')
url = f'http://{address}:3010'
operations = ['add', 'minus', 'multiply', 'divide']
result = 0


def homepage_parser(url):
    home_page_req = requests.get(url)
    home_page_html = home_page_req.text

    # BS object with the lxml parser
    soup = BeautifulSoup(home_page_html, 'lxml')
    next_port = soup.find('a').text
    new_url = '{x[0]}:{x[1]}:{p}'.format(x=url.split(':'), p=next_port)
    return next_port, new_url


def conn_checker(port, address=address):
    sock = socket.socket(socket.AF_INET, socket.AF_INET)
    try:
        sock.connect((address, int(port)))
        return True
    except:
        return False

# operation example: add 900 3212
def ops_executor(command):
    global result
    lst = command.split(' ')
    operation = lst[0]
    value = lst[1]
    if '.' in value:
        value = float(value)
    else:
        value = int(value)
    
    print("[OPERATION]" + operation + str(value)) # Debugging

    if operation == 'add':
        result += value
    elif operation == 'minus':
        result -= value
    elif operation == 'multiply':
        result *= value
    else:
        result /= value

connect = True
while connect:
    next_port, new_url = homepage_parser(url)
    if conn_checker(next_port) == True and int(next_port) == 1337:
        print("[CONNECTED]")
        time.sleep(4.0)
        while True:
            try:
                next_port, new_url = homepage_parser(url)
                if conn_checker(next_port) == True:
                    response = requests.get(new_url).text
                    if response != 'STOP':
                        ops_executor(response)
                        print(result)
                        time.sleep(5.0)
                    else:
                        connect = False
                        break
                else:
                    time.sleep(1.0)
            except Exception as ex:
                print(ex)
    else:
        print(f"[WAITING FOR CONNECTION] current port {next_port}")

print(result)
        
