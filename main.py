
import json
import ipaddress
from collections import Counter
import pandas as pd
import os
import sys


#Constants
path = sys.path[0]+ '\\'
log_file = "log.txt"

#functions


def save_json_file(path, file, data):
    with open(path+file, 'w') as jsonFile:
        jsonFile.write(json.dumps(data, indent = 3))
    

def from_txt_to_json(path, file):
    filepath = path+file
    log_json = []
    ip_json = {}
    linhas_arquivo_original = 0
    with open(filepath) as fp:
        next(fp) #remove header from log file
        for index, line in enumerate(fp):
            l = line.split()
            ip_json['srcaddr'] = l[0]
            ip_json['dstaddr'] = l[1]
            ip_json['port'] = l[2]
            ip_json['action'] = l[3]
            ip_json['status'] = ''
            log_json.append(ip_json)
            ip_json = {}
            linhas_arquivo_original = linhas_arquivo_original + 1
        save_json_file(path,'1_log.json',log_json)
    return linhas_arquivo_original


def filter_json(path, file):
    f = open(path+file)
    input_dict = json.load(f)
    output_dict = [x for x in input_dict if x['port'] not in['443','80']] #removing ports 443 and 80 only
    save_json_file(path,'2_log_filtered_without_443_and_80.json', output_dict)
    linhas_arquivo_sem_portas_443_80 = len(output_dict)
    return linhas_arquivo_sem_portas_443_80


def remove_internal_net_and_vpn(path, file, net1, net2, vpn, public1, public2,public3): #remove public IPs
    suspicious_ips = []
    suspicious_ports = []
    suspicious_action = []
    suspicious_ssh_accepted =[]
    f = open(path+file)
    input_dict = json.load(f)
    external_src = []
    for item in input_dict:
        src = ipaddress.IPv4Address(item['srcaddr'])
        if (src not in net1 and src not in net2 and src not in vpn and src != public1 and src != public2 and src !=  public3) :
            item['status'] = "Possible attack on port " + item['port'] + " with action " + item['action']
            external_src.append(item)
            suspicious_ips.append(item['srcaddr'])
            suspicious_ports.append(item['port']+ ' ' + item['action'])
            suspicious_action.append(item['action'])
            if (item['port']=="22" and item['action']=="ACCEPT"):
                suspicious_ssh_accepted.append(item)

    linhas_arquivo_sem_portas_rede_int_e_vpn_e_publicos = len(external_src)
    save_json_file(path, '3_external_src.json', external_src)
    number_of_suspicious_ssh = len(suspicious_ssh_accepted)
    return linhas_arquivo_sem_portas_rede_int_e_vpn_e_publicos, suspicious_ips, suspicious_ports, suspicious_action, number_of_suspicious_ssh


def suspicious_ip_statistics(suspicious_ips,suspicious_ports,suspicious_action):
    unique_ips = list(dict.fromkeys(suspicious_ips))
    unique_ports = list(dict.fromkeys(suspicious_ports))
    contador = Counter(suspicious_ips)
    contador2 = Counter(suspicious_ports)
    contador3 = Counter(suspicious_action)
    contador = json.dumps(contador, indent=0, sort_keys=True)
    contador2 = json.dumps(contador2, indent=0, sort_keys=True)
    contador3 = json.dumps(contador3, indent=0, sort_keys=True)
    save_json_file(path, '5_1_stats.json', contador)
    save_json_file(path, '5_2_stats.json', contador2)
    return unique_ips, contador, unique_ports, contador2, contador3


def from_json_to_txt(path, file, output):
    df = pd.read_json(path+file)
    df.to_csv (path+output, index = False)
    
    
def save_stats_txt(path, file, contador, header):
    contador = contador.strip('{')
    contador = contador.strip('}')
    aux = contador.replace(",","")
    contador = aux.replace('"',"")
    aux = contador.replace(":","")
    contador = aux
    file_object = open(path+file, 'a')
    file_object.write(header)
    file_object.write(contador)
    file_object.close


def main():
    REDE_INT1 = ipaddress.ip_network('10.0.0.0/16')
    REDE_INT2 = ipaddress.ip_network('10.50.0.0/16')
    REDE_VPN  = ipaddress.ip_network('192.168.0.0/16')
    PUBLIC_IP1 = ipaddress.IPv4Address('241.223.148.36')
    PUBLIC_IP2 = ipaddress.IPv4Address('26.66.77.16')
    PUBLIC_IP3 = ipaddress.IPv4Address('60.142.8.92')
    
    if os.path.exists("final_report.txt"):
        os.remove("final_report.txt") #keep only latest execution
    if os.path.exists("4_final_result.txt"):
        os.remove("4_final_result.txt") #keep only latest execution
    if os.path.exists(log_file):
        try:
            linhas_arquivo_original = from_txt_to_json(path, log_file) #convert the txt log into json
            save_stats_txt(path, 'final_report.txt',"","-------------------Server Activity Report-------------------------" + '\n\n')
            save_stats_txt(path, 'final_report.txt',"","1)Total number of connection requests: " + str(linhas_arquivo_original) + '\n\n')
            linhas_arquivo_sem_portas_443_80 = filter_json(path,'1_log.json') #remove all entries that have ports 80 or 443
            save_stats_txt(path, 'final_report.txt',"","2)Server requests with ports 443 and 80 filtered out: " +  str(linhas_arquivo_sem_portas_443_80) + '\n\n')
            linhas_arquivo_sem_portas_rede_int_e_vpn_e_publicos, suspicious_ips, suspicious_ports, suspicious_action,number_of_suspicious_ssh  = remove_internal_net_and_vpn(path, '2_log_filtered_without_443_and_80.json', REDE_INT1, REDE_INT2, REDE_VPN, PUBLIC_IP1, PUBLIC_IP2, PUBLIC_IP3)
            save_stats_txt(path, 'final_report.txt',"","3)Server requests excluding internal network, VPN and public IPs: " + str(linhas_arquivo_sem_portas_rede_int_e_vpn_e_publicos) + '\n\n')
            from_json_to_txt(path, '3_external_src.json','4_final_result.txt')
            unique_ips, contador, unique_ports, contador2, contador3 = suspicious_ip_statistics(suspicious_ips,suspicious_ports, suspicious_action)
            save_stats_txt(path, 'final_report.txt',"","4)Unique IPs identified: " + str(len(unique_ips)) +'\n\n')
            save_stats_txt(path, 'final_report.txt',contador3,"5)Number_of_attemps by action: (after applying filters 2 and 3)")
            save_stats_txt(path, 'final_report.txt',"",'\n')
            save_stats_txt(path, 'final_report.txt',"","6)Number of UNAUTHORIZED SSH connections: {}".format(number_of_suspicious_ssh)+'\n\n')
            save_stats_txt(path, 'final_report.txt',contador,"7)Source_IP Number_of_attemps:")
            save_stats_txt(path, 'final_report.txt',"",'\n')
            save_stats_txt(path, 'final_report.txt',contador2,"8)Port Action Number_of_requests:")
            print("Success. Please check final_report.txt...")
        except:
            print("Error. Please contact Fernando Moreira.")    
    else:
            print("Make sure that {} is in the same folder as the main.py script.".format(log_file))        
    
if __name__ == "__main__":
    main()