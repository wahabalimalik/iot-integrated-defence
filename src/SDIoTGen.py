'''
This module provides an example IoT network and decoding of GA solutions to create the associated topology.  

@author: Mengmeng Ge
'''

from Node import *
from Network import *
from Vulnerability import *
from harm import *
from random import Random
from time import time
import ProblemFormulation as pf
from Metrics import *
from itertools import accumulate
import random
from collections import OrderedDict

#=================================================================================================
# Create real network 
#=================================================================================================

def add_conn(net):
    nodes_vlans = []
    for vlan in net.subnets:
        temp = []
        for node in net.nodes:
            if node.subnet == vlan:
                temp.append(node)
        nodes_vlans.append(temp)
    #print(nodes_vlans)
    
    #Add connections from other VLANs to VLAN4
    for node in nodes_vlans[3]:
        temp = nodes_vlans[0] + nodes_vlans[1] + nodes_vlans[2]
        for conNode in temp: 
            connectOneWay(conNode, node)
    
    
    #Add connections from VLAN2 to VLAN3
    for node in nodes_vlans[1]:
        for conNode in nodes_vlans[2]:
            connectOneWay(node, conNode)
          
    return None


def add_vul(net):
    """
    Add vulnerabilities for real devices.
    """
    for node in net.nodes:
        if 'mri' in node.name or 'ct' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8308
            #Exploitability score: 6.8
            vul = vulNode("CVE-2018-8308")
            vul.createVul(node, 0.006, 1, 3.4, 6.6, 5.9, 0.7)
        elif 'thermostat' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2013-4860
            vul = vulNode("CVE-2013-4860")
            vul.createVul(node, 0.006, 1)
        elif 'meter' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2017-9944
            #Exploitability score: 10.0
            vul = vulNode("CVE-2017-9944")
            vul.createVul(node, 0.042, 1)     
        elif 'camera' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-10660
            vul = vulNode("CVE-2018-10660")
            vul.createVul(node, 0.042, 1)
        elif 'tv' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-4094
            #Exploitability score: 8.6
            vul = vulNode("CVE-2018-4094")
            vul.createVul(node, 0.012, 1)
        elif 'laptop' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8345
            #Exploitability score: 4.9
            vul = vulNode("CVE-2018-8345")
            vul.createVul(node, 0.004, 1, )     
        elif 'server' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8273
            vul = vulNode("CVE-2018-8273")
            vul.createVul(node, 0.006, 1)                  

    return None

def createRealSDIoT(node_vlan_list):
    """
    An example SD-IoT network.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            iot = realNode(j)
            iot.id = id
            iot.subnet = vlan
            #print(iot.subnet)
            if iot.subnet == 'vlan4':
                iot.critical = True
            net.nodes.append(iot)
            id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    #printNetWithVul(net)
    
    return net

def createRealSDIoTScale(node_vlan_list, scale):
    """
    An example SD-IoT network with addition of a subset of IoT nodes.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            # Do not increase mri and ct
            if j in ['thermostat', 'meter', 'camera', 'tv', 'laptop']:
                for k in range(0, scale):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            else:
                iot = realNode(j)
                iot.id = id
                iot.subnet = vlan
                #print(iot.subnet)
                if iot.subnet == 'vlan4':
                    iot.critical = True
                net.nodes.append(iot)
                id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    printNetWithVul(net)
    
    return net

def createRealSDIoTScale2(node_vlan_list, scale):
    """
    An example SD-IoT network with addition of real IoT nodes.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            # Do not increase mri and ct
            if j in ['thermostat', 'meter', 'camera', 'tv', 'laptop']:
                for k in range(0, scale):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            elif j in ['mri', 'ct']:
                for k in range(0, 2):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            else:
                iot = realNode(j)
                iot.id = id
                iot.subnet = vlan
                #print(iot.subnet)
                if iot.subnet == 'vlan4':
                    iot.critical = True
                net.nodes.append(iot)
                id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    printNetWithVul(net)
    
    return net


def add_solution_set(solution_set):
    return solution_set['mri'], solution_set['ct'], solution_set['thermostat'], solution_set['meter'], \
        solution_set['camera'], solution_set['tv'], solution_set['laptop'], solution_set['server']

def getIoTNum(net):
    num = 0
    for node in net.nodes:
        if 'server' not in node.name:
            num += 1
    return num

#=================================================================================================
# Add attacker and create HARM
#=================================================================================================

def add_attacker(net):
    #Add attacker
    A = device('attacker')    
    A.setStart()
    for temp in net.nodes:
        
        #Set the real and decoy servers as targets
        if "server" in temp.name:
            #print("server", temp.name)
            temp.setEnd()
        else:
            #print("others", temp.name)
            A.con.append(temp)
    
    net.nodes.append(A)
    
    constructSE(net)

    return net

def constructHARM(net):
    #Create security model
    h = harm()
    
    #printNet(net)
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    h.system_risk = system_risk(net)
    #h.model.printAG()
    #h.model.printPath()
    #print("number of attack paths:", len(h.model.allpath))
    
    return h

#=================================================================================================
# Calculate System Risk
#=================================================================================================

def system_risk(net):
    total_risk = 0

    for node in net.nodes:
        if "decoy" in node.name:
            vul = node.vul.nodes
            for v in vul:
                probability = v.exploitability / 10
                impact = v.impact
                risk_decoy_node = probability * impact
                total_risk += risk_decoy_node

    return total_risk

#=================================================================================================
# Add initial deployment of decoys into network
#=================================================================================================


def get_vul_for_ct_n_mri():
    vul_list = [
        {
            "vendor": "ABC",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2018-8308",
                    "cve_bs": 6.6,
                    "impact": 4.9,
                    "exploitability": 0.7,
                    "cost": 3.4
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2017-8495",
                    "cve_bs": 7.8,
                    "impact": 5.9,
                    "exploitability": 1.8,
                    "cost": 2.2
                }
            ]
        },
        {
            "vendor": "XYZ",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2016-7034",
                    "cve_bs": 6.8,
                    "impact": 6.4,
                    "exploitability": 0.86,
                    "cost": 3.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2017-4278",
                    "cve_bs": 5.0,
                    "impact": 2.9,
                    "exploitability": 1,
                    "cost": 5.0
                }
            ]
        },
        {
            "vendor": "EXP",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2019-14905",
                    "cve_bs": 5.6,
                    "impact": 4.7,
                    "exploitability": 0.8,
                    "cost": 4.4
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2019-14910",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        }
    ]
    return random.choice(vul_list)


def get_vul_for_thermostat_meter_n_camera():
    vul_list = [
        {
            "vendor": "ABC",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2018-6294",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2018-6295",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v2",
                    "cve_id": "CVE-2018-6297",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        },
        {
            "vendor": "XYZ",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2018-6294",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2018-6295",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v2",
                    "cve_id": "CVE-2018-6297",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        },
        {
            "vendor": "EXP",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2018-6294",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2018-6295",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                },
                {
                    "version": "v2",
                    "cve_id": "CVE-2018-6297",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        }
    ]
    return random.choice(vul_list)


def get_random_os_vul():
    os_vul_list = [
        {
            "os": "W10",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2017-8530",
                    "cve_bs": 5.8,
                    "impact": 4.9,
                    "exploitability": 0.86,
                    "cost": 4.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2017-8495",
                    "cve_bs": 6.0,
                    "impact": 6.4,
                    "exploitability": 0.68,
                    "cost": 4.0
                }
            ]
        },
        {
            "os": "Linux",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2016-7034",
                    "cve_bs": 6.8,
                    "impact": 6.4,
                    "exploitability": 0.86,
                    "cost": 3.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2017-4278",
                    "cve_bs": 5.0,
                    "impact": 2.9,
                    "exploitability": 1,
                    "cost": 5.0
                }
            ]
        },
        {
            "os": "RedHat",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2019-14905",
                    "cve_bs": 5.6,
                    "impact": 4.7,
                    "exploitability": 0.8,
                    "cost": 4.4
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2019-14910",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        }
    ]
    return random.choice(os_vul_list)


def get_random_vendor_vul():
    vendor_vul_list = [
        {
            "vendor": "TCL Technology",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2020-27403",
                    "cve_bs": 6.5,
                    "impact": 3.6,
                    "exploitability": 2.8,
                    "cost": 3.5
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2020-28055",
                    "cve_bs": 7.8,
                    "impact": 5.9,
                    "exploitability": 1.8,
                    "cost": 2.2
                }
            ]
        },
        {
            "vendor": "Apple",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2018-4094",
                    "cve_bs": 7.8,
                    "impact": 5.9,
                    "exploitability": 1.8,
                    "cost": 2.2
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2018-4095",
                    "cve_bs": 7.8,
                    "impact": 5.9,
                    "exploitability": 1.8,
                    "cost": 2.2
                }
            ]
        },
        {
            "vendor": "Samsung",
            "detail": [
                {
                    "version": "v0",
                    "cve_id": "CVE-2022-44636",
                    "cve_bs": 4.6,
                    "impact": 2.5,
                    "exploitability": 2.1,
                    "cost": 5.4
                },
                {
                    "version": "v1",
                    "cve_id": "CVE-2015-5729",
                    "cve_bs": 9.8,
                    "impact": 5.9,
                    "exploitability": 3.9,
                    "cost": 0.2
                }
            ]
        }
    ]
    return random.choice(vendor_vul_list)


def update_decoy_vul(net, diversity_percentage,node_list=[]):
    """
    Add vulnerabilities for decoy devices.
    """
    number_of_nodes = round((diversity_percentage /100)*len(net.nodes))
    node_qulified = random.choices(net.nodes, k=number_of_nodes)
    if node_list:
        node_qulified = node_list
    for node in net.nodes:
        if node in node_qulified:
            update_node(node)


    return None


def update_node(node):
    if 'ct' in node.name or "mri" in node.name:
        node.vul = None
        random_vendor_vul = get_vul_for_ct_n_mri()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'thermostat' in node.name:
        node.vul = None
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'meter' in node.name:
        node.vul = None
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'camera' in node.name:
        node.vul = None
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'tv' in node.name:
        node.vul = None
        random_vendor_vul = get_random_vendor_vul()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, random_vendor_vul["detail"][0]["cost"], random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"], random_vendor_vul["detail"][0]["exploitability"])
        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, random_vendor_vul["detail"][1]["cost"], random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"], random_vendor_vul["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'laptop' in node.name:
        node.vul = None
        get_os_list = get_random_os_vul()
        vul1 = vulNode(get_os_list["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, get_os_list["detail"][0]["cost"], get_os_list["detail"][0]["cve_bs"],
                       get_os_list["detail"][0]["impact"], get_os_list["detail"][0]["exploitability"])
        vul2 = vulNode(get_os_list["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, get_os_list["detail"][1]["cost"], get_os_list["detail"][1]["cve_bs"],
                       get_os_list["detail"][1]["impact"], get_os_list["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'server' in node.name:
        node.vul = None
        get_os_list = get_random_os_vul()
        vul1 = vulNode(get_os_list["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, get_os_list["detail"][0]["cost"], get_os_list["detail"][0]["cve_bs"],
                       get_os_list["detail"][0]["impact"], get_os_list["detail"][0]["exploitability"])
        vul2 = vulNode(get_os_list["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, get_os_list["detail"][1]["cost"], get_os_list["detail"][1]["cve_bs"],
                       get_os_list["detail"][1]["impact"], get_os_list["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)


def add_decoy_vul(node):
    """
    Add vulnerabilities for decoy devices.
    """

    if 'ct' in node.name or "mri" in node.name:
        random_vendor_vul = get_vul_for_ct_n_mri()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'thermostat' in node.name:
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'meter' in node.name:
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'camera' in node.name:
        random_vendor_vul = get_vul_for_thermostat_meter_n_camera()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node,
                       0.042,
                       1,
                       random_vendor_vul["detail"][0]["cost"],
                       random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"],
                       random_vendor_vul["detail"][0]["exploitability"])

        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul2.createVul(node,
                       0.012,
                       1,
                       random_vendor_vul["detail"][1]["cost"],
                       random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"],
                       random_vendor_vul["detail"][1]["exploitability"])

        vul3 = vulNode(random_vendor_vul["detail"][1]["cve_id"])

        vul3.createVul(node,
                       0.006,
                       1,
                       random_vendor_vul["detail"][2]["cost"],
                       random_vendor_vul["detail"][2]["cve_bs"],
                       random_vendor_vul["detail"][2]["impact"],
                       random_vendor_vul["detail"][2]["exploitability"])

        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)

        # node.vul = None
        # # https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        # # Score: 10.0
        # vul1 = vulNode("CVE-2018-6294")
        # vul1.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul2 = vulNode("CVE-2018-6295")
        # vul2.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        # vul3 = vulNode("CVE-2018-6297")
        # vul3.createVul(node, 0.042, 1, 0.2, 9.8, 5.9, 3.9)
        #
        # vul3.thresholdPri(node, 1)
        # vul3.terminalPri(node, 1)
    elif 'tv' in node.name:
        random_vendor_vul = get_random_vendor_vul()
        vul1 = vulNode(random_vendor_vul["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, random_vendor_vul["detail"][0]["cost"], random_vendor_vul["detail"][0]["cve_bs"],
                       random_vendor_vul["detail"][0]["impact"], random_vendor_vul["detail"][0]["exploitability"])
        vul2 = vulNode(random_vendor_vul["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, random_vendor_vul["detail"][1]["cost"], random_vendor_vul["detail"][1]["cve_bs"],
                       random_vendor_vul["detail"][1]["impact"], random_vendor_vul["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'laptop' in node.name:
        get_os_list = get_random_os_vul()
        vul1 = vulNode(get_os_list["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, get_os_list["detail"][0]["cost"], get_os_list["detail"][0]["cve_bs"],
                       get_os_list["detail"][0]["impact"], get_os_list["detail"][0]["exploitability"])
        vul2 = vulNode(get_os_list["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, get_os_list["detail"][1]["cost"], get_os_list["detail"][1]["cve_bs"],
                       get_os_list["detail"][1]["impact"], get_os_list["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'server' in node.name:
        get_os_list = get_random_os_vul()
        vul1 = vulNode(get_os_list["detail"][0]["cve_id"])
        vul1.createVul(node, 0.042, 1, get_os_list["detail"][0]["cost"], get_os_list["detail"][0]["cve_bs"],
                       get_os_list["detail"][0]["impact"], get_os_list["detail"][0]["exploitability"])
        vul2 = vulNode(get_os_list["detail"][1]["cve_id"])
        vul2.createVul(node, 0.012, 1, get_os_list["detail"][1]["cost"], get_os_list["detail"][1]["cve_bs"],
                       get_os_list["detail"][1]["impact"], get_os_list["detail"][1]["exploitability"])
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
        
    return None

def check_decoy_type(dimension, decoy_num, decoy_list):
    temp = list(accumulate(decoy_num))
    #print(temp, dimension)
    for i in range(0, len(temp)):
        if i == 0:
            if dimension <= temp[i]:
                return decoy_list[i], i+1
        else:
            if dimension > temp[i-1] and dimension <= temp[i]:
                return decoy_list[i], i+1

def add_decoy_type(node, info):
    if "server" in node.name:
        node.type = info["server_decoy_type"]
    else:
        node.type = "emulated"
    return None

def add_decoy_pro(node, info):
    node.pro = info[node.type]

def add_decoy_conn(net):
    temp = []
    for node in net.nodes:
        if "decoy_server" in node.name:
            temp.append(node)
            
    for node in net.nodes:
        if "decoy" in node.name and "server" not in node.name:
            for conNode in temp:
                connectOneWay(node, conNode)

    # decoyNode = net.nodes[8:-1]
    # # decoyNode = net.nodes[:]
    # black_list = []
    # for node in net.nodes:
    #     if "decoy" in node.name and "server" not in node.name:
    #         for conNode in decoyNode:
    #             if node.name != conNode.name and conNode.name not in black_list:
    #                 connectOneWay(node, conNode)
    #         black_list.append(node.name)
            
    return None


def closest_connections(net):
    all_closeness = {}
    for node in net.nodes:
        steps = OrderedDict()
        steps = check_path(node, steps)
        if steps:
            visited = []
            distance=[]
            keys = [x for x in  steps]
            iter = 1
            for key in keys:
                any = False
                for x in steps[key]:
                    if x not in visited:
                        any = True
                        distance.append((node.name, x, iter))
                        visited.append(x)
                if any:
                    iter +=1
            distance = sum([dis[2] for dis in distance])
            closeness = (len(net.nodes) - 1) * 1 / distance
            all_closeness[node] = closeness
    all_closeness
    top_indice = sorted(all_closeness.items(), key=lambda x:x[1])[-5:]
    return [i[0] for i in top_indice]




def check_path(node, steps):
    if node.con:
        steps[node.name] = OrderedDict()
        for con_node in node.con:
            steps[node.name][con_node.name] = 1
        for con_node in node.con:
            if con_node.con:
                steps = check_path(con_node, steps)

    # steps = OrderedDict({
    #     'thermostat': {
    #         'tv': 1,
    #         'laptop': 1
    #     },
    #     'tv': {
    #         'serverd': 1,
    #         'laptop': 1,
    #     },
    #     'laptop': {
    #         'serverd': 1
    #     },
    #     'serverd': {
    #         'server': 1
    #     }
    # })

    return steps


def add_decoy_deployment(net, info):
    
    decoy_net = copyNet(net)
    decoy_num = info["decoy_num"]
    decoy_list = info["decoy_list"]
    temp = []
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):
        name, vlan = check_decoy_type(i+1, decoy_num, decoy_list)
        #print(name, vlan)
        dnode = decoyNode(name+str(i+1))
        dnode.subnet = vlan
        add_decoy_type(dnode, info)
        add_decoy_vul(dnode)
        add_decoy_pro(dnode, info["attackerIntelligence"])
        decoy_net.nodes.append(dnode)
        #A name list of decoys deployed
        #Used in changing connections as binary encodings need to correspond to the decoys
        temp.append(dnode.name) 
    
    #Add connections from decoys to decoys
    add_decoy_conn(decoy_net)
    
    #print("Initial deployment:")
    #printNetWithVul(decoy_net)
    
    return decoy_net, temp

#=================================================================================================
# Add solution into network (change connections)
# If 0 -> 1: add connection
# If 1 -> 0: remove connection
# Others: no change
#=================================================================================================

def add_solution(net, candidate_solution, info, decoy_list):
    """
    Interpret solution to add connections.
    """
    newNet = copyNet(net)
    temp = decoy_list
    #Locate the decoy nodes from the newly created network
    for node1 in newNet.nodes:
        if node1.name in decoy_list:
            temp[decoy_list.index(node1.name)] = node1

    #Add or remove connections from real IoT nodes to decoys
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):    
        num = i * info["riot_num"]
        dnode = temp[i]
        #print(dnode.name)
        for j in range(1, info["riot_num"]+1):
            #print(candidate_solution[num+j-1])
            if candidate_solution[num+j-1] == 1 and info["previous_solution"][num+j-1] == 0:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        connectOneWay(node2, dnode)
            elif candidate_solution[num+j-1] == 0 and info["previous_solution"][num+j-1] == 1:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        disconnectOneWay(node2, dnode)
                        
    #print("Connection changes:")
    #printNetWithVul(newNet)

    return newNet

def add_solution_real_decoy(net, candidate_solution, info, decoy_list):
    """
    Interpret solution to add connections.
    Add or remove connections:
    - from real IoT nodes to decoys
    - from real IoT nodes to real IoT nodes
    """
    newNet = copyNet(net)
    temp = decoy_list
    #Locate the decoy nodes from the newly created network
    for node1 in newNet.nodes:
        if node1.name in decoy_list:
            temp[decoy_list.index(node1.name)] = node1

    #Add or remove connections from real IoT nodes to decoys
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):    
        num = i * info["riot_num"]
        dnode = temp[i]
        #print(dnode.name)
        for j in range(1, info["riot_num"]+1):
            #print(candidate_solution[num+j-1])
            if candidate_solution[num+j-1] == 1 and info["previous_solution"][num+j-1] == 0:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        #print("Add connection: ", node2.name, dnode.name)
                        connectOneWay(node2, dnode)
            elif candidate_solution[num+j-1] == 0 and info["previous_solution"][num+j-1] == 1:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        #print("Remove connection: ", node2.name, dnode.name)
                        disconnectOneWay(node2, dnode)
    
    solution1 = (info["diot_dimension"]+info["dserver_dimension"]) * info["riot_num"]
    id_list = range(1, info["riot_num"]+1)
    #Add or remove connections from real IoT nodes to real IoT nodes
    for i in range(0, info["riot_num"]):
        num = i * (info["riot_num"]-1)
        for j in range(0, info["riot_num"]-1): #index of the id_list
            if candidate_solution[solution1+num+j-1] == 1 and info["previous_solution"][solution1+num+j-1] == 0:
                for node3 in newNet.nodes:
                    for node4 in newNet.nodes:
                        temp_list = []
                        for k in id_list:    
                            if k != (i+1):
                                temp_list.append(k) 
                        if node3.id == (i+1) and node4.id == temp_list[j]:
                            #print("Add connection: ", node3.name, node4.name)
                            connectOneWay(node3, node4)
            elif candidate_solution[solution1+num+j-1] == 0 and info["previous_solution"][solution1+num+j-1] == 1:
                for node3 in newNet.nodes:
                    for node4 in newNet.nodes:
                        temp_list = []
                        for k in id_list:    
                            if k != (i+1):
                                temp_list.append(k) 
                        if node3.id == (i+1) and node4.id == temp_list[j]:
                            #print("Remove connection: ", node3.name, node4.name)
                            disconnectOneWay(node3, node4)              
    
    #print("Connection changes:")
    #printNetWithVul(newNet)

    return newNet