"""
This module conducts security analysis.

@author: Mengmeng Ge
"""

from attackGraph import *
from attackTree import *
from harm import *
from SDIoTGen import *
import subprocess
import os
import re
import math
from random import shuffle, uniform, expovariate
import numpy as np
import harm



#---------------------------------------------------------------------------------------------------
#Compute compromise rate for lower layer (AT); MTTC (path level) and MTTSF for upper layer (AG)
#We only consider two cases: 
#1) one vulnerability for each node 
#2) multiple vulnerabilities for one node:
#   only ADN or OR, which means the attacker need to use all vulnerabilities or any one of them
#---------------------------------------------------------------------------------------------------

def computeNodeMTTC(node):
    count = 0
    MTTC = 0
    flag = False

    if node.type == True:
        node.comp = True
        count += 1
        if node.critical == True:
            flag = True
        MTTC = 1.0/node.val
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        if pro > 1.0:
            pro = 1.0 
        MTTC = (1.0/node.val) * pro
    #print(node.name, node.type, node.val, MTTC, flag)
    return MTTC, count, flag

#---------------------------------------------------------------------------------------------------
#Compute MTTSF used in GA
#---------------------------------------------------------------------------------------------------

def computeMTTSF(harm, net, cflag):
    """
    Compute MTTSF based on the attacker's intelligence.
    Used for computing optimal topology via GA.
    Assume IDS has 100% accuracy.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath) #Attacker randomly picks one entry point at a time
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))
    MTTSF = 0
    break_flag = False
    
    totalCount = 0
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, count, flag = computeNodeMTTC(node) 
                    MTTSF += MTTC
                    if node.type == True:
                        totalCount += count
                    #print(float(totalCount/totalNo))
                    
                    if float(totalCount/totalNo) >= cflag or flag == True:
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
    
    return MTTSF 

#---------------------------------------------------------------------------------------------------
#Compute MTTSF in shuffling
#----------------------------------------------------------------------------------------------------

def computeCompNodes(node, detect_pro):
    """
    Simulate attacker's behavior.
    Generate the compromised nodes
    """
    flag = False #SF2
    detect_pro = 1.0 #Reflect real compromised nodes by the attacker
    #print("Compromised node: ", node.name, node.type, node.val)
    #Critical node can be always detected
    if node.type == True:
        node.comp = True
        if node.critical == True:
            flag = True
        MTTC = (1.0/node.val) * node.pro - node.prev_comp
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        MTTC = (1.0/node.val) * pro * detect_pro
    #print("MTTC: ", MTTC)  
    return MTTC, flag 

def checkNeighbors(compNodes, neighbor_list):
    compNo = 0
    for node in compNodes:
        for neighbor in neighbor_list:
            if node.name == "ag_"+neighbor.name:
                compNo += 1
    #print("Number of compromised neighbors: ", compNo)
    return compNo

def assignCompNodeInNet(decoy_net, attack_node):
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
            #print("Assign compromised node in original net: ", node.name, attack_node.name)
            node.comp = True
    return None

def modifyCompNodeInNet(decoy_net, attack_node, left_time):
    
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
            #print("Assign compromised node in original net: ", node.name, attack_node.name)
            
            node.prev_comp = node.prev_comp + left_time
    return None

def computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo):
    """
    Zero false positive and false negative by IDS.
    """
    dividend1 = len(compNodes)
    divisor1 = totalNo
    value1 = dividend1/divisor1
    
    dividend2 = compNeighborNo 
    divisor2 = neighborNo
    value2 = dividend2/divisor2
    return value1, value2
    
def computeIDSRateMTTSF(detect_pro, compNodes, totalNo):
   
    dividend = len(compNodes) 
    divisor = totalNo
    value = dividend/divisor   
    return value 

def computeSSL_Interval(harm, net, decoy_net, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    Compute system security level for adaptive shuffling.
    """
    
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:",)) 

    totalTime = 0 #Total time between each shuffling
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    #print("Neighbor list: ", [i.name for i in neighbor_list])
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    #Simulate attacker's behavior
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    if node.type == True:
                        compNodes.append(node)
                        assignCompNodeInNet(decoy_net, node)
                        
                    totalTime += MTTC
                    
                    #print("SF1: ", float(len(compNodes)/totalNo))
                    #print("SF2: ", flag)
                    compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                    #Incorporate IDS accuracy
                    value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                    #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                    SSL =  w1 * value1 + w2 * value2
                    #print("SSL: ", SSL)
                    #Exit inner loop
                    if value1 >= cflag or flag == True:
                        SSL = 1.0
                        break_flag = True
                        break
                    elif (SSL - previous_ssl) > thre_check:
                        break_flag = True
                        break
                        
        #Exit outer loop
        if break_flag == True:
            break
    #print("MTTC:", totalTime)
    max_value, cost, return_cost = system_risk(harm, decoy_net)
    return SSL, totalTime, compNodes, decoy_net, max_value, cost, return_cost

def computeSSL_FixedInterval(harm, net, decoy_net, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes, delay):
    """
    Compute system security level for hybrid shuffling: mix of adaptive and fixed interval.
    """
    
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:",)) 
    
    #print("==============================================================================")
    totalTime = 0
    SSL = 0.0
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    #print("Neighbor list: ", [i.name for i in neighbor_list])
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    #print(node.name, node.val)
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    
                    #Calculate the previous total compromise time
                    previousTotalTime = totalTime - MTTC
                    interval_left = delay - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    
                    if totalTime < delay:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                    
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time smaller than interval: ", SSL)
                        #Exit inner loop
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                            break_flag = True
                            break
                        elif (SSL - previous_ssl) > thre_check:
                            break_flag = True
                            break
                    elif totalTime == delay:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time equals to interval: ", SSL)
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = delay
                        break_flag = True
                        
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time larger than interval: ", SSL)
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                        break    
                        
        #Exit outer loop
        if break_flag == True:
            break
    #print("MTTC:", totalTime)
    #print("SSL:", SSL)
    max_value, cost, return_cost = system_risk(harm, decoy_net)
    return SSL, totalTime, compNodes, decoy_net, max_value, cost, return_cost

def computeMTTSF_Baseline(harm, net, attack_net, cflag, detect_pro, compNodes):
    """
    Compute system security level for baseline scheme.
    """
    totalNo = len(net.nodes)
    totalCount = 0
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    #shuffle(harm.model.allpath)
    #harm.model.printPath()
    #print("number of attack paths:", ) 
    
    totalTime = 0
    security_failure = False
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    print(node.name, node.val, node.type)
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    totalCount += 1
                    
                    print("Accumulated MTTC:", totalTime)
                    if node.type == True:
                        compNodes.append(node)
                        assignCompNodeInNet(attack_net, node)
                    ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)

                    #Exit inner loop 
                    if ratioIDS >= cflag or flag == True:
                        print("Failure condition: ", ratioIDS, flag)
                        security_failure = True
                        break_flag = True
                        break

        #Exit outer loop
        if break_flag == True:
            break
       
    return totalTime, compNodes, attack_net, security_failure

def computeMTTSF_Interval(harm, net, decoy_net, interval_check, cflag, detect_pro, compNodes, security_failure):
    """
    Compute system security level for fixed interval shuffling.
    """
    totalNo = len(net.nodes)

    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    # shuffle(harm.model.allpath)
    #harm.model.printPath()
    #print("number of attack paths:", ) 
    
    
    totalTime = 0
    previousTotalTime = 0
    
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    
                    #Calculate the previous total compromise time
                    previousTotalTime = totalTime - MTTC
                    interval_left = interval_check - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    
                    if totalTime < interval_check:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #Exit inner loop 
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                            break_flag = True
                            break
                    elif totalTime == interval_check:
                        #Shuffle
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #End
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = interval_check
                        break_flag = True
                        security_failure = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
    max_value, cost, return_cost = system_risk(harm, decoy_net)
    op_cost = operational_cost(decoy_net)
    return totalTime, compNodes, decoy_net, security_failure, max_value, cost, return_cost, op_cost


def computeMTTSF_RandomInterval(harm: object, net: object, decoy_net: object, interval_mean: object, cflag: object, detect_pro: object, compNodes: object,
                                security_failure: object) -> object:
    """
    Compute system security level for random interval shuffling.
    """
    totalNo = len(net.nodes)

    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
   # shuffle(harm.model.allpath)#Attacker randomly picks one entry point at a time


    # Get all the entry points
    all_entry_points = harm.model.allpath

    # Randomly select an entry point
    random_entry_point = random.choice(all_entry_points)

    #harm.model.printPath()
    #print("number of attack paths:", )


    totalTime = 0
    previousTotalTime = 0
    
    interval_check = expovariate(1.0/interval_mean)
    #print(interval_check)
    
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, flag = computeCompNodes(node, detect_pro)
                    totalTime += MTTC
                    
                    previousTotalTime = totalTime - MTTC
                    interval_left = interval_check - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    if totalTime < interval_check:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #Exit inner loop
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                            break_flag = True
                            break
                    elif totalTime == interval_check:
                        #Shuffle
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #End
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = interval_check
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
    max_value, cost, return_cost = system_risk(harm,decoy_net)
    op_cost = operational_cost(decoy_net)
    return totalTime, compNodes, decoy_net, security_failure, max_value, cost, return_cost, op_cost

#=================================================================================================
# Calculate System Risk
#=================================================================================================

# def system_risk(net):
#     max_value = 0
#     cost = 0
#     return_cost = 0
#
#     for node in net.nodes:
#         value, path_cost, path_return_cost = connect_path(0, 0, 0, node)
#         if value > max_value:
#             max_value = value
#         cost += path_cost
#         return_cost += path_return_cost
#     return max_value, cost, path_return_cost
#
#
# def connect_path(total_risk, cost, return_cost, node):
#     if node.con:
#         for con_node in node.con:
#             if con_node.con:
#                 node_risk, node_cost, path_return_cost = connect_path(total_risk, cost, return_cost, con_node)
#                 total_risk += node_risk
#                 cost += node_cost
#                 return_cost += path_return_cost
#             else:
#                 total_risk += calculate_node(total_risk, con_node)
#                 node_cost, node_return_cost = calculate_cost(cost, return_cost, con_node)
#                 cost += node_cost
#                 return_cost += node_return_cost
#
#     total_risk += calculate_node(total_risk, node)
#     node_cost, node_return_cost = calculate_cost(cost, return_cost, node)
#     cost += node_cost
#     return_cost += node_return_cost
#
#     return total_risk, cost, return_cost
#
#
# def calculate_node(total_risk, node):
#     for vul_node in node.vul.nodes:
#         probability = vul_node.exploitability / 10
#         impact = vul_node.impact
#         risk_decoy_node = probability * impact
#         total_risk += risk_decoy_node
#     return total_risk
#
#
# def calculate_cost(cost, return_cost, node):
#     for vul_node in node.vul.nodes:
#         cost += vul_node.cost
#         if vul_node.cost:
#             return_cost += ((vul_node.exploitability / 10) * vul_node.impact) / vul_node.cost
#     return cost, return_cost




#***************************************************************************************************************
#With Harm Model
#****************************************************************************************************************

def operational_cost(net):
    operational_cost = 0
    for node in net.nodes:
        rev_cost = 0
        vul_list = []
        dup_vul_list = []
        cost ,vul_list,dup_vul_list = connect_path_op(0,node,vul_list,dup_vul_list)
        if dup_vul_list:
            group_list = group_by_value(dup_vul_list)
            for dup in group_list:
                rev_cost += dup[0][1] + len(dup) * 0.5
                cost -= dup[0][1]
            cost = cost - rev_cost
        operational_cost += cost
    return operational_cost


def group_by_value(list):
    result = {}
    for tup in list:
        key = tup[0]
        if key in result:
            result[key].append(tup)
        else:
            result[key] = [tup]

    final_result = [v for v in result.values()]
    return final_result


def connect_path_op(operational_cost, node, vul_list,dup_vul_list) :
    if node.con:
        for con_node in node.con:
            if con_node.con:
                amount, _, __ = connect_path_op(operational_cost, con_node, vul_list,dup_vul_list)
                operational_cost += amount
            else:
                for vul_node in con_node.vul.nodes:
                    if vul_node.name not in vul_list:
                        operational_cost += vul_node.cost
                        vul_list.append(vul_node.name)
                    else:
                        operational_cost += 0.5
                        dup_vul_list.append((vul_node.name, vul_node.cost))


    for vul_node in node.vul.nodes:
        if vul_node.name not in vul_list:
            operational_cost += vul_node.cost
            vul_list.append(vul_node.name)
        else:
            operational_cost += 0.5
            dup_vul_list.append((vul_node.name, vul_node.cost))
    return operational_cost, vul_list,dup_vul_list

def system_risk(harm: object, net: object) -> object:
    max_value = 0
    cost = 0
    return_cost = 0
    harm.model.calcRisk()
    # Get all the entry points
    all_entry_points = harm.model.allpath

    # Randomly select an entry point
    random_entry_point = random.choice(all_entry_points)

    for path in random_entry_point:
        for node in net.nodes:
            total_risk, path_cost, path_return_cost = connect_path(0, 0, 0, node)
            if total_risk > max_value:
                max_value = total_risk
            cost += path_cost
            return_cost += path_return_cost
    return max_value, cost, path_return_cost


def connect_path(total_risk, cost, return_cost, node):
    if node.con:
        for con_node in node.con:
            update_node(con_node)
            if con_node.con:
                node_risk, node_cost, path_return_cost = connect_path(total_risk, cost, return_cost, con_node)
                total_risk += node_risk
                cost += node_cost
                return_cost += path_return_cost
            else:
                total_risk += calculate_node(con_node)
                node_cost, node_return_cost = calculate_cost(con_node)
                cost += node_cost
                return_cost += node_return_cost



    total_risk += calculate_node(node)
    node_cost, node_return_cost = calculate_cost(node)
    cost += node_cost
    return_cost += node_return_cost

    return total_risk, cost, return_cost


def calculate_node(node):
    total_risk = 0
    for vul_node in node.vul.nodes:
        probability = vul_node.exploitability / 10
        impact = vul_node.impact
        risk_decoy_node = probability * impact
        total_risk += risk_decoy_node
    return total_risk


def calculate_cost(node):
    cost = 0
    return_cost = 0
    for vul_node in node.vul.nodes:
        cost += vul_node.cost
        if vul_node.cost:
            return_cost += ((vul_node.exploitability / 10) * vul_node.impact) / vul_node.cost
    return cost, return_cost


