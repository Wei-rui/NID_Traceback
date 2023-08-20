import django
import os
import iptrace.search_crypt
import datetime
import hashlib

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "NID_Traceback.settings")
django.setup()

from iptrace.models import asDomain, asIDEA, asGroup, asUser
from iptrace.search_action import search
import Config


def loadUser(user_paras):
    # userName,userDID,groupID
    user_name = user_paras[0][0]
    for user_char in user_paras[0][1:]:
        if user_char.isupper():
            user_name = user_name + ' ' + user_char
        else:
            user_name = user_name + user_char

    hash_object = hashlib.sha256()
    hash_object.update(user_paras[1].encode())

    group = asGroup.objects.filter(id=int(user_paras[2]))[0]
    userLen = 36 - (2 * int(group.dividePart, 2) + 2)
    userPart = bin(int(hash_object.hexdigest(), 16))[2:][0:userLen]

    userTest = asUser.objects.filter(groupID=int(user_paras[2]), userPart=userPart)
    if userTest is None or len(userTest) == 0:
        asUser.objects.create(userName=user_name, userDID=user_paras[1],
                              groupID=int(user_paras[2]), userPart=userPart)
    else:
        raise ValueError("Hash Conflict!")


def loadDomain(domain_paras):
    # domainPrefix, domainIP,naName
    asDomain.objects.create(domainPrefix=domain_paras[0], domainIP=domain_paras[1], domainName=domain_paras[2])


def loadGroup(group_paras):
    # groupName,dividePart,orgPart
    asGroup.objects.create(groupName=group_paras[0], dividePart=group_paras[1], orgPart=group_paras[2])


def loadModel(config_line):
    config_paras = config_line.split(' ')
    if config_paras[0] == "user":
        loadUser(config_paras[1:])
    elif config_paras[0] == "domain":
        loadDomain(config_paras[1:])
    elif config_paras[0] == "group":
        loadGroup(config_paras[1:])


def genAddr(user: asUser, idea: asIDEA, create_time: datetime.datetime):
    minute_info = (create_time.timestamp() - datetime.datetime(year=create_time.year, month=1, day=1, hour=0, minute=0,
                                                               second=0, microsecond=0).timestamp()) // 60
    time_info = bin(int(minute_info))[2:].zfill(24)

    group = asGroup.objects.filter(id=user.groupID)[0]
    nid = group.dividePart + group.orgPart + user.userPart
    idea_object = iptrace.search_crypt.IDEA_Crypto(int(idea.ideaKey, 16))
    aid_int = idea_object.encrypt_block(int(nid + time_info, 2))
    aid_str = hex(aid_int)[2:].zfill(16)

    suffix = ""
    for i in range(4):
        suffix = suffix + ":" + aid_str[4 * i: 4 * (i + 1)]
    prefix = ':'.join(Config.DOMAIN_PREFIX.split(':')[0:4])
    address = prefix + suffix
    return address


def createIDEAAddr(outfile):
    start_time = datetime.datetime(year=2023, month=5, day=16, hour=17,
                                   minute=29, second=10).replace(tzinfo=datetime.timezone.utc)
    delta_time = datetime.timedelta(hours=2, minutes=12, seconds=0)
    create_time = datetime.timedelta(hours=1, minutes=23, seconds=12)

    ip_list = []
    for i in range(3):
        idea_object = iptrace.search_crypt.IDEA_Crypto()
        idea_info = asIDEA.objects.create(ideaKey=hex(idea_object.master_key)[2:],
                                          startTime=start_time + i * delta_time,
                                          endTime=start_time + (i + 1) * delta_time)

        for user in asUser.objects.all():
            ip_addr = genAddr(user, idea_info, start_time + i * delta_time + create_time)
            ip_list.append(ip_addr)

    with open(outfile, 'w') as file:
        file.writelines('\n'.join(ip_list))


def loadConfig(config_name: str, out_name: str):
    with open(config_name, 'r') as file:
        config_lines = file.readlines()

    for line in config_lines:
        loadModel(line.strip())

    createIDEAAddr(out_name)


def testIPAddress(out_name: str):
    with open(out_name, 'r') as file:
        address_lines = file.readlines()

    for address_line in address_lines:
        ip_addr = address_line.strip('\n')
        print("Test IP Address:", ip_addr)
        print("IP Address Search Result:", search(ip_addr))


if __name__ == "__main__":
    mode = 'test'
    config_file = 'config_1.txt'

    if mode == 'build':  # 将config.txt文件中的信息初始化到数据库,并生成样例IP地址文件
        loadConfig(config_file, 'ip_address.txt')
    elif mode == 'test':  # 测试解析样例IP文件中的地址
        testIPAddress('ip_address.txt')
