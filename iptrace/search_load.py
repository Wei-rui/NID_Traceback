import django
import os
import iptrace.search_crypt
import datetime
import hashlib

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "NID_Traceback.settings")
django.setup()

from iptrace.models import Domain, IDEA, Group, User
from iptrace.search_action import search
import Config


def loadUser(user_paras):
    # naIP,userName,userDID,groupID
    hash_object = hashlib.sha256()
    hash_object.update(user_paras[2].encode())

    group = Group.objects.filter(id=int(user_paras[3]))[0]
    userLen = 36 - (2 * int(group.dividePart, 2) + 2)
    userPart = bin(int(hash_object.hexdigest(), 16))[2:][0:userLen]

    userTest = User.objects.filter(groupID=int(user_paras[3]), userPart=userPart)
    if userTest is None or len(userTest) == 0:
        User.objects.create(naIP=user_paras[0], userName=user_paras[1], userDID=user_paras[2],
                            groupID=int(user_paras[3]), userPart=userPart)
    else:
        raise ValueError("Hash Conflict!")


def loadDomain(domain_paras):
    # domainIP, naName
    Domain.objects.create(domainIP=domain_paras[0], domainName=domain_paras[1])


def loadGroup(group_paras):
    # naIP,groupName,dividePart,orgPart
    Group.objects.create(naIP=group_paras[0], groupName=group_paras[1],
                         dividePart=group_paras[2], orgPart=group_paras[3])


def loadModel(config_line):
    config_paras = config_line.split(' ')
    if config_paras[0] == "user":
        loadUser(config_paras[1:])
    elif config_paras[0] == "domain":
        loadDomain(config_paras[1:])
    elif config_paras[0] == "group":
        loadGroup(config_paras[1:])


def genAddr(user: User, idea: IDEA, create_time: datetime.datetime):
    minute_info = (create_time.timestamp() - datetime.datetime(year=create_time.year, month=1, day=1, hour=0, minute=0,
                                                               second=0, microsecond=0).timestamp()) // 60
    time_info = bin(int(minute_info))[2:].zfill(24)

    group = Group.objects.filter(id=user.groupID)[0]
    nid = group.dividePart + group.orgPart + user.userPart
    idea_object = iptrace.search_crypt.IDEA_Crypto(int(idea.ideaKey, 16))
    aid_int = idea_object.encrypt_block(int(nid + time_info, 2))
    aid_str = hex(aid_int)[2:].zfill(16)

    suffix = ""
    for i in range(4):
        suffix = suffix + ":" + aid_str[4 * i: 4 * (i + 1)]
    prefix = ':'.join(user.naIP.split(':')[0:4])
    address = prefix + suffix
    return address


def createIDEAAddr(outfile):
    start_time = datetime.datetime(year=2023, month=5, day=16, hour=17,
                                   minute=29, second=10).replace(tzinfo=datetime.timezone.utc)
    delta_time = datetime.timedelta(hours=2, minutes=12, seconds=0)
    create_time = datetime.timedelta(hours=1, minutes=23, seconds=12)

    ip_list = []
    for domain in Domain.objects.all():
        for i in range(3):
            idea_object = iptrace.search_crypt.IDEA_Crypto()
            idea_info = IDEA.objects.create(naIP=domain.domainIP, ideaKey=hex(idea_object.master_key)[2:],
                                            startTime=start_time + i * delta_time,
                                            endTime=start_time + (i + 1) * delta_time)

            for user in User.objects.all():
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

    if mode == 'build':  # 将config.txt文件中的信息初始化到数据库,并生成样例IP地址文件
        loadConfig('config.txt', 'ip_address.txt')
    elif mode == 'test':  # 测试解析样例IP文件中的地址
        testIPAddress('ip_address.txt')
