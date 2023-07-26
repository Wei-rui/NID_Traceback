import datetime
import ipaddress
import requests
import iptrace.search_crypt
import Config
from iptrace.models import asIDEA, asGroup, asUser, asDomain


def getGroupList(group_part: str):
    """
    根据Group部分查询Group列表
    :param group_part: 组织部分
    :return: 查询到的Group列表
    """
    group_list = asGroup.objects.filter(orgPart=group_part)
    return group_list


def getUserList(user_part: str, group_id: int):
    """
    根据用户部分和组织ID查询组织列表
    :param user_part: 用户部分字符串
    :param group_id: 组织ID字符串
    :return: 查询到的Group列表
    """
    user_list = asUser.objects.filter(userPart=user_part, groupID=group_id)
    return user_list


def getAidTime(time_mile):
    """
    将日期毫秒数转换为日期字符串
    :param time_mile:日期的毫秒数
    :return:日期的String类型,格式为yyyy-MM-dd HH:mm:ss
    """
    time_stamp = float(time_mile) / 1000
    time_date = datetime.datetime.fromtimestamp(time_stamp)
    # time_date_str = time_date.strftime("%Y-%m-%d %H:%M:%S")
    time_date_str = time_date.strftime("%Y-%m-%d %H:%M")
    return time_date_str


def getCurrYearFirst():
    """
    获取当前年份第一天的毫秒数
    :return:当前年份第一天的毫秒数 比如：2023-01-01 00:00:00
    """
    y = datetime.datetime(year=datetime.datetime.now().year, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return int(round(y.timestamp() * 1000))


def getMileSeconds(time_date: datetime.datetime):
    """
    获取datetime对象的毫秒级时间戳
    :param time_date:datetime数据
    :return:datetime的毫秒级时间戳
    """
    time_mile = int(round(time_date.timestamp() * 1000))
    return time_mile


def getSuffix(ipv6_addr: str):
    """
    获取IPv6地址的后64位
    :param ipv6_addr:IPV6地址
    :return:IPv6地址后缀,冒号间不足4位补前导0,例如:0200:0000:feb0:0000
    """
    ipv6_addr_list = ipv6_addr.split(":")
    ipv6_addr_suffix = ""
    for i in range(4, 8):
        ipv6_addr_suffix = ipv6_addr_suffix + ":" + ipv6_addr_list[i].zfill(4)
    return ipv6_addr_suffix[1:]


def getPrefix(ipv6_addr: str):
    """
    获取IPv6地址的前64位
    :param ipv6_addr:IPV6地址
    :return:IPv6地址前缀,去掉冒号间的0与前导0,例如:2001:da8::b255:
    """
    ipv6_addr_list = ipv6_addr.split(":")
    ipv6_addr_prefix = ""
    for i in range(0, 4):
        if ipv6_addr_list[i] != "0":
            ipv6_addr_prefix = ipv6_addr_prefix + ipv6_addr_list[i]
        ipv6_addr_prefix = ipv6_addr_prefix + ":"
    return ipv6_addr_prefix


def hexStrToBinStr(hex_string: str):
    """
    16进制字符串转为2进制字符串
    :param hex_string:16进制字符串
    :return:2进制字符串
    """
    return bin(int(hex_string, 16))[2:]


def send2rpki(prefix_ip):
    """
    与RPKI通信,根据地址前缀获取地址所属AS
    :param prefix_ip: 传入的地址前缀
    :return: 所属AS的基础信息
    """
    prefix_data = {'prefix': prefix_ip}
    rpki_url = 'http://' + Config.RPKI_IP + ':' + str(Config.SERVER_PORT) + '/query_prefix'
    response = requests.post(rpki_url, data=prefix_data)

    if Config.DEBUG_MODE:
        print("send2rpki", rpki_url, response.json())

    if response.json()['status'] == 'BS.500':
        return None
    return response.json()


def queryDomain(prefix_ip):
    """
    从数据库中根据地址前缀查询地址所属AS
    :param prefix_ip: 地址前缀
    :return: 所属AS的基础信息
    """
    if Config.DEBUG_MODE:
        print("queryDomain", prefix_ip)

    domains = asDomain.objects.filter(domainPrefix=prefix_ip)
    if domains is not None and len(domains) > 0:
        return {'domainIP': domains[0].domainIP, 'domainName': domains[0].domainName}
    return {}


def resolveAID(ip_suffix: str):
    """
    在本AS内查询某个地址后缀信息的逻辑实现
    :param ip_suffix: 需要解析的目标后缀
    :return: 是否解析成功,具体解析结果
    """
    if Config.DEBUG_MODE:
        print("resolveAID", ip_suffix)

    resolve_result = {'success': True}
    lastNid, IDEA_list = None, asIDEA.objects.all().order_by("startTime")
    if IDEA_list is not None and len(IDEA_list) > 0:
        for idea_object in IDEA_list:
            idea_key = idea_object.ideaKey
            aid = iptrace.search_crypt.getIdeaDecrypt(ip_suffix.replace(':', ''), idea_key).zfill(16)
            aid_bin = hexStrToBinStr(hex_string=aid).zfill(64)  # 将十六进制AID转为2进制字符串
            nid = aid[0:10]  # nid为AID的前10位字符串(对应40位二进制)

            time_str = aid_bin[40:]  # 截取24位时间位=分钟数,这个时间为(当前时间-当前年第一天时间)的分钟数
            time_miles = int(time_str, 2) * 60 * 1000 + getCurrYearFirst()  # 解析出来毫秒数+当年第一天毫秒数=现在毫秒数

            start_time = getMileSeconds(idea_object.startTime)  # 取出idea的开始时间毫秒数与结束时间毫秒数
            end_time = getMileSeconds(idea_object.endTime)

            if start_time <= time_miles <= end_time:  # 如果timeLong在开始时间与结束时间之间,则此密钥为最新密钥,退出循环
                lastNid = nid
                aidTimeString = getAidTime(time_miles)

                resolve_result['idea_key'] = idea_key
                resolve_result['de_block'] = aid
                resolve_result['nid'] = lastNid
                resolve_result['time'] = aidTimeString
                break
    else:
        resolve_result['success'] = False
        resolve_result['message'] = "没有相应的IDEA记录"
        return resolve_result

    if lastNid is not None and lastNid != "":  # 拆分NID

        lastNidBin = hexStrToBinStr(hex_string=lastNid).zfill(40)

        divideID = lastNidBin[0:4]
        orgLen = 2 * int(divideID, 2) + 2
        orgID, userID = lastNidBin[4: 4 + orgLen], lastNidBin[4 + orgLen: 40]

        resolve_result['orgID'] = orgID
        resolve_result['userID'] = userID
        groupList = getGroupList(group_part=orgID)
        if groupList is not None and len(groupList) > 0:
            userList = getUserList(user_part=userID, group_id=groupList[0].id)
            if userList is not None and len(userList) > 0:
                resolve_result['groupName'] = groupList[0].groupName
                resolve_result['userName'] = userList[0].userName
                resolve_result['userDid'] = userList[0].userDID
            else:
                resolve_result['success'] = False
                resolve_result['message'] = "不存在对应的用户"
                return resolve_result
        else:
            resolve_result['success'] = False
            resolve_result['message'] = "不存在对应的组织"
            return resolve_result
    else:
        resolve_result['success'] = False
        resolve_result['message'] = "没有相应的IDEA记录"
    return resolve_result


def send2resolve(target_ip, suffix_ip):
    """
    :param target_ip: 目标AS服务器的IP地址
    :param suffix_ip: 要求目标AS服务器解析的IP地址后缀
    :return: 返回解析出的用户信息的json
    """
    suffix_data = {'suffix': suffix_ip}
    server_url = 'http://' + target_ip + ':' + str(Config.SERVER_PORT) + '/query_suffix'
    response = requests.post(server_url, data=suffix_data)

    if Config.DEBUG_MODE:
        print("send2resolve", server_url, response.json())

    return response.json()


def search(ipv6_addr: str):
    """
    对输入的IPv6地址
    :param ipv6_addr:输入的IPv6地址
    :return:追溯得到的结果
    """
    search_result = {'success': True, 'ip_addr': ipv6_addr}
    if ipv6_addr is not None and ipv6_addr != "":
        try:  # 检验输入的地址是否符合IP地址格式
            address = ipaddress.ip_address(ipv6_addr)
        except Exception as e:
            print(e)
            search_result['success'] = False
            search_result['message'] = "输入字符串不符合IP地址格式"
            return search_result

        if address.version != 6:  # 检验输入的地址是否是IPv6地址格式
            search_result['success'] = False
            search_result['message'] = "输入地址不是IPv6地址"
            return search_result

        ipv6_prefix = getPrefix(ipv6_addr)  # 前缀共64位用:号分隔，冒号与冒号间存在0不显示
        ipv6_suffix = getSuffix(ipv6_addr)  # 后缀共64位，每个冒号之前默认4位，不足4位在前面补0

        search_result['prefix'] = ipv6_prefix
        search_result['suffix'] = ipv6_suffix
        search_result['aid'] = ipv6_suffix.replace(':', '')

        # 使用前缀:根据前缀64位到domain表中找对应的naIP(RPKI query模拟)
        domain_info = send2rpki(ipv6_prefix)  # 返回的是AS的信息列表
        if domain_info is not None and 'domainIP' in domain_info.keys():
            naIP = domain_info['domainIP']
            search_result['as_name'] = domain_info['domainName']

            if Config.DEBUG_MODE:
                print("getServerIP:", naIP)

            # 使用后缀:在naIP对应域内解析出用户数据
            resolve_result = send2resolve(naIP, ipv6_suffix)
            for each_key in resolve_result.keys():
                search_result[each_key] = resolve_result[each_key]
        else:
            search_result['success'] = False
            search_result['message'] = "前缀不属于任何AS"

    return search_result


if __name__ == "__main__":
    # test
    search(ipv6_addr="2001:da8:24d:0:0257:7d40:744e:eba0")
