from django.http import HttpResponse
from django.template.loader import get_template
from iptrace.search_action import search
import ipaddress


def testIPAddr(ip_addr):
    """
    测试输入的字符串是否合法IP地址(前端测试用)
    :param ip_addr: IP地址
    :return: 返回输入是否为合法IP地址
    """
    try:  # 检验输入的地址是否符合IP地址格式
        address = ipaddress.ip_address(ip_addr)
    except Exception as e:
        print(e)
        return False
    return True


def getSearchPost(request):
    """
    获取输入对应的IP地址追溯结果
    :param request: 前端传递的POST请求,包含IP地址
    :return: 返回渲染的前端html页面
    """
    search_context = None
    try:
        ipv6_addr = request.POST["ip_addr"]
        search_success, search_result = search(ipv6_addr)
        # search_show, search_result = testIPAddr(ipv6_addr),
        # {"ip_addr": ipv6_addr, "prefix": "120", "suffix": "100", "message": "错误的IP格式！！"}
        search_context = {"search_show": search_success, "search_result": search_result}

    except Exception as e:
        print(e)

    search_t = get_template('searchAddress.html')
    html = search_t.render(search_context)
    return HttpResponse(html)

