from django.http import HttpResponse
from django.template.loader import get_template
import ipaddress
from iptrace.search_action import search


def testIPAddr(ip_addr):
    try:  # 检验输入的地址是否符合IP地址格式
        address = ipaddress.ip_address(ip_addr)
    except Exception as e:
        print(e)
        return False
    return True


def getSearchPost(request):
    search_context = None
    try:
        ipv6_addr = request.POST["ip_addr"]
        search_show, search_result = search(ipv6_addr)
        # search_show, search_result = testIPAddr(ipv6_addr), {"ip_addr": ipv6_addr, "prefix": "120", "suffix": "100", "message": "错误的IP格式！！"}
        search_context = {"search_show": search_show, "search_result": search_result}

    except Exception as e:
        print(e)

    search_t = get_template('searchAddress.html')
    html = search_t.render(search_context)
    return HttpResponse(html)
