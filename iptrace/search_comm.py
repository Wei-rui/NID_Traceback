from iptrace.models import basicInfo


def as2rpki(address_prefix: str):
    """
    与RPKI通信,根据地址前缀获取地址所属AS
    :param address_prefix: 传入的地址前缀
    :return: 所属AS的基础信息
    """
    address_as = basicInfo()
    # TODO RPKI查询获取所属AS的代码实现
    return address_as


# TODO 通信具体实现
def as2send():
    """
    :return:
    """
    pass


def as2receive():
    """
    :return:
    """
    return
