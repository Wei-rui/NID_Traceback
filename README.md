## IP地址跨域追溯模拟实现

### 多服务器模拟实现测试

#### 配置文件
Config.py文件中的相关配置
```
DEBUG_MODE 表明是否为DEBUG模式,开启则会进行一些输出
DOMAIN_IP 表明当前模拟的AS的服务器IP地址
DOMAIN_NAME AS的名称
DOMAIN_PREFIX 当前AS拥有的前缀

RPKI_IP RPKI服务器的IP地址
SERVER_PORT 服务器运行的端口,默认8000,后续有冲突情况需要修改Config和项目配置
```
数据初始化的config_x.txt（x为1/2/...）文件的相关配置
```
# domain开头：所有模拟的AS的基本信息
domain domain拥有的前缀 domain的服务器IP地址 domain的名称
# group开头：当前模拟的AS的组织信息
group group的名称 group的分割部分 group的组织部分
# user开头：当前模拟的AS的用户信息
user user的用户名 user的DID部分，此处为10位ID user所在组织的ID（本地服务器中的组织ID）
```

#### 测试过程
数据库初始化
```
python manage.py makemigrations iptrace
python manage.py migrate
```
样例数据初始化，将iptrace/search_load.py文件中的mode变量设置为'build'，config_file变量设置为输入的config文件，运行iptrace/search_load.py
```
# 代码将config_file中配置的域/用户/组织信息初始化到数据库中，并生成一些IDEA密钥和合法地址
python iptrace/search_load.py
```
（启动服务器后，可以将iptrace/search_load.py中的mode设置为'test'再运行，测试生成的IP地址的解析）

启动服务器，可以使用生成的示例IP地址测试前端解析效果
```
python manage.py runserver
```
### 单服务器模拟实现测试
#### 测试过程
数据库
```
python manage.py makemigrations iptrace
python manage.py migrate
```
样例数据初始化，将iptrace/search_load.py中的mode设置为'build'，运行iptrace/search_load.py
```
python iptrace/search_load.py
```
（可以将iptrace/search_load.py中的mode设置为'test'再运行，测试生成的IP地址的解析）

启动服务器，可以使用生成的示例IP地址测试前端解析效果
```
python manage.py runserver
```