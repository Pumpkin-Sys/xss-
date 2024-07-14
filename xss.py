import requests
from bs4 import BeautifulSoup

# 定义XSS攻击指令
payload = "<script>alert('pkn‘);</script>"


def xss1(url):
    # 向指定URL发送GET请求
    response = requests.get(url)

    # 使用BeautifulSoup解析HTML内容
    soup = BeautifulSoup(response.text, 'html.parser')

    # 查找所有的表单元素
    forms = soup.find_all('form')
    for form in forms:
        # 获取表单的action属性和method属性
        action = form.get('action')
        method = form.get('method', 'get')

        # 准备POST或GET请求的数据
        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                data[input_name] = payload  # 将XSS载荷注入到每个输入字段

        # 发送带有指令的请求
        if method.lower() == 'post':
            response = requests.post(action, data=data)
        else:
            response = requests.get(action, params=data)

        # 检查载荷是否被反射回来
        if payload in response.text:
            print(f"在{url}的表单action {action}中发现潜在的XSS")
            return True

    return False


# 测试函数
target_url = input("请输入目标URL：")
if xss1(target_url):
    print("检测到XSS漏洞！")
else:
    print("未发现XSS漏洞。")
