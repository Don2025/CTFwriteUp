import requests,re
url = 'https://1254-e9566a93-6f41-45c3-be56-a1fc4678145c.do-not-trust.hacking.run/'
s = requests.Session() # 创建一个Session对象：s

def getURL(url):
    con = s.get(url) # 发送请求，使用默认得登录属性 
    res = con.text # 获取页面text格式转换得字符串：res
    return res

def Calculation(text):
    result = eval(((re.findall(".*</p",text))[0])[0:-3]) # 正则筛选公式
    return result # 返回计算公式的结果 result

def postRES():
    result = Calculation(getURL(url)) #调用函数返回网页页面内容再调用
    payload = {'result':result}
    r = s.post(url,data=payload) # 模拟提交计算结果给服务端
    return r

print(postRES().text) # 返回HTTP结果中的text数据