import sys
import json
from datetime import datetime

# 从文件中加载一个包含JSON数据的列表
if len(sys.argv) < 2:
    print("Usage: python json2md.exe <filename>")
    sys.exit(1)
filename = sys.argv[1]
with open(filename, 'r', encoding='utf-8') as file:
    json_data = json.load(file)

n = len(json_data)
print("本次一共捕获{}条蜜罐信息".format(n))
today = datetime.now().date()  # 获取今天日期
hour = datetime.now().time().hour
if hour >= 8 and hour < 12:
    time_of_day = "上午"
elif hour >= 14 and hour < 17:
    time_of_day = "下午"
else:
    time_of_day = "晚上"
# 提取关键信息并整理成Markdown列表
markdown_content = f"""## {today}{time_of_day}蜜罐捕获信息

目的IP都是10.78.173.236（蜜罐）。
| 攻击者编号 |           攻击源IP           | 次数 |    最近攻击时间     | 攻击方式                     |
| :--------: | :--------------------------: | :--: | :-----------------: | ---------------------------- |\n"""
txt_content = ""
for i in range(n):
    data = json_data[i]
    specific_time = datetime.utcfromtimestamp(data['lastAttackTime'])
    events = ''
    for event in data['event']:
        if 'zmap扫描' in event['event_name']:
            events += 'zmap端口扫描 + '
        elif 'SSH连接' in event['event_name']:
            events += '尝试ssh连接 + '
    events = '尝试telnet连接' if len(data['event']) == 0 else events[:-3]
    markdown_content += f"| {data['attack_name']} | {data['sourceIp']} {data['location']} | {data['logCount']} | {specific_time} | {events} |\n"
    txt_content += f"{data['sourceIp']}\n"

# 写入.md文件
filename = f'{today}{time_of_day}蜜罐捕获情况.md'
with open(filename, 'w') as file:
    file.write(markdown_content)
print(f'Json文件已经转换成Markdown内容并写入到{filename}中。')
# 写入.txt文件
filename = f'{today}{time_of_day}蜜罐建议封堵IP.txt'
with open(filename, 'w') as file:
    file.write(txt_content)
print(f'所有源IP已经保存到{filename}中。')