import sys
import json
import pytz
import pandas as pd
from datetime import datetime

# 从命令行参数指定的文件中加载一个包含JSON数据的列表
if len(sys.argv) < 2:
    print("Usage: python json2excel.py <filename>")
    sys.exit(1)
filename = sys.argv[1]
with open(filename, 'r', encoding='utf-8') as file:
    json_data = json.load(file)

n = len(json_data)
print("本次一共捕获{}条蜜罐信息".format(n))
startday = datetime(2024,7,22)
today = datetime.now().date()  # 获取今天日期
month = today.month
day = today.day
# 创建一个空的Excel表并设置列名
df_res = pd.DataFrame()
columns = ['攻击者编号', '攻击源IP', '次数', '最近攻击时间', '攻击方式']
df_res = df_res.reindex(columns=columns)

for i in range(n):
    data = json_data[i]
    # 将UTC时间戳转换为UTC+8时区时间
    utc8 = pytz.timezone('Asia/Shanghai')
    utc8_time = datetime.fromtimestamp(data['lastAttackTime'], tz=utc8)
    specific_time = str(utc8_time)[:-6]
    events = ''
    for event in data['event']:
        if 'zmap扫描' in event['event_name']:
            events += 'zmap端口扫描 + '
        elif 'SSH连接' in event['event_name']:
            events += '尝试ssh连接 + '
    events = '尝试telnet连接' if len(data['event']) == 0 else events[:-3]
    # 添加数据到DataFrame
    df_res.loc[len(df_res)] = [data['attack_name'], f"{data['sourceIp']} {data['location']}", data['logCount'], specific_time, events]


# 写入.xlsx文件
filename = f'{startday.month}月{startday.day}日~{month}月{day}日蜜罐捕获攻击IP信息.xlsx'
df_res.to_excel(filename, index=False)
print(f'Json文件已经提取出Excel表格并写入到{filename}中。')