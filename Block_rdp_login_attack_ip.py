# -*- coding:UTF-8 -*-

# 速度极快
import time
import subprocess
import win32evtlog
import xml.etree.ElementTree as ET
#Archive-Security-2023-03-22-08-53-12-655
# c:/Windows/system32/winevt/Logs/Security.evtx
EvtxPath = r"c:/Windows/system32/winevt/Logs/Security.evtx"  # 日志路径
IpList=[]   # 用于存放所有连接失败的ip
IpDict={}   # 用于存放IP失败次数
DenyIp=[]  # 用于存放大于三次失败次数的IP并在接下来进行封禁
# 解析Windows事件日志
start_time=time.time()  # 计算耗时开始
query_handle = win32evtlog.EvtQuery(
    EvtxPath,
    win32evtlog.EvtQueryFilePath)

read_count = 0
while True:
    # read 100 records
    events = win32evtlog.EvtNext(query_handle, 100)
    read_count += len(events)
    # if there is no record break the loop
    if len(events) == 0:
        break
    for event in events:
        xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        # print(xml_content)

        # parse xml content
        xml = ET.fromstring(xml_content)
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        EventID = xml.find(f'.//{ns}EventID').text
        if EventID== "4625" :
            AttackIp  = xml.find(f'.//{ns}Data[@Name="IpAddress"]').text
            LogonType = xml.find(f'.//{ns}Data[@Name="LogonType"]').text
            if LogonType == '3':
                    # 在IPlist里添加
                    IpList.append(AttackIp)
# 遍历IpList 得到IP失败次数
for ipaddress in IpList:
    # 如果这个ip没在字典中
    if ipaddress not in IpDict:
        if ipaddress=="-":
            continue
        # 没有就加到字典并配置默认次数
        IpDict[ipaddress] = 1
    else:
        # 如果有，就把值加一
        IpDict[ipaddress] = IpDict[ipaddress]+1



#如果大于不等于三次就写入到denyip列表中
for i in IpDict:
    if IpDict[i] > 3 :
        DenyIp.append(i)
        
end_time=time.time()
print(f"running time={end_time-start_time}")
print("攻击次数"+str(len(IpList)))

# 输出失败次数
for key, value in IpDict.items():
    print("失败IP：",key, "失败次数:", value)

for i in DenyIp:
    print("大于三次失败次数需要封禁："+str(i))


# 
JoinIp = ','.join(DenyIp)
print(JoinIp)  # 把ip组合为1.1.1.1,2.2.2.2,3.3.3.3

# 检测防火墙是否存在
command = f"netsh advfirewall firewall show rule name=\"test\" dir=in verbose"
try:
    # 不存在会报错崩溃，所以用try
    result=subprocess.run(command, capture_output=True, text=True, check=True)
except subprocess.CalledProcessError as e:
    print(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.也就是没这个规则")
    # 根据返回值做进一步处理
    # 没有：
    print("检测到没有规则，将新建规则：")
    command = f"netsh advfirewall firewall add rule name=\"test\" dir=in action=block protocol=any remoteip=\"{str(JoinIp)}\""
    result=subprocess.run(command, capture_output=True, text=True, check=True)
    print(result.stdout)
else:
    # 如果命令成功执行，这里可以处理结果
    # 有：
    print("检测到有规则，将设置规则：")
    
    command = f"netsh advfirewall firewall set rule name=\"test\" new remoteip=\"{str(JoinIp)}\""
    result=subprocess.run(command, capture_output=True, text=True, check=True)
    print(result.stdout)




