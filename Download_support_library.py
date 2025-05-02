import os

try:
    os.system("pip3 install -r requirements.txt")
except Exception as e:
    print(f"\033[35m{e}\033[0m")
    print("下载依赖库失败！！！\n请自行下载：\nrequests\ntqdm")
else:
    print("下载完成✅")
input("Press enter to continue...")