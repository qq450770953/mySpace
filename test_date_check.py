from datetime import datetime, date, timedelta

print("\n===== 问题原始代码 =====")
print("from datetime import datetime, timedelta")
print("# 问题代码 - 这会导致AttributeError: type object 'datetime.datetime' has no attribute 'datetime'")
print("isinstance(start_date, (datetime.date, datetime.datetime))")

print("\n===== 问题原因分析 =====")
print("1. datetime模块已经被导入，datetime.datetime尝试引用datetime模块的datetime属性")
print("2. 正确的写法应该是：import datetime，然后使用datetime.datetime")
print("3. 或者像当前导入一样: from datetime import datetime，然后直接使用datetime")

print("\n===== 修复方法 =====")
print("方法1 - 直接使用导入的类：")
print("isinstance(start_date, (date, datetime))")
print("\n方法2 - 直接使用date类：")
print("isinstance(start_date, date)")
print("\n方法3 - 完整导入datetime模块：")
print("import datetime")
print("isinstance(start_date, (datetime.date, datetime.datetime))")

# 创建日期对象
now = datetime.now()
today = now.date()

print("\n===== 测试结果 =====")
print(f"now: {now}, type: {type(now)}")
print(f"today: {today}, type: {type(today)}")

# 测试正确的isinstance检查方式
print("\n正确的isinstance检查：")
print(f"isinstance(now, datetime): {isinstance(now, datetime)}")
print(f"isinstance(today, date): {isinstance(today, date)}")
print(f"isinstance(now, date): {isinstance(now, date)}")  # datetime也是date的子类

# 单一类型检查
print("\n使用单一类型检查：")
print(f"type(now) is datetime: {type(now) is datetime}")
print(f"type(today) is date: {type(today) is date}")

# 展示如何正确转换
print("\n类型转换：")
if isinstance(now, datetime):
    date_only = now.date()
    print(f"datetime转换为date: {date_only}, type: {type(date_only)}")

# 测试日期比较
print("\n日期比较：")
tomorrow = today + timedelta(days=1)
print(f"today: {today}, tomorrow: {tomorrow}")
print(f"tomorrow > today: {tomorrow > today}")

# 测试格式化
print("\n日期格式化：")
print(f"today格式化为YYYY-MM-DD: {today.strftime('%Y-%m-%d')}")
print(f"now格式化为YYYY-MM-DD HH:MM:SS: {now.strftime('%Y-%m-%d %H:%M:%S')}") 