# Python 文件编码与语法问题解决方案

## 问题描述

Python文件中出现的 `语句必须用换行符或分号分隔` 错误，通常是由于以下原因造成的：

1. 中文注释或文档字符串编码错误
2. 文档字符串后缺少换行符
3. 文件中存在无效的特殊字符（如Unicode替代字符�）

## 解决方案

我们采用了以下步骤解决问题：

1. 在文件开头添加编码声明：`# -*- coding: utf-8 -*-`
2. 在文档字符串之后添加换行符，确保语句正确分隔
3. 移除文件中的损坏字符

### 核心修复代码

```python
# -*- coding: utf-8 -*-
def fix_python_file(file_path):
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()
    
    # 确保文件有编码声明
    if not content.startswith('# -*- coding: utf-8 -*-'):
        content = '# -*- coding: utf-8 -*-\n' + content
    
    # 在所有函数文档字符串后添加换行符
    # 例如: """更新项目信息""" => """更新项目信息"""\n
    content = content.replace('def func():\n    """文档"""', 
                           'def func():\n    """文档"""\n    ')
    
    # 删除损坏的特殊字符
    content = content.replace('�', '')
    
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)
```

### 预防措施

为避免类似问题再次出现，建议采取以下措施：

1. 在所有Python文件开头添加编码声明：`# -*- coding: utf-8 -*-`
2. 使用一致的编辑器和编码设置
3. 确保所有文档字符串后有换行符
4. 使用编辑器的"显示不可见字符"功能检查文件格式 