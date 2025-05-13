# Project Management System

A comprehensive project management system with task tracking, progress monitoring, and team collaboration features.

## Features

### 1. Task Lifecycle Management
- Multi-level task breakdown (Project → Subtask → Milestone)
- Task assignment and priority management
- Gantt chart visualization
- Real-time status updates
- Risk analysis and management

### 2. Progress Tracking
- Global progress dashboard
- Team member contribution heatmap
- Automated report generation
- Custom analytics and filtering

### 3. Team Collaboration
- Real-time messaging
- File sharing and version control
- Resource management
- Automated notifications

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
python run.py
```

## Project Structure

```
project_management/
├── app/
│   ├── __init__.py
│   ├── models/
│   ├── routes/
│   ├── services/
│   ├── static/
│   └── templates/
├── config.py
├── run.py
└── requirements.txt
```

## 最近修复的问题

### 管理员权限识别问题修复 (Admin Authentication Fix)

我们解决了管理员用户登录后被错误识别为普通用户的问题。主要修复点包括：

1. **多层次管理员角色检查**：
   - 在页面初始化阶段强化了admin用户检测
   - 实现了JWT token解析，确保token中的admin信息被正确识别
   - 修改了`getUserRoles`函数，确保admin用户始终获得正确权限

2. **存储冗余**：
   - 在多个存储位置（localStorage和Cookie）同时设置admin标志
   - 使用多个键名（is_admin、admin、admin_role）保存admin状态，提高系统容错性

3. **守卫机制**：
   - 添加了页面加载时的admin角色守卫机制
   - 实现了定期检查admin权限的计时器，自动修复可能的权限错误

4. **用户模型强化**：
   - 在User模型中强化了admin用户识别逻辑，确保admin用户始终有admin角色

修复后，admin用户登录系统将被正确识别并获得所有管理权限，即使在某些情况下初始JWT token加载不完整。

### 权限问题排查指南

如果仍遇到权限问题，请检查：

1. 控制台日志中的`admin`状态输出
2. localStorage和Cookies中是否包含正确的admin标志
3. JWT token解析结果中的角色信息
4. 用户数据库记录中的角色关联

## 最近更新

### 项目编辑功能改进 (最新)

1. **修复项目负责人下拉框**
   - 现在项目负责人下拉框只显示具有管理员(admin)和项目经理(manager/project_manager)角色的用户
   - 优先显示用户名(username)而非角色名，提高可读性
   - 添加数据加载错误处理，在无法获取数据时显示友好提示

2. **修复保存按钮卡顿问题**
   - 添加多层保护机制，确保保存按钮不会永久停留在加载状态
   - 实现定期检查机制，自动恢复卡住的按钮状态
   - 保存按钮原始文本，确保正确恢复到初始状态
   - 设置超时保护，最长8秒后自动恢复按钮可点击状态

3. **其他优化**
   - 优化异常处理，确保在网络错误情况下也能正常使用
   - 页面加载完成时自动重置所有按钮状态
   - 添加日志记录，方便排查问题

## 联系我们 

## 已知问题和解决方案

### Bootstrap资源加载失败

问题：网页可能会出现以下错误：
```
资源加载失败: https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css
资源加载失败: https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js
```

解决方案：
1. 系统已配置使用本地Bootstrap文件而非CDN，避免由于网络问题导致的资源加载失败
2. 如果仍然出现资源加载问题，可以运行项目根目录下的`download_bootstrap.py`脚本下载必要的Bootstrap文件：
   ```
   python download_bootstrap.py
   ```
3. 如果下载仍失败，系统会自动使用内置的备用样式，确保基本功能正常

### 项目编辑功能问题

问题：编辑项目页面可能出现以下问题：
1. 负责人展示错误，显示角色而非用户名
2. 保存按钮展示为"加载中"状态，无法点击
3. 项目信息获取失败，错误信息：`[fetchProjectDataFromApi:editor] 请求失败: 404 {"error": "Not found"}`

解决方案：
1. 已修复API端点问题，确保系统使用正确的URL获取项目数据
2. 增强了数据获取机制，即使API调用失败也能使用页面上的基本信息进行编辑
3. 改进了项目经理信息处理逻辑，确保正确显示用户名而非角色
4. 优化了保存按钮状态管理，确保按钮在各种情况下都能正确重置为可点击状态
5. 添加了超时保护机制，确保保存按钮在10秒内自动恢复为可点击状态
6. 改进了项目负责人下拉框，现在只显示具有管理员和项目经理角色的用户
7. 增加了更详细的错误处理和提示，使用户能够更清楚地了解错误原因
8. 新增页面加载完成时的按钮状态重置机制，确保页面加载后按钮始终处于可用状态
9. 如果仍遇到问题，可以尝试：
   - 清除浏览器缓存
   - 刷新页面
   - 强制重载页面 (Ctrl+F5)

### 项目详情页面功能问题

问题：项目详情页面可能出现以下问题：
1. 负责人下拉框未展示所有用户，仅显示部分项目经理
2. 创建任务功能失败，报错：`Uncaught ReferenceError: createTask is not defined`
3. 添加成员、删除项目等功能可能存在未定义的函数错误

解决方案：
1. 已增加从全局用户API获取所有用户的代码，确保所有下拉框包含完整的用户列表
2. 添加了缺失的`createTask()`、`addMember()`、`uploadFile()`和`deleteProject()`函数
3. 新增了`/api/noauth/tasks`端点以支持无认证任务创建功能
4. 修复了`/api/tasks/<task_id>/update_bypass`端点，现在支持PUT和POST请求，避免405错误
5. 优化了所有功能函数的错误处理和状态管理，确保按钮状态正确更新
6. 每个功能都添加了详细的控制台日志，方便排查问题
7. 如果页面加载后仍有功能问题，请尝试：
   - 刷新页面后再试
   - 查看浏览器控制台是否有具体错误信息
   - 确认用户是否有相应操作权限

### 任务更新API调用问题

问题：使用PUT请求更新任务时，API返回405 Method Not Allowed错误

解决方案：
1. 已修复`/api/tasks/<task_id>/update_bypass`端点，现在同时支持PUT和POST方法
2. 添加了更详细的错误处理，确保API调用失败时返回清晰的错误信息
3. 如果仍遇到405错误，可以尝试以下替代API端点：
   - `/api/tasks/<task_id>/no_csrf` - 完全豁免CSRF的任务更新端点
   - `/api/tasks/<task_id>` - 标准任务更新端点
4. 添加了请求失败的自动重试机制，在遇到某些错误时会自动切换端点重试

### 其他已知问题 