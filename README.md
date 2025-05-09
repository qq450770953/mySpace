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