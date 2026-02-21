pkill -f "celery -A PKV worker"
pkill -f "python manage.py runserver 0.0.0.0:8001"
pkill -f "python manage.py tailwind start"
