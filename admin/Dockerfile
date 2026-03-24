FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV ADMIN_PASSWORD=ubuntu-desk-admin
ENV PORT=8088
ENV SECRET_KEY=mude-esta-chave-em-producao
ENV DB_PATH=/data/db_v2.sqlite3

EXPOSE 8088

CMD ["python", "app.py"]
