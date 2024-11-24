FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    iptables \
    net-tools

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

