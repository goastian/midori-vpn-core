FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache \
    python3 \
    py3-pip \
    wireguard-tools  \
    wireguard-tools-bash-completion \
    wireguard-tools-openrc \
    wireguard-tools-wg \
    wireguard-tools-wg-quick \
    iproute2 \
    net-tools \
    vim \
    git

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]

