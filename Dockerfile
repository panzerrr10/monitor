# 基础镜像：Python 3.12 精简版（跟你本机 3.12.3 对齐）
FROM python:3.12-slim

# 容器内的工作目录（后续命令都在这里执行）
WORKDIR /app

# 【关键】先拷依赖清单再装依赖
# 为什么：Docker 是分层缓存，只要 requirements.txt 没变，
#        下次构建就能复用这一层，不用重新装包（省几分钟）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    -i https://mirrors.aliyun.com/pypi/simple/

# 再拷代码（代码改动频繁，放最后，避免缓存失效）
COPY server/ ./server/
COPY config/ ./config/

# 声明端口（只是文档作用，实际监听由 settings.json 决定）
EXPOSE 8090

# 容器启动时执行什么
CMD ["python", "server/app.py"]
