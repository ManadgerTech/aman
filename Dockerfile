FROM python:3.12-slim
WORKDIR /app
COPY aman.py .
EXPOSE 8787
ENTRYPOINT ["python", "aman.py", "serve"]
CMD ["--host", "0.0.0.0", "--port", "8787"]
