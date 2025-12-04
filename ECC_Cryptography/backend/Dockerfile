FROM python:3.10

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# To Build & Run
# docker build -t ecdsa-backend .
# docker run -p 8000:8000 ecdsa-backend

