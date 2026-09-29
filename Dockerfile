FROM node:22-slim AS dashboard-build

WORKDIR /build
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY dashboard/ ./
RUN npx vite build

FROM python:3.14-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY inv4r/ inv4r/
COPY configs/ configs/
COPY mappings/ mappings/
COPY controls/ controls/
COPY --from=dashboard-build /build/dist/ dashboard/dist/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "inv4r.cli", "serve-api", "--host", "0.0.0.0", "--port", "8000"]
