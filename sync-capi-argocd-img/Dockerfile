#FROM python:3.11.14-slim
FROM ubuntu:noble

COPY kubectl /usr/local/bin/kubectl

RUN apt-get update && apt-get install -y curl python3 python3-yaml yq

RUN chmod +x /usr/local/bin/kubectl

COPY sync_capi_argocd.py /usr/local/bin/sync_capi_argocd.py

ENTRYPOINT ["python3", "/usr/local/bin/sync_capi_argocd.py"]
