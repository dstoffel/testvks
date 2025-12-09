#!/usr/bin/env python3

import json,yaml
import os
import subprocess
import logging
import base64
import tempfile
import sys

CAPI_ADMIN_SECRET_SUFFIX = "-kubeconfig"
ARGOCD_NS = os.getenv("ARGOCD_NS", "argo-cd")
ARGOCD_LABEL_PREFIX = os.getenv("ARGOCD_LABEL_PREFIX", "argocd/")
SYNC_LABEL = os.getenv("SYNC_LABEL", "argocd/sync-supervisor")
SUPERVISOR_CONTEXT = os.getenv("SUPERVISOR_CONTEXT", "")
ARGOCD_CONTEXT = os.getenv("ARGOCD_CONTEXT", "argocd")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
INSECURE = True if os.getenv("INSECURE", False) == "true" else False
VKS_NS = os.getenv("VKS_NS", "")


logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argocd-capi-sync")


def run(cmd):
    try:
      out = subprocess.check_output(cmd, shell=True, text=True)
      log.debug(f'[EXECed] {cmd} : ')
      return out
    except subprocess.CalledProcessError as e:
        log.error(f"Exec error: {cmd}")
        log.error(e.output)
        raise

def get_capi_clusters():
    allclusters = []
    for NS in VKS_NS.split(','):
        data = run(f"kubectl --context={SUPERVISOR_CONTEXT} get clusters -n {NS} -l {SYNC_LABEL}=true -o json")
        clusters = json.loads(data)["items"]
        nb=len(clusters)
        names = ','.join([n['metadata']['name'] for n in clusters])
        allclusters = allclusters + clusters
        log.info(f'Cluster VKS[{SYNC_LABEL}=true/{NS}] : {nb} ({names})')
    return allclusters

def get_argocd_clusters():
    data = run(
        f"kubectl --context={ARGOCD_CONTEXT} get secrets "
        f"-n {ARGOCD_NS} -l {SYNC_LABEL}=true,argocd/supervisor-context={SUPERVISOR_CONTEXT} -o json"
    )
    secrets = json.loads(data)["items"]
    nb=len(secrets)
    names = ','.join([s["metadata"]["name"].strip('cluster-') for s in secrets])
    log.info(f'Cluster ArgoCD[{SYNC_LABEL}=true,  argocd/supervisor-context={SUPERVISOR_CONTEXT}] : {nb} ({names})')
    return {s["metadata"]["name"]: s for s in secrets}

def extract_tls_from_kubeconfig(kubeconfig_b64):
    kubeconfig_yaml = base64.b64decode(kubeconfig_b64).decode("utf-8")
    kubeconfig = yaml.safe_load(kubeconfig_yaml)

    cluster_info = kubeconfig["clusters"][0]["cluster"]
    user_info = kubeconfig["users"][0]["user"]


    ca_data = cluster_info["certificate-authority-data"]
    server = cluster_info["server"]
    cert_data = user_info["client-certificate-data"]
    key_data = user_info["client-key-data"]

    return server, ca_data,  cert_data, key_data

def sync_argocd_secret(cluster):
    name = cluster["metadata"]["name"]
    namespace = cluster["metadata"]["namespace"]
    admin_secret = f"{name}{CAPI_ADMIN_SECRET_SUFFIX}"
    secret_name = f"cluster-{namespace}-{name}"
    log.info(f"Syncing ArgoCD secret {secret_name} for cluster {namespace}/{name}")

    kubeconfig_b64 = run(
        f"kubectl --context={SUPERVISOR_CONTEXT} get secret {admin_secret} "
        f"-n {namespace} -o jsonpath='{{.data.value}}'"
    ).strip()

    server, ca_data, cert_data, key_data = extract_tls_from_kubeconfig(kubeconfig_b64)
    if INSECURE:
      config_json = json.dumps({
          "tlsClientConfig": {
              "insecure": INSECURE,
              "certData": cert_data,
              "keyData": key_data,
          }
      })
    else:
      config_json = json.dumps({
          "tlsClientConfig": {
              "caData": ca_data,
              "insecure": INSECURE,
              "certData": cert_data,
              "keyData": key_data,
          }
      })

    secret_data = {
        "config": base64.b64encode(config_json.encode()).decode(),
        "name":  base64.b64encode(namespace.encode()+'-'.encode()+name.encode()).decode(),
        "server": base64.b64encode(server.encode()).decode(),
    }

    labels = {
        "argocd.argoproj.io/secret-type": "cluster",
        "argocd.argoproj.io/auto-label-cluster-info": "true",
        "argocd/supervisor-namespace": namespace,
        "argocd/supervisor-context": SUPERVISOR_CONTEXT
    }

    for k, v in cluster["metadata"].get("labels", {}).items():
        if k.startswith(ARGOCD_LABEL_PREFIX):
            labels[k] = v

    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": secret_name,
            "namespace": ARGOCD_NS,
            "labels": labels,
        },
        "data": secret_data,
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        yaml.safe_dump(secret, f)
        tmpfile = f.name

    content = open(tmpfile).read()

    run(f"kubectl --context={ARGOCD_CONTEXT} apply -f {tmpfile}")
    log.debug(f'Secrent content: \n{content}')
    os.remove(tmpfile)

    log.debug(f"Secret ArgoCD {name} synchronisé avec {len(labels)} labels")




def cleanup_argocd_clusters(capi_clusters, argocd_clusters):
    capi_names = {f'{c['metadata']['namespace']}-{c['metadata']['name']}' for c in capi_clusters}
    for secret_name in argocd_clusters.keys():
        cluster_name = secret_name.replace("cluster-", "")
        if cluster_name not in capi_names:
            log.info(f"Deleting  argoCD cluster {secret_name}")
            run(f"kubectl --context={ARGOCD_CONTEXT} delete secret {secret_name} -n {ARGOCD_NS}")

def main():
    log.info(f'Syncing clusters, SUPERVISOR_CONTEXT={SUPERVISOR_CONTEXT}, ARGOCD_CONTEXT={ARGOCD_CONTEXT}, VKS_NS={VKS_NS}')

    if VKS_NS == False:
        log.error('VKS_NS is required: comma-separated vpshere namespaces, used to find vks clusters')
        sys.exit(1)

    if SUPERVISOR_CONTEXT == '' or ARGOCD_CONTEXT == '':
        log.info('SUPERVISOR_CONTEXT or ARGOCD_CONTEXT empty, in-cluster')

    capi_clusters = get_capi_clusters()
    argocd_clusters = get_argocd_clusters()

    for cluster in capi_clusters:
        sync_argocd_secret(cluster)

    cleanup_argocd_clusters(capi_clusters, argocd_clusters)
    log.info("Clusters synced")

if __name__ == "__main__":
    main()
