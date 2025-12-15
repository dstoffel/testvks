# on supervisor in argo NS:

openssl req -x509 -nodes -newkey rsa:4096 -keyout sealed-secrets.key -out sealed-secrets.crt -days 3650 -subj "/CN=sealed-secrets"
k create secret tls imported-sealed-secrets-key --key=sealed-secrets.key --cert=sealed-secrets.crt  -n test
k label secret -n test  imported-sealed-secrets-key sealedsecrets.bitnami.com/sealed-secrets-key=active


# sync secret from supervisor to vks using jobs:

add           - name: SYNC_SECRETS
            value: "default-registry-creds:kube-system,imported-sealed-secrets-key:kube-system"
to the job


# you can add afterwards sealed secret to the git repo

echo -n bar | kubectl create secret generic testsecret -n default --dry-run=client --from-file=foo=/dev/stdin -o json | kubeseal  --cert sealed-secrets.crt   -o yaml --scope cluster-wide
kubectl create secret docker-registry registry-creds --docker-server=myregistry.com --docker-username=myuser --docker-password=mypw --dry-run=client -o json -n default | kubeseal  --cert sealed-secrets.crt   -o yaml --scope cluster-wide
