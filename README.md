## codius-install

[Codius](https://codius.org/) installer for [OpenFaaS Cloud](https://github.com/openfaas/openfaas-cloud)

### Installation

Install OpenFaas Cloud with [ofc-bootstrap](https://github.com/openfaas-incubator/ofc-bootstrap/blob/master/USER_GUIDE.md):

- If your [Kubernetes cluster](https://github.com/openfaas-incubator/ofc-bootstrap/blob/master/USER_GUIDE.md#start-by-creating-a-kubernetes-cluster) does not come with [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) support, install a [Network Policy provider](https://kubernetes.io/docs/tasks/administer-cluster/network-policy-provider/) such as [Calico](https://docs.projectcalico.org/getting-started/kubernetes/).
- Skip the [Setup your access control](https://github.com/openfaas-incubator/ofc-bootstrap/blob/master/USER_GUIDE.md#setup-your-access-control) and [Use authz](https://github.com/openfaas-incubator/ofc-bootstrap/blob/master/USER_GUIDE.md#use-authz-recommended) steps
- Set [`network_policies`](https://github.com/openfaas-incubator/ofc-bootstrap/blob/master/USER_GUIDE.md#toggle-network-policies-recommended) to `true`

Update the values in `config.env` for your host, then run:

```
kubectl patch -n openfaas-fn deploy/buildshiprun -p '{"spec":{"template":{"spec":{"containers":[{"name":"buildshiprun","image":"wilsonianbcoil/of-buildshiprun:pr-1-merge","imagePullPolicy":"Always"}]}}}}'
kubectl patch -n openfaas deploy/edge-router -p '{"spec":{"template":{"spec":{"containers":[{"name":"edge-router","image":"wilsonianbcoil/edge-router:pr-1-merge","imagePullPolicy":"Always"}]}}}}'
kubectl set env -n openfaas deploy/edge-router auth_url=http://edge-auth.openfaas:8080
kubectl set env -n openfaas-fn deploy/system-github-event validate_customers=false
kubectl annotate ingress -n openfaas openfaas-ingress nginx.ingress.kubernetes.io/custom-http-errors=402
kubectl annotate ingress -n openfaas openfaas-ingress nginx.ingress.kubernetes.io/default-backend=codius-web
kubectl apply -k .
```
