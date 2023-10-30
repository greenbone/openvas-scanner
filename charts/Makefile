_PHONY: install-http install-mtls uninstall log-openvasd

install-http:
	helm install --namespace openvasd --create-namespace openvasd openvasd/ --values openvasd/values.yaml --values openvasd/http-root.yaml

install-mtls:
	helm install --namespace openvasd --create-namespace openvasd openvasd/ --values openvasd/values.yaml --values openvasd/mtls-wo-ingress.yaml

uninstall:
	helm uninstall -n openvasd openvasd

log-openvasd:
	kubectl logs -n openvasd deployment/openvasd -c openvasd
