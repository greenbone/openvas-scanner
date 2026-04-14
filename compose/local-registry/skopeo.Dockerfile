FROM quay.io/skopeo/stable:latest

COPY skopeo-push-registry.bash /usr/local/bin/skopeo-push-registry.bash
RUN mkdir /state
RUN chmod +x /usr/local/bin/skopeo-push-registry.bash

ENTRYPOINT ["/usr/local/bin/skopeo-push-registry.bash"]
