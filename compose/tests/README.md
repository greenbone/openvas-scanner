Spawns up openvasd compose and a victim which can be used to verify issues with e.g. selinux.


Fixes for nichtsfrei/victim image:

Unfortunately the uid/gid range of nichtsfrei/victim is very large which means for rootless podman images we need to adjust the allowed uid/gid space:

```

```

```bash

sudo usermod --add-subuids 100000-165535 "$USER"
sudo usermod --add-subgids 100000-165535 "$USER"
podman system migrate
```
