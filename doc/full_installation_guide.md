# Full Openvas Installation Guide

This guide just links to the relevant parts of the [official community documentation](https://greenbone.github.io/docs/latest/22.4/source-build/index.html) for building the scanner stack from source.

Some comments on different parts of the documentation

1. [prerequisites](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#prerequisites): You can decide how you want to install the stack. If you want to run it via a dedicated user and install via source/build/install folders you can follow this section of the guide. If not adjust accordingly.
2. [Installation source](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#choosing-the-installation-source): For development just use git. Do not use the version variables as used in the guide.
3. [Install gvm-libs](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#gvm-libs). Installing gvmd, pq-gvm, gsa, gsad is not needed if you only want to install the scanner stack.
4. [Install openvas-smb](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#openvas-smb)
5. [Install openvas-scanner](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#openvas-scanner)
6. [Install ospd-openvas](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#openvas-scanner) only if you want to install the complete gvm stack (with gvmd, pq-gvm, gsa, gsad)
7. [Install openvasd](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#openvasd)
8. [Install greenbone-feed-sync](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#greenbone-feed-sync)
9. [Performing a system setup](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#performing-a-system-setup): from this section only the following is needed for the scanner stack: Redis, some parts of permissions section (depending on setup), feed validation, sudo for scanning, systemd files for openvasd if you want to use systemd
10. [Perfroming feed sync](https://greenbone.github.io/docs/latest/22.4/source-build/index.html#performing-a-feed-synchronization)

Now you can use the https://greenbone.github.io/scanner-api/ for running scans.
