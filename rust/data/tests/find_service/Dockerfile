FROM ubuntu:22.04

# Configure postfix non-interactively
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
RUN echo "postfix postfix/mailname string localhost" | debconf-set-selections

# Install all dependencies: services, Rust build tools, and OpenVAS dependencies
RUN apt-get update && apt-get install -y \
    apache2 \
    openssh-server \
    vsftpd \
    dovecot-pop3d \
    dovecot-imapd \
    postfix \
    mysql-server \
    telnetd \
    xinetd \
    netcat-openbsd \
    curl \
    build-essential \
    pkg-config \
    zlib1g-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:testpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configure Apache
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
RUN echo '<html><body><h1>Test HTTP Server</h1></body></html>' > /var/www/html/index.html

# Configure FTP
RUN echo "anonymous_enable=YES" >> /etc/vsftpd.conf
RUN echo "local_enable=YES" >> /etc/vsftpd.conf
RUN echo "write_enable=YES" >> /etc/vsftpd.conf
RUN echo "listen=YES" >> /etc/vsftpd.conf
RUN echo "listen_ipv6=NO" >> /etc/vsftpd.conf

# Configure Dovecot for POP3/IMAP
RUN sed -i 's/#listen = \*, ::/listen = */' /etc/dovecot/dovecot.conf
RUN sed -i 's/#disable_plaintext_auth = yes/disable_plaintext_auth = no/' /etc/dovecot/conf.d/10-auth.conf

# Configure MySQL
RUN service mysql start && \
    mysql -e "CREATE USER 'testuser'@'%' IDENTIFIED BY 'testpass';" && \
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';" && \
    mysql -e "FLUSH PRIVILEGES;"
RUN sed -i 's/bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

# Configure Postfix/SMTP
RUN sed -i 's/inet_interfaces = loopback-only/inet_interfaces = all/' /etc/postfix/main.cf

# Configure Telnet
RUN echo "service telnet\n{\n    socket_type     = stream\n    protocol        = tcp\n    wait            = no\n    user            = root\n    server          = /usr/sbin/in.telnetd\n    disable         = no\n    port            = 23\n}" > /etc/xinetd.d/telnet

# Create a simple NetBus-like service on port 12345 for security testing
RUN echo '#!/bin/bash\nwhile true; do echo "NetBus" | nc -l -p 12345; done' > /usr/local/bin/netbus-sim.sh
RUN chmod +x /usr/local/bin/netbus-sim.sh

# Create startup script starts services and provides a shell
RUN echo '#!/bin/bash\n\
echo "Starting services..."\n\
service mysql start\n\
service apache2 start\n\
service ssh start\n\
service vsftpd start\n\
service dovecot start\n\
service postfix start\n\
service xinetd start\n\
/usr/local/bin/netbus-sim.sh &\n\
\n\
exec /bin/bash' > /usr/local/bin/start-services.sh

RUN chmod +x /usr/local/bin/start-services.sh

# Set working directory for user files
WORKDIR /workspace

CMD ["/usr/local/bin/start-services.sh"]
