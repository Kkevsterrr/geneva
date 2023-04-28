FROM python:3.6-stretch

# Set the root password in the container so we can use it
RUN echo "root:Docker!" | chpasswd

# Update package lists and install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnetfilter-queue-dev \
    iptables \
    tcpdump \
    netcat \
    net-tools \
    git \
    graphviz \
    openssh-server \
    tshark

# Enable root SSH login for client testing
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# Install Python dependencies
RUN pip install netfilterqueue requests dnspython anytree graphviz netifaces paramiko tld docker scapy==2.4.3 psutil

ENV PATH="/usr/sbin:${PATH}"

ENTRYPOINT ["/bin/bash"]
