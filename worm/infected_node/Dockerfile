FROM ubuntu:20.04
#ARG DEBIAN_FRONTEND=noninteractive
#RUN apt-get update && apt-get install -y --no-install-recommends curl iputils-ping jq mtr-tiny netcat tcpdump vim-nox zsh nmap openjdk-11-jdk python3 python3-pip

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl iputils-ping netcat tcpdump nmap iproute2 \
  && apt-get install -y --no-install-recommends zsh vim jq python3 python3-pip openjdk-8-jdk zip \
  && pip install requests

# Setup malicious java class
WORKDIR /opt/utils
RUN mkdir -p malware
WORKDIR /opt/utils/malware
#COPY marshalsec-0.0.3-SNAPSHOT.jar .
COPY * ./

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
