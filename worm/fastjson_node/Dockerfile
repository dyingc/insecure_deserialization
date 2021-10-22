#FROM vulhub/fastjson:1.2.24
FROM vulhub/fastjson:1.2.45
RUN apt-get update ; apt-get install -y tcpdump \
  && mkdir -p "/tmp/test" ; echo "This is some data" > /tmp/test/myfile
WORKDIR /tmp/test
