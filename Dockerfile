
FROM alpine:latest

COPY build/bin/monhelper /bin/

RUN chmod +x /bin/monhelper

ENTRYPOINT [ "/bin/monhelper" ]
