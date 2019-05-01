
FROM alpine

COPY build/bin/monhelper /bin/

ENTRYPOINT [ "/bin/monhelper" ]
