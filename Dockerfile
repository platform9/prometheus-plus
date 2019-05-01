
FROM alpine

COPY build/bin/monhelper /bin/

ENTRYPOINT [ "/bin/monhelper", "--log-level=INFO", "--mode=k8s" ]
