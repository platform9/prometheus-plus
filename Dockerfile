
FROM alpine:latest

COPY build/bin/promplus /bin/
COPY promplus /etc/promplus/

RUN chmod +x /bin/promplus

ENTRYPOINT [ "/bin/promplus" ]
