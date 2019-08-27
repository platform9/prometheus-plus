
FROM alpine:latest

COPY build/bin/promplus /bin/
COPY config /etc/pf9/

RUN chmod +x /bin/promplus

ENTRYPOINT [ "/bin/promplus" ]
