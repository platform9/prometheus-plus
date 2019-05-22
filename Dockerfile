
FROM alpine:latest

COPY build/bin/promplus /bin/

RUN chmod +x /bin/promplus

ENTRYPOINT [ "/bin/promplus" ]
