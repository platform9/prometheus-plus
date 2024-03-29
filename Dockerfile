
FROM alpine:latest

COPY build/bin/promplus /bin/

COPY promplus /etc/promplus/

RUN chmod +x /bin/promplus

RUN apk add libc6-compat

ENTRYPOINT [ "/bin/promplus" ]