FROM alpine:3.16

COPY build/bin/promplus /bin/

COPY promplus /etc/promplus/

RUN chmod +x /bin/promplus

ENTRYPOINT [ "/bin/promplus" ]
