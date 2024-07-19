FROM erlang:27.0
COPY --from=denoland/deno:bin-1.45.0 /deno /usr/local/bin/deno

ADD https://github.com/gleam-lang/gleam/releases/download/v1.3.1/gleam-v1.3.1-x86_64-unknown-linux-musl.tar.gz /tmp/gleam.tar.gz
RUN tar -xf /tmp/gleam.tar.gz -C /usr/bin

RUN /bin/sh

RUN useradd gleamering_light
RUN useradd gleamering_star
RUN groupadd gleamering
RUN usermod -aG gleamering gleamering_light
RUN usermod -aG gleamering gleamering_star
RUN mkdir /home/gleamering_light
RUN chown root:gleamering_light /home/gleamering_light
RUN mkdir /home/gleamering_star
RUN chown root:gleamering_star /home/gleamering_star

RUN mkdir /var/gleamering
RUN mkdir /var/www
RUN mkdir /var/www/static
COPY ./gleamering_light /var/gleamering/gleamering_light
COPY ./gleamering_hope /var/gleamering/gleamering_hope
COPY ./gleamering_star /var/gleamering/gleamering_star
COPY ./gleamering_light/static /var/www/static
COPY ./db.sqlite3 /var/www/db.sqlite3
COPY ./.env /var/gleamering/
RUN ln -s /var/gleamering/.env /var/gleamering/gleamering_star/.env
RUN ln -s /var/gleamering/.env /var/gleamering/gleamering_light/.env
COPY ./start.sh /start.sh

RUN chown -R root:gleamering_light /var/gleamering/gleamering_light
RUN chown -R root:gleamering /var/gleamering/gleamering_hope
RUN chown -R root:gleamering_star /var/gleamering/gleamering_star
RUN chown -R root:gleamering /var/www
RUN chown gleamering_star:gleamering /var/www/db.sqlite3
COPY ./gleamering_hope_flag.txt /flag
RUN chown root:gleamering_star /flag
RUN chmod -R 775 /var/gleamering
RUN chmod -R 775 /home
RUN chmod 775 /var/www/db.sqlite3
RUN chmod 775 /var/www
RUN chmod +x /start.sh

USER gleamering_light
WORKDIR /var/gleamering/gleamering_light
RUN gleam build

USER gleamering_star
WORKDIR /var/gleamering/gleamering_star
RUN gleam build

USER root

EXPOSE 8000

CMD ["/start.sh"]
