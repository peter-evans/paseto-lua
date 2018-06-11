FROM python:3.6.5

ENV LUA_VERSION 5.3
ENV LUA_DIR "/lua_install"
ENV PATH "$PATH:$LUA_DIR/bin"

RUN apt-get -y update \
 && apt-get install -y -qq --no-install-recommends unzip \
 && pip install hererocks \
 && hererocks $LUA_DIR -r^ --lua=$LUA_VERSION \
 && luarocks install basexx \
 && luarocks install busted \
 && luarocks install luacheck \
 && luarocks install luacov
 
RUN wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz \
 && tar xzf LATEST.tar.gz \
 && cd libsodium-stable/ \
 && ./configure --prefix=/usr \
 && make \
 && make check \
 && make install

WORKDIR /paseto

CMD [ "./local/docker-cmd.sh" ]
