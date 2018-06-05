FROM python:3.6.5

ENV LUA_VERSION 5.3
ENV LUA_DIR "/lua_install"
ENV PATH "$PATH:$LUA_DIR/bin"

RUN apt-get -y update \
 && apt-get install -y -qq --no-install-recommends unzip \
 && pip install hererocks \
 && hererocks $LUA_DIR -r^ --lua=$LUA_VERSION \
 && luarocks install busted \
 && luarocks install luacheck \
 && luarocks install luacov

RUN git clone https://github.com/peter-evans/luanacha.git -b v2 /luanacha \
 && cd /luanacha \
 && make LUADIR=$LUA_DIR \
 && cp luanacha.so $LUA_DIR/lib/lua/$LUA_VERSION/luanacha.so

WORKDIR /paseto

CMD [ "./docker-cmd.sh" ]
