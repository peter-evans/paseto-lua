FROM python:3.6.5

ENV LUA_VERSION 5.3
ENV COMPAT all
ENV LUA_DIR "/lua_install"
ENV PATH "$PATH:$LUA_DIR/bin"

RUN apt-get -y update \
 && apt-get install -y -qq --no-install-recommends sudo zip unzip \
 && pip install hererocks \
 && hererocks $LUA_DIR -r^ --lua=$LUA_VERSION --compat=$COMPAT \
 && luarocks install libsodium \
 && luarocks install basexx \
 && luarocks install lua-struct \
 && luarocks install lua-cjson 2.1.0 \
 && luarocks install busted \
 && luarocks install luacheck \
 && luarocks install luacov

WORKDIR /paseto

CMD [ "./.dev/docker-cmd.sh" ]
