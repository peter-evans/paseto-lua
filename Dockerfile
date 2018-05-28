FROM python:3.6.5

ENV PATH "$PATH:/lua_install/bin"

RUN apt-get -y update \
 && apt-get install -y -qq --no-install-recommends unzip \
 && pip install hererocks \
 && hererocks /lua_install -r^ --lua=5.3 \
 && luarocks install busted \
 && luarocks install luacheck \
 && luarocks install luacov

WORKDIR /paseto
