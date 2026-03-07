FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install atheris pyyaml

COPY . $SRC/agent-bom
WORKDIR $SRC/agent-bom

COPY .clusterfuzzlite/build.sh $SRC/
