# base-builder-python (pinned by hash for OpenSSF Scorecard)
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:535ce35f80fdcb33755c455baefa8ab3796d74035cfe0f4091cadb8ca2f5874f

RUN pip3 install atheris==3.0.0 pyyaml==6.0.3  # pinned — update periodically

COPY . $SRC/agent-bom
WORKDIR $SRC/agent-bom

COPY .clusterfuzzlite/build.sh $SRC/
