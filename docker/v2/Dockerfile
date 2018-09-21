# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

FROM python:3.7-alpine

LABEL maintainer="Dan Chaffelson <chaffelson@gmail.com>"
LABEL site="https://github.com/Chaffelson/whoville"

ENV BRANCH=hdp3cbd
ENV PROFILE=/.secrets.yaml
ENV PYTHONUNBUFFERED=0

RUN apk update && apk upgrade \
    && apk add --no-cache --virtual .build-deps gcc build-base linux-headers \
    ca-certificates python3-dev libffi-dev libressl-dev git \
    && apk add -U --no-cache libxslt-dev bash \
    && git clone https://github.com/Chaffelson/whoville.git -b ${BRANCH} \
    && cd /whoville \
    && pip install -e . \
    && apk del .build-deps \
    && echo "python3 /whoville/whoville/mayor.py $PROFILE" > /run-module.sh

ENTRYPOINT ["/bin/bash"]
CMD ["/run-module.sh"]
