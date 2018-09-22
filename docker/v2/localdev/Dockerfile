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

ENV PYTHONUNBUFFERED=0
ENV TZ=${TZ:-"Europe/London"}


ADD ./requirements.txt /requirements.txt

RUN apk update && apk upgrade \
    && apk add --no-cache --virtual .build-deps git gcc libffi-dev musl-dev \
    libressl-dev ca-certificates python3-dev linux-headers tzdata \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && pip install --no-cache -r requirements.txt \  
    && apk del .build-deps \
    

ADD ./ /whoville
WORKDIR /whoville
ENV PYTHONPATH=/whoville

ENTRYPOINT ["python3"]
CMD ["./whoville/mayor.py"]

#ENV BRANCH=hdp3cbd
#    && git clone --depth 1 -b ${BRANCH} https://github.com/Chaffelson/whoville.git /whoville \


# Local Environment Execution Options
#docker build -t whoville:hdp3cbd .
#&& docker run
#-v /Users/dchaffey/PycharmProjects/whoville:/whoville
#-e TZ={timezone}
#--name whoville
#whoville:hdp3cbd 