FROM registry.centos.org/centos/centos:7

ENV APP_DIR='/f8a_report'

WORKDIR ${APP_DIR}

RUN yum install -y epel-release &&\
    yum install -y gcc git python36-pip python36-devel &&\
    yum clean all &&\
    mkdir -p ${APP_DIR}

RUN pip3 install --upgrade pip

COPY f8a_report/ ${APP_DIR}/f8a_report
COPY requirements.txt ${APP_DIR}
RUN pip3 install -r requirements.txt
#CMD ["f8a_report/stack_report_main.py"]
CMD ["f8a_report/helpers/npm_metadata.py"]
ENTRYPOINT ["python3"]
